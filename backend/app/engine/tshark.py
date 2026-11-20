"""Run Wireshark's command-line tools. Every packet TrustWatch sees is decoded by tshark,
so the dashboard reads packets exactly the way Wireshark does.

Needs Wireshark installed (on Ubuntu: sudo apt install tshark).
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from functools import cache
from pathlib import Path

from .packet import TSHARK_FIELDS, PacketInfo, parse_fields

# Where the Wireshark installers put the tools when they are not on PATH.
_INSTALL_DIRS = [
    Path("/Applications/Wireshark.app/Contents/MacOS"),
    Path("C:/Program Files/Wireshark"),
]

# -n: no name lookups (they would be slow, and in live mode tshark would capture its own DNS queries).
DECODE_ARGS = ["-n", "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=,"]
for _field in TSHARK_FIELDS:
    DECODE_ARGS += ["-e", _field]


class TsharkNotFound(Exception):
    pass


class TsharkError(Exception):
    """A Wireshark tool failed. The message is its own explanation, e.g. "isn't a capture file"."""


@cache
def tool(name: str) -> str:
    """Path to a Wireshark tool: "tshark", "dumpcap" or "editcap"."""
    if found := shutil.which(name):
        return found
    for folder in _INSTALL_DIRS:
        for candidate in (folder / name, folder / f"{name}.exe"):
            if candidate.is_file():
                return str(candidate)
    raise TsharkNotFound(f"Could not find {name}. Install Wireshark (on Ubuntu: sudo apt install tshark).")


def read_capture(path: str | Path) -> list[PacketInfo]:
    """Decode every packet in a .pcap or .pcapng file."""
    result = subprocess.run(
        [tool("tshark"), "-r", str(path), *DECODE_ARGS],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if result.returncode != 0:
        raise TsharkError(result.stderr.strip())
    return [parse_fields(line) for line in result.stdout.splitlines()]


class LiveCapture:
    """tshark capturing an interface: it saves every packet to `pcap` and prints each one as it arrives."""

    def __init__(self, interface: str, pcap: Path) -> None:
        self._stderr = tempfile.TemporaryFile(mode="w+")  # a file, not a pipe, so tshark can never stall on it
        self._stopping = False
        self._proc = subprocess.Popen(
            [tool("tshark"), "-i", interface, "-w", str(pcap), "-F", "pcap", "-P", "-l", *DECODE_ARGS],
            stdout=subprocess.PIPE, stderr=self._stderr, text=True, encoding="utf-8", errors="replace",
        )
        # tshark prints "Capturing on ..." even when the capture then fails, so give a failure a moment to show.
        try:
            self._proc.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            return
        raise TsharkError(self._error())

    def packets(self) -> Iterator[PacketInfo]:
        """Each packet as it arrives, until stop() is called or the capture fails."""
        for line in self._proc.stdout:
            yield parse_fields(line)
        self._proc.wait()
        if not self._stopping:
            raise TsharkError(self._error() or "tshark stopped capturing unexpectedly.")

    def stop(self) -> None:
        self._stopping = True
        self._proc.terminate()  # tshark finishes the .pcap and exits, which ends packets()

    def _error(self) -> str:
        self._stderr.seek(0)
        return self._stderr.read().strip()


def interfaces() -> list[dict]:
    """Capture interfaces, e.g. {"name": "en0", "description": "Wi-Fi", "ip": "192.168.1.5"}."""
    out = subprocess.run([tool("dumpcap"), "-D", "-M"], capture_output=True, text=True, check=True).stdout
    try:
        listed = json.loads(out)
    except json.JSONDecodeError:  # older Wireshark: plain "1. en0 (Wi-Fi)" lines, without addresses
        plain = subprocess.run([tool("dumpcap"), "-D"], capture_output=True, text=True, check=True).stdout
        found = [re.match(r"\d+\. (\S+)(?: \((.*)\))?$", line) for line in plain.splitlines()]
        return [{"name": m[1], "description": m[2] or m[1], "ip": ""} for m in found if m]
    found = []
    for entry in listed:
        for name, info in entry.items():
            ipv4 = [a for a in info.get("addrs", []) if "." in a and ":" not in a]
            found.append({"name": name, "description": info.get("friendly_name") or name, "ip": ipv4[0] if ipv4 else ""})
    return found


def copy_frames(source: Path, destination: Path, count: int) -> None:
    """Save frames 1..count of `source` as a .pcap, so frame numbers stay the same."""
    subprocess.run(
        [tool("editcap"), "-F", "pcap", "-r", str(source), str(destination), f"1-{count}" if count else "0"],
        capture_output=True, check=True,
    )
