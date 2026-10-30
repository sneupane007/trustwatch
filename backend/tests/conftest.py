from pathlib import Path

import pytest

from scripts.make_samples import write_capture


@pytest.fixture
def capture_file(tmp_path: Path):
    """Write a list of Scapy packets to a temporary .pcap and return its path."""

    def write(pkts, name: str = "test.pcap") -> Path:
        path = tmp_path / name
        write_capture(path, sorted(pkts, key=lambda p: float(p.time)))
        return path

    return write
