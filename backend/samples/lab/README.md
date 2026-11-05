# Lab captures

Real captures from our isolated lab, used to check the detectors on real traffic
(Phase 1 Part 2, Tasks C and D). The synthetic samples one folder up only prove the logic.

> **Safety:** recorded only on a UTM **Host Only** network, against our own VMs.

## Lab setup

UTM on macOS (Apple silicon), QEMU backend, all VMs ARM64 Ubuntu, network mode **Host Only**
(`192.168.128.0/24`). Wireshark runs on the victim.

| VM | Role | IP | MAC | Interface |
|---|---|---|---|---|
| Attacker | Ubuntu with `dsniff`, `ettercap-text-only`, `nmap` | `192.168.128.2` | `0a:7b:7b:0d:b7:d5` | `enp0s1` |
| Victim | Ubuntu with Wireshark | `192.168.128.3` | `9a:46:0e:88:e1:45` | `enp0s1` |
| Server | Ubuntu, the host the attacker impersonates | `192.168.128.5` | `b2:70:50:cd:34:45` | `enp0s1` |

Attack tools were installed by switching the attacker to Shared Network for the install only,
then back to Host Only before any attack.

## Captures

### `arp_spoof.pcapng` (recorded 2026-10-30)

1. Victim: start Wireshark on `enp0s1`, then `ping -c 3 192.168.128.5` so the server's real MAC is seen first.
2. Attacker:
   ```
   sudo sysctl -w net.ipv4.ip_forward=1
   sudo arpspoof -i enp0s1 -t 192.168.128.3 192.168.128.5
   ```
3. Victim, during the attack: `ping -c 5 192.168.128.5` and `ip neigh`.
   `192.168.128.5` changed from `b2:70:50:cd:34:45` to `0a:7b:7b:0d:b7:d5` (the attacker).
4. After ~30 s: Ctrl+C on the attacker (arpspoof re-sends the real MAC), then
   `sudo sysctl -w net.ipv4.ip_forward=0`.

### Still to record

- `baseline.pcapng`: ~5 minutes of normal use on the victim, no attacks.
- `dns_spoof.pcapng`: needs `dnsmasq` on the server and an ettercap `dns_spoof` run; add the lab
  domain's real address to `KNOWN_GOOD` in `app/detectors/dns_spoof.py`.
- `port_scan.pcapng`: `sudo nmap -sS 192.168.128.3` from the attacker.

## Results

| Capture | Expected | Detected | False alarms | Notes |
|---|---|---|---|---|
| baseline | none | not recorded yet | | |
| arp_spoof | ARP spoofing | ✅ 1 alert, high | 0 | 87 packets. Attacker `0a:7b:7b:0d:b7:d5`, victim `192.168.128.3`, original MAC `b2:70:50:cd:34:45` (frame #11). 39 forged claims, frames 22–80. |
| dns_spoof | DNS spoofing | not recorded yet | | |
| port_scan | Port scan | not recorded yet | | |

### Observations for the report

- **Restore packets are not counted.** When arpspoof stops it sends 5 replies (frames 81–85)
  restoring the real MAC. Wireshark's `arp.duplicate-address-detected` flags them because they
  come from the attacker's NIC, but they claim the real MAC, so TrustWatch correctly ignores them.
- **ICMP redirects give the attacker away.** With IP forwarding on, the attacker's kernel sent the
  victim `Redirect Host (New nexthop: 192.168.128.5)`, another visible sign of a man-in-the-middle.
- **"First MAC wins"** worked here because the victim pinged the server before the attack started.
