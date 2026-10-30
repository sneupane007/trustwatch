"""Every detector the engine runs. Add a new one here to put it on the dashboard."""

from .arp_spoof import ArpSpoofDetector
from .dns_spoof import DnsSpoofDetector
from .port_scan import PortScanDetector

# Same order as our slides: ARP, DNS, port scan.
ALL_DETECTORS = [ArpSpoofDetector, DnsSpoofDetector, PortScanDetector]
