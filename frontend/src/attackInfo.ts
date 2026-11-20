// Text from our slides: Attacks_Deck_Detailed.pptx and Theory_Why_Attacks_Work.pptx.

export interface AttackInfo {
  layer: string;
  howItWorks: string;
  trustAssumption: string;
  inWireshark: string;
  howWeDetect: string;
  realWorldFix: string;
}

export const ATTACK_INFO: Record<string, AttackInfo> = {
  arp_spoof: {
    layer: "Link / network",
    howItWorks:
      "The attacker sends forged ARP replies claiming the gateway's IP. The victim updates its ARP cache and sends its traffic to the attacker.",
    trustAssumption: "Any reply is believed, even one nobody asked for. Nothing checks who is answering.",
    inWireshark:
      "Filter arp. Look for repeated unsolicited replies (arp.opcode == 2) where one MAC address answers for an IP it should not own.",
    howWeDetect: "Track IP to MAC pairs over time. Flag any IP that suddenly maps to a second MAC address.",
    realWorldFix: "Dynamic ARP Inspection, static ARP entries",
  },
  dns_spoof: {
    layer: "Application, over UDP",
    howItWorks:
      "The attacker answers a DNS query first with a forged reply that reuses the query ID. The victim trusts the first answer it gets.",
    trustAssumption: "The first answer matching the query ID wins. Answers carry no proof of origin.",
    inWireshark:
      "Filter dns. Compare dns.id and the answer records. Two responses to one query with different addresses is the tell.",
    howWeDetect:
      "Group responses by query ID and name. Flag conflicting answers, or an answer that differs from a known-good address.",
    realWorldFix: "DNSSEC, encrypted DNS",
  },
  port_scan: {
    layer: "Transport, TCP",
    howItWorks:
      "The attacker sends SYN packets to many ports and reads the replies: SYN/ACK means open, RST means closed. A SYN scan never finishes the handshake.",
    trustAssumption: "Open and closed ports must answer differently (SYN/ACK vs RST) for TCP to work.",
    inWireshark:
      "Filter tcp.flags.syn == 1 && tcp.flags.ack == 0. Expect a burst of SYNs from one source to many ports within seconds.",
    howWeDetect:
      "Count distinct destination ports per source in a sliding window. Flag any source that crosses a threshold tuned on the baseline.",
    realWorldFix: "Firewall rules, rate limiting, IDS",
  },
};

export const CLOSING_IDEA = "Each of these attacks works because the protocol trusts by default.";
