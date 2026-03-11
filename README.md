# SOC PCAP Analysis Tool

A lightweight SOC-focused PCAP triage dashboard designed to help analysts quickly investigate packet captures without spending hours manually reviewing them in Wireshark.

The tool automatically analyzes a `.pcap` or `.pcapng` file and generates:

• Threat findings  
• Network behavior summary  
• Host activity insights  
• DNS and TLS indicators  
• HTTP request patterns  
• Conversation flows  
• Capture health metrics  

It also generates a **formal incident-ready analysis summary report** which can be downloaded as a **PDF**.

---

# Features

SOC-oriented triage dashboard

• One-command launch  
• Web UI dashboard  
• Automatic PCAP analysis  
• Host activity profiling  
• DNS & TLS inspection  
• Web request analysis  
• Conversation flow detection  
• Priority findings detection  
• Analyst takeaway generation  
• Formal report generator  
• Downloadable PDF summary

---

# Dashboard Overview

The UI provides:

PCAP Summary
- packet count
- top protocols
- triage score
- findings

Capture Health
- average packet size
- median packet size
- top ports
- top DNS queries

Investigation Tabs
- Findings
- Hosts
- Network
- DNS & TLS
- Web
- Flows

Formal Report
- Executive overview
- Analyst takeaway
- Priority findings
- Most relevant hosts
- Capture metrics
- Recommendations

---

# Installation

Clone or download the project.

```bash
git clone https://github.com/yourrepo/soc-pcap-analysis-tool
cd soc-pcap-analysis-tool
