# SOC PCAP Analysis Tool

A SOC-focused PCAP triage dashboard designed to help security analysts quickly analyze packet capture files without spending hours manually reviewing traffic in Wireshark.

The tool automatically analyzes `.pcap` and `.pcapng` files and produces investigation-ready insights including network behavior, suspicious activity indicators, and a formal analysis summary report.

This tool is intended for **SOC analysts, incident responders, and threat hunters** who need rapid visibility into captured network traffic.

---

# Features

SOC-Oriented PCAP Triage

- Upload `.pcap` or `.pcapng` files through a web dashboard
- Automatic packet analysis
- Host activity profiling
- DNS query analysis
- TLS SNI inspection
- HTTP request investigation
- Conversation flow detection
- Suspicious behavior findings
- Analyst takeaway generation
- Formal investigation summary
- Downloadable PDF report

---

# Dashboard Capabilities

The dashboard provides immediate visibility into capture activity.

### PCAP Summary
- Packet count
- Top protocols
- Unique hosts
- Triage score
- Findings summary

### Capture Health
- Average packet size
- Median packet size
- Most used ports
- Most queried DNS domains

### Investigation Tabs

Findings  
Prioritized security observations detected during analysis.

Hosts  
Most active systems and communication patterns.

Network  
Top source and destination IP activity.

DNS & TLS  
Domain queries and TLS SNI analysis.

Web  
HTTP requests and paths.

Flows  
Conversation flows between hosts.
<img width="979" height="226" alt="0" src="https://github.com/user-attachments/assets/83ef2476-cdca-4f13-971f-01ec40b84750" />
<img width="918" height="768" alt="Screenshot_2026-03-11_15-51-34" src="https://github.com/user-attachments/assets/41825bc7-b860-4ac3-8e7e-6daed3369633" />

<img width="920" height="614" alt="2" src="https://github.com/user-attachments/assets/363d8e5c-1df7-4b0c-937c-1ace603d3d42" />
<img width="919" height="720" alt="3" src="https://github.com/user-attachments/assets/a8ac8aa5-8e3b-4fa9-a8b5-62dc397c5a0c" />
<img width="743" height="772" alt="4" src="https://github.com/user-attachments/assets/fee3b2fb-c900-4e3a-9c86-09bf627bcda5" />
<img width="701" height="467" alt="6" src="https://github.com/user-attachments/assets/7ea007d9-dd23-42da-996a-d9c5b00a366d" />

---

# Formal Analysis Report

<img width="562" height="752" alt="5" src="https://github.com/user-attachments/assets/b26d1733-a2d2-4a2e-9d80-4ed74ef6ea1b" />

The tool can generate a **formal SOC investigation report** including:

- Executive Overview
- Analyst Takeaway
- Priority Findings
- Most Relevant Hosts
- Capture Metrics
- Investigation Recommendation

Reports can be exported as **PDF for incident documentation**.

---

# Installation

Clone the repository.

```bash
git clone https://github.com/jameskyle100/soc-pcap-analysis-tool.git
cd soc-pcap-analysis-tool

Install required dependencies.

pip install -r requirements.txt

Or with Python3:

pip3 install -r requirements.txt
Running the Tool

Start the analysis server.

python3 run_dashboard.py

Once the server starts, open your browser and navigate to:

http://127.0.0.1:8765
Using the Tool

Open the dashboard in your browser.

Upload a .pcap or .pcapng file.

Select an analysis mode.

Click Analyze PCAP.

Review the results in the dashboard tabs.

Open Analysis Summary to generate the formal report.

Download the PDF report if needed.

Analysis Modes
Mode	Description
quick	Fast statistical analysis
hunt	Deep SOC investigation mode
web	Focus on HTTP activity
dns	Focus on DNS queries

Recommended mode for investigations:

hunt
Example Usage
git clone https://github.com/jameskyle100/soc-pcap-analysis-tool.git
cd soc-pcap-analysis-tool
pip install -r requirements.txt
python3 run_dashboard.py

Open:

http://127.0.0.1:8765

Upload a PCAP file and begin analysis.

Security Notice

This tool performs local static packet analysis only.

It does NOT:

execute payloads

connect to external threat intelligence services

upload PCAP data anywhere

All analysis is performed locally on the machine running the tool.

Project Structure
soc-pcap-analysis-tool
│
├── run_dashboard.py
├── requirements.txt
├── README.md
