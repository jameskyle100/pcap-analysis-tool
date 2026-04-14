# PCAP Analysis Tool

Investigation-ready PCAP analysis for faster SOC triage and deeper network insight.

The tool automatically analyzes `.pcap` and `.pcapng` files and produces investigation-ready insights including network behavior, suspicious activity indicators, and a formal analysis summary report.

This tool is intended for SOC analysts, incident responders, and threat hunters** who need rapid visibility into captured network traffic.

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
<img width="659" height="175" alt="Screenshot 2026-04-14 141329" src="https://github.com/user-attachments/assets/fa8d49a7-486c-4a1d-807f-ad5cc66a8457" />
<img width="937" height="469" alt="Screenshot 2026-04-14 141230" src="https://github.com/user-attachments/assets/1fc98df5-5435-4523-8d79-71c1dcb48d93" />
<img width="935" height="469" alt="Screenshot 2026-04-14 141057" src="https://github.com/user-attachments/assets/872f4fa0-511f-4006-92e0-bc333ea7b201" />


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
git clone https://github.com/jameskyle100/pcap-analysis-tool.git
cd pcap-analysis-tool

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
git clone https://github.com/jameskyle100/pcap-analysis-tool.git
cd pcap-analysis-tool
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
pcap-analysis-tool
│
├── run_dashboard.py
├── requirements.txt
├── README.md
