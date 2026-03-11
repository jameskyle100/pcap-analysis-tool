Install required dependencies.

pip install -r requirements.txt

Or with Python3:

pip3 install -r requirements.txt
Running the Tool

Start the analysis server.

python3 analyzer.py

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
python3 analyzer.py

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
