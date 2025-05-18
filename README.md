# Networksniff
Below is a Python network sniffer that captures and analyzes network traffic using the scapy library. This sniffer can capture packets, display their information, and perform basic analysis.

# Prerequisites
First, install the required packages:

# bash
pip install scapy matplotlib
# Features:
# 1.Packet Capture:

Captures packets from a specified network interface

Supports BPF filters to capture specific traffic (e.g., 'tcp port 80')

# 2.Traffic Analysis:

Counts packets by protocol (TCP, UDP, ICMP)

Tracks source and destination IP addresses

Records packet sizes and timestamps

# 3. Visualization

# Usage
Run the script (may require admin/sudo privileges)

Select an interface (or press Enter for default)

Enter number of packets to capture (0 for unlimited)

Optionally enter a BPF filter expression

Press Ctrl+C to stop capture and view statistics

# Advanced Features to Consider Adding
Deep Packet Inspection:

Extract HTTP headers from TCP packets

Analyze DNS queries/responses

Security Monitoring:

Detect port scans or SYN floods

Identify suspicious traffic patterns

Performance Enhancements:

Multithreading for real-time analysis

Packet filtering before processing

Output Options:

Save captured packets to PCAP file

Generate HTML reports

# To Run the Script

 1. Save the Script
Download/Copy the script, and save it as network_sniffer.py

 2. Run the Script
Since sniffing requires root privileges, run it with sudo:
sudo python3 network_sniffer.py

3. Select Interface & Options
When prompted:
Enter interface (e.g., eth0, wlan0)

Packet count: Enter 0 for unlimited (stop with Ctrl+C).

BPF filter: Optional (e.g., tcp port 80 for HTTP traffic).
