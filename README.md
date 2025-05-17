#SocketSheriff
A PyQt5-based application for monitoring network connections and capturing packets on Windows. This tool displays active network connections with process information and allows packet sniffing for selected processes by filtering based on the ports that process is using. Supports saving captured packets in PCAP or CSV format.
Features

Process Monitoring: View all processes with active network connections
Connection Tracking: See detailed connection history for each process
Packet Sniffing: Capture and inspect network packets for selected processes
Port-Based Filtering: Automatically filters packets based on the ports used by the selected process
Save Options: Export captured packets as PCAP (for use with Wireshark) or CSV
Process Management: View process relationships (parent/child) and status



Install required dependencies:
```bash
pip install PyQt5 psutil scapy pillow
```

Run the application:
```bash
python socket-sheriff.py
```


###Limitations

Port-Based Filtering: The packet capture uses port filtering which has limitations:

If multiple processes share the same ports, packets from all of them will be captured
Processes using dynamic port allocation may not be fully tracked



Contributions are welcome! Please feel free to submit a Pull Request.
License
MIT
