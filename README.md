# SocketSheriff
A PyQt5-based application for monitoring network connections and capturing packets on Windows. This tool displays active network connections with process information and allows packet sniffing for selected processes by filtering based on the ports that process is using. Supports saving captured packets in PCAP or CSV format.
Features


![ss](https://github.com/user-attachments/assets/c268cec8-2df8-4a1d-9c6c-9d38939d022e)

### Requirements

* Windows operating system
* Python 3.6+
* Dependencies:
  * PyQt5: GUI framework
  * psutil: Process and system information
  * scapy: Packet capture and analysis
  * Pillow: Image processing for icons

Install required dependencies:
```bash
pip install PyQt5 psutil scapy pillow
```

Run the application:
```bash
python socket-sheriff.py
```


### Limitations

Port-Based Filtering: The packet capture uses port filtering which has limitations:

If multiple processes share the same ports, packets from all of them will be captured
Processes using dynamic port allocation may not be fully tracked



Contributions are welcome! Please feel free to submit a Pull Request.
License
MIT
