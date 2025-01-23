# Packet Sniffer

This Python script is a simple network packet sniffer that captures HTTP traffic and detects potential login information (e.g., usernames and passwords). It can be used to monitor a specified network interface for HTTP requests and analyze the content of the packets.

---

## Features

- **Capture HTTP Requests:** Extract the URL of each HTTP request on the network.
- **Detect Login Credentials:** Search for potential usernames and passwords in HTTP packets.
- **Live Packet Processing:** Processes packets in real time without storing them to disk.

---

## Requirements

To run this script, you need:
- Python 3.6+
- The `scapy` library for packet sniffing and manipulation:
```bash
pip install scapy
```

## How to Use
1. Clone the Repository
Clone this repository or download the script file directly:

```bash
git clone https://github.com/MashoodShabbir/Packet_Sniffer.git
cd PacketSniffer
```

2. Run the Script
Execute the script using Python. Specify the network interface you want to sniff on using the -i or --iface argument:

```bash
python packet_sniffer.py -i <interface>
```
This will start sniffing packets on the eth0 interface.

## Output
1. HTTP Request URLs:
The script displays the URL of each HTTP request intercepted on the specified interface:

```bash
[+] HTTP Request: example.com/login
```
2. Login Information (if any):
If the script detects potential login credentials in the intercepted packets, it will display them:

```bash
[+] Possible Username/Password: username=admin&password=12345
```
## Important Notes
1. Root Privileges:
Packet sniffing typically requires root/administrator permissions. Use sudo when running the script:

```bash
sudo python packet_sniffer.py -i <interface>
```
2. HTTP Only:
This script works on unencrypted HTTP traffic. It cannot sniff encrypted HTTPS traffic due to SSL/TLS encryption.

3. Use Responsibly:
Ensure you have proper authorization to monitor the specified network. Unauthorized sniffing of network traffic may be illegal and unethical.

## Arguments
-i or --iface: Specifies the network interface to sniff packets on (e.g., eth0, wlan0).

## Example Output
```bash
[+] HTTP Request: example.com/login
[+] Possible Username/Password: username=admin&password=12345
```
If no login information is found, only the HTTP request URLs are displayed.

## Disclaimer
This script is intended for educational purposes and authorized network monitoring only. Unauthorized use of this tool on networks where you do not have permission is illegal and unethical.

Thank you for checking out this project! Feel free to contribute or report any issues.

