# HIDS

This project is a Host-Based Intrusion Detection System developed in C++ for Linux systems. It monitors local system activity by capturing network packets using libpcap and analyzing them for known attack signatures.

## Features

- Real-time packet capture using `libpcap`
- Detection of:
  - TCP Floods
  - UDP Floods
  - ICMP (Ping) Floods
  - SYN Floods
  - Port Scans
- Stores all attack data in an SQLite database
- Alerts printed on terminal and logged to `alerts.txt`
- Automatically selects the network interface on startup

## Prerequisites

- A Linux system (preferably Kali, Ubuntu, Debian, etc.)
- GCC Compiler
- `libpcap` and `libsqlite3` development libraries

## Installation

1. Install the required dependencies:
```bash
sudo apt update
sudo apt install build-essential libpcap-dev libsqlite3-dev
```
2. Clone the repository:
```bash
git clone https://github.com/haera16/HIDS.git
cd HIDS
```
3. Build the project:
```bash
g++ -o hids hids.cpp -lpcap -lsqlite3
```
4. Ensure your signature.db is present with an attacks table:
```bash
CREATE TABLE attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    attack_type TEXT,
    source_ip TEXT,
    target_ip TEXT,
    target_port INTEGER,
    packet_count INTEGER,
    severity TEXT,
    description TEXT
);
```

## Usage
1. Run the IDS (with root privileges):
```bash
sudo ./hids
```
2. The program will start monitoring network traffic and:

- Display real-time packet capture logs
- Log intrusion alerts to `alerts.txt`
- Store detailed attack data in `signature.db`
- Detect and notify potential security threats like floods or scans

## Logging
The system automatically logs events to `alerts.txt` and stores attack records in `signature.db`, including:

- Detected flood attacks (TCP, UDP, ICMP, SYN)
- Port scan attempts
- Timestamps and IP address information
- Packet counts and severity levels

## Configuration
You can modify the following parameters directly in the `hids.cpp` source code:

- `TCP_FLOOD_THRESHOLD`, `UDP_FLOOD_THRESHOLD`, `ICMP_FLOOD_THRESHOLD`, `SYN_FLOOD_THRESHOLD`: Packet count thresholds for detection
- `PORT_SCAN_THRESHOLD`: Number of unique ports scanned in a time window
- `TIME_WINDOW`: Time frame (in seconds) for attack detection logic
- SQLite database path: Adjust in the `init_database()` function if needed

## Contributing
1. Fork the repository  
2. Create your feature branch (`git checkout -b feature/YourFeature`)  
3. Commit your changes (`git commit -m 'Add YourFeature'`)  
4. Push to the branch (`git push origin feature/YourFeature`)  
5. Open a Pull Request

## Acknowledgments
- [libpcap](https://www.tcpdump.org/) library developers  

