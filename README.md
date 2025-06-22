# HIDS

This project is a Host-Based Intrusion Detection System developed in C++ for Linux systems. It monitors local system activity by capturing network packets using libpcap and analyzing them for known attack signatures.

## 🚀 Features

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

## 🧰 Prerequisites

- A Linux system (preferably Kali, Ubuntu, Debian, etc.)
- GCC Compiler
- `libpcap` and `libsqlite3` development libraries

Installation

1. Install the required dependencies:
```bash
sudo apt update
sudo apt install build-essential libpcap-dev libsqlite3-dev
