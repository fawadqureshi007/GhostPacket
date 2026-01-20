

---

# ARP Spoofing with Scapy

A Python-based demonstration of an **ARP spoofing (ARP poisoning)** attack using the **Scapy** library.
This project shows how ARP manipulation can be used to intercept network traffic between two devices on a local network.

---

## ⚠️ Legal Disclaimer

**This tool is for educational and authorized security testing purposes only.**

ARP spoofing is illegal and unethical when performed without permission.

### You must always:

* Obtain **explicit written authorization**
* Test only on **networks you own or are authorized to assess**
* Comply with **local and international cybersecurity laws**

The author assumes **no responsibility** for misuse of this software.

---

## 📌 Project Overview

### This project demonstrates:

* How the ARP protocol works internally
* How ARP tables can be poisoned
* The risks of unsecured local networks
* The importance of ARP defenses and monitoring

---

## 📋 Prerequisites

### Required:

* Python 3.x
* Scapy
* Administrator / Root privileges

### Supported Platforms:

* Linux
* macOS
* Windows (requires **Npcap** with WinPcap compatibility)

---

## 🔧 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/fawadqureshi007/GhostPacket.git
cd GhostPacket
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

### Alternative:

```bash
pip install scapy
```

---

## 🚀 Usage

### Run the script with administrator or root privileges:

```bash
sudo python3 arp.py -t <target_ip> -g <gateway_ip>
```

### Arguments

* `-t, --target`
  Target device IP address

* `-g, --gateway`
  Gateway (router) IP address

### Example

```bash
sudo python3 arp.py -t 192.168.1.100 -g 192.168.1.1
```

Press **Ctrl + C** to stop the attack and automatically restore the ARP tables.

---

## 🧠 How It Works

### Step-by-step process:

1. **MAC Address Resolution**
   Resolves MAC addresses for the target and gateway.

2. **ARP Poisoning**
   Sends forged ARP replies to both devices.

3. **Traffic Interception (MITM)**
   Redirects traffic through the attacker machine.

4. **ARP Restoration**
   Restores legitimate ARP entries on exit.

---

## 🔍 Core Functions

### Key functions used in the script:

* `get_mac(ip)`
  Resolves an IP address to a MAC address

* `spoof(target_ip, spoof_ip)`
  Sends fake ARP responses

* `restore(destination_ip, source_ip)`
  Restores correct ARP table entries

---

## 📦 Dependencies

### Python Libraries:

* **Scapy** — packet crafting and network manipulation

---

## 🎓 Educational Purpose

### This project helps you understand:

* ARP vulnerabilities
* Man-in-the-Middle (MITM) attacks
* Packet-level traffic interception
* Network security fundamentals

---

## 🔐 Mitigation and Defense

### To protect against ARP spoofing attacks:

* Use static ARP entries
* Enable Dynamic ARP Inspection (DAI)
* Implement DHCP snooping
* Encrypt traffic using HTTPS, SSH, or VPNs
* Segment networks with VLANs

---

## ⚠️ Troubleshooting

### Permission Denied

* Use `sudo` on Linux/macOS
* Run as Administrator on Windows

### Scapy Not Installed

```bash
pip install scapy
```

### MAC Address Not Found

* Ensure the target is online
* Confirm both devices are on the same subnet

### Npcap Issues (Windows)

* Install Npcap from [https://nmap.org/npcap/](https://nmap.org/npcap/)
* Enable **WinPcap compatibility mode**

---

## 📄 License

### MIT License

This project is licensed under the **MIT License**.
See the `LICENSE` file for more information.

---

## 🤝 Contributing

### Contributions are welcome!

Please ensure:

* Code follows **PEP 8**
* Complex logic is commented clearly
* Functions include meaningful docstrings

---

## 📚 References

* Scapy Documentation
* ARP Protocol — RFC 826
* Man-in-the-Middle Attack Concepts

---

## ✅ Final Reminder

**Use this tool responsibly, ethically, and legally.**

---

