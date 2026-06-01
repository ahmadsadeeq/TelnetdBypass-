# TelnetdBypass — CVE-2026-24061 Scanner

A Python-based security scanner that detects and exploits **CVE-2026-24061**, 
a critical (CVSS 9.8) authentication bypass vulnerability in GNU InetUtils 
telnetd versions 1.9.3 through 2.7.

## How it Works
The scanner injects a malicious `USER=-f root` value via the Telnet 
NEW-ENVIRON option (RFC 1572), tricking the server into skipping 
authentication and granting a root shell.

## Features
- Single IP, hostname, or full CIDR range scanning
- Multi-threaded (default 50 threads) for fast results
- Live progress bar with coloured terminal output
- Post-exploitation confirmation via `id` command
- Saves reports in plain text or JSON format

## Usage
```bash
# Scan single target
sudo python3 telnetd_scanner.py -t 192.168.56.101 -p 23 -v

# Scan entire subnet
sudo python3 telnetd_scanner.py -t 192.168.56.0/24 --threads 30

# Save report
sudo python3 telnetd_scanner.py -t 192.168.56.101 -o report.txt

# JSON output
sudo python3 telnetd_scanner.py -t 192.168.56.101 --format json -o report.json
```

## Affected Versions
| Software | Vulnerable | Patched |
|---|---|---|
| GNU InetUtils telnetd | <= 2.7 | >= 2.8 |

## Tested On
- Kali Linux (attacker)
- Debian 11 with inetutils-telnetd (target)
- VirtualBox Host-Only Network

## Disclaimer
This tool is for **authorised security research and educational purposes only**.
Do not use against systems you do not own or have explicit permission to test.

## Author
Ahmad Sadeeq
