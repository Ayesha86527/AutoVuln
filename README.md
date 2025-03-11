# AutoVuln

# Overview
AutoVuln is a CLI-based automated vulnerability assessment tool designed for penetration testers and cybersecurity professionals. It uses Nmap for port scanning, service detection and vulnerability identification using NSE scripts.

# Features
- Automated port scanning (fast scan, focused scan, deep scan and optimized deep scan)
  * Fast Scan: Scans first 100 ports
  * Focused Scan: Scans popular ports like 443,80 etc.
  * Deep Scan: Scans all 65535 ports.
  * Optimized Deep Scan: Scans first 10000 ports.
- Services and OS detection
- NSE-based vulnerability scanning
- CLI-based for easy and fast execution

# Installation 
* Prerequistes
  1. Python 3.12
  2. Nmap installed
  3. Required python module
     pip install nmap
* Cloning the Repository
  git clone http://github.com/Ayesha86527/AutoVuln.git
  cd AutoVuln
