 PoC for CVE-2024-55591
A comprehensive all-in-one Python-based Proof of Concept script to discover and exploit a critical authentication bypass vulnerability (CVE-2024-55591) in certain Fortinet devices. This script:

Installs Missing Dependencies automatically
Optionally Scans a target host for open ports using nmap
Performs Pre-flight Checks to ensure the service is a Fortinet device and is vulnerable
Exploits the WebSocket interface to hijack a Telnet-like CLI session
Runs an Initial or Multiple Commands post-exploit
Checks the Device Version against known vulnerable ranges from Fortinet PSIRT FG-IR-24-535
Table of Contents
Vulnerability Summary
Affected Versions
Pre-Requisites
Usage
1. Clone & Install
2. Run the Script
3. Follow the Wizard
Features
Automatic Dependency Installation
Optional Nmap SYN Scanning
Multi-Port Testing
Post-Exploitation Commands
Version Parsing and Vulnerability Check
Example Walkthrough
1. Initial Wizard Prompts
2. Nmap Results & Port Selection
3. Exploitation Flow
4. Post-Exploitation Flow
Disclaimer
Vulnerability Summary
CVE-2024-55591 is a critical authentication bypass in certain Fortinet products (FortiOS & FortiProxy). By exploiting a flaw in the WebSocket/Telnet management interface, an attacker can gain privileged CLI access without valid credentials.

Affected Versions
According to the Fortinet PSIRT Advisory (FG-IR-24-535), the following versions are known to be affected:

FortiOS: 7.0.0 to 7.0.16
FortiProxy: 7.0.0 to 7.0.19, 7.2.0 to 7.2.12
Pre-Requisites
Python 3.x
(Optional) Nmap for automatic port scanning
Network access to the target device
Sufficient privileges on your local machine to install missing Python packages (if needed)
Usage
1. Clone & Install
git clone https://github.com/ScaryByteRnD/CVE-2024-55591-POC.git
cd CVE-2024-55591-POC
2. Run the Script
python3 ScaryByte_CVE_2024_55591.py
When executed, the script automatically checks for missing Python dependencies (requests, urllib3) and attempts to install them.

3. Follow the Wizard
You will be prompted for:

Target IP/Hostname
Whether to run Nmap to find open ports
If multiple open ports are found, whether to test ALL or just one
Whether to use SSL
A Command to run initially (you can select from a pre-defined list or supply your own)
(Optional) Whether to run post-exploitation commands
Once you confirm, the script tests connectivity, checks vulnerability, upgrades the connection to WebSocket, and attempts the auth bypass.

Features
Automatic Dependency Installation
At startup, this script checks for requests and urllib3. If missing, it attempts to install them via pip.

Optional Nmap SYN Scanning
If you choose, the script runs nmap -sS -p- --min-rate 500 <host> to discover open TCP ports, then either:

Tries all the discovered ports
Lets you pick one
Multi-Port Testing
If multiple ports are discovered open, you can instruct the script to test them all. This is useful if Fortinet services are listening on non-standard ports.

Post-Exploitation Commands
If the exploit succeeds, you can optionally run additional commands in the same Telnet session, such as:

diag sys top
diag debug crashlog read
execute shell
You can modify these post-exploitation commands in the script to gather more advanced data.

Version Parsing and Vulnerability Check
The script attempts to parse the device version from the output of get system status or get system info. If it matches a known vulnerable range, it notifies you.

Example Walkthrough
1. Initial Wizard Prompts
Target IP: e.g., 192.168.1.50
Nmap scan?: y (Yes) to discover open ports
SSL?: Typically y if connecting via HTTPS/443
Initial Command: e.g., get system status
Post-exploit commands: y or n
2. Nmap Results & Port Selection
If Nmap finds multiple open ports, you can choose to test all ports automatically or pick a specific one.

3. Exploitation Flow
The script checks if /login?redir=/ng returns Fortinet’s management interface
The script checks if service-worker.js?local_access_token=ScaryBYte contains the substring api/v2/static
If both checks pass, it attempts the WebSocket upgrade and sends a fake Telnet login context
Once you have a Telnet-like CLI, you can run commands like get system status
4. Post-Exploitation Flow
If post-exploit mode is enabled, the script sends additional debug or system commands. The output is collected and displayed in your console.
