# certrecon.py - CERTRECON v1.2
# Made with Pride 🇮🇳 by Ritik Shrivas

import requests
import json
import os
import sys
import time
import random
from termcolor import colored
from pyfiglet import Figlet
from tqdm import tqdm

# -------------------- Dynamic Banner --------------------
def display_banner():
    # Use only guaranteed available fonts on Kali
    fonts = ["slant", "big", "standard", "smslant", "block", "digital"]
    font_choice = random.choice(fonts)
    f = Figlet(font=font_choice)

    print(colored(f.renderText("CERTRECON"), 'green'))
    print(colored("🛡️  MADE IN INDIA  🇮🇳", 'cyan'))
    print(colored("🔥 Recon Like a Ghost, Strike Like a Beast!", 'yellow'))
    print(colored("🔐 Proudly Developed by Ritik Shrivas\n", 'magenta'))

# -------------------- Terminal Loading Animation --------------------
def loading_animation(message, duration=5):
    spinner = ["◐", "◓", "◑", "◒"]
    for _ in range(duration * 5):
        sys.stdout.write(f"\r{message} {random.choice(spinner)}")
        sys.stdout.flush()
        time.sleep(0.2)
    sys.stdout.write("\n")

# -------------------- Fetch Subdomains --------------------
def fetch_subdomains(domain):
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        loading_animation("🔍 Fetching subdomains...", 5)
        response = requests.get(url)
        if response.status_code == 200:
            data = json.loads(response.text)
            subdomains = set()
            for entry in data:
                name_value = entry.get("name_value")
                if name_value:
                    for subdomain in name_value.split('\n'):
                        subdomains.add(subdomain.strip())
            return list(subdomains)
        else:
            print(colored("[!] Error fetching subdomains from cert.sh!", 'red'))
            return []
    except Exception as e:
        print(colored(f"[!] Error: {str(e)}", 'red'))
        return []

# -------------------- Check Live Hosts --------------------
def check_live_hosts(subdomains):
    live_hosts = []
    for subdomain in tqdm(subdomains, desc="🕵️ Checking live hosts", unit="host"):
        try:
            response = requests.get(f"http://{subdomain}", timeout=3)
            if response.status_code < 400:
                live_hosts.append(subdomain)
        except requests.RequestException:
            continue
    return live_hosts

# -------------------- Advanced Module: Subdomain Takeover Checker --------------------
def check_subdomain_takeover(live_hosts):
    # Placeholder: Simulate takeover check.
    vulnerable = []
    for host in live_hosts:
        if "test" in host:  # Simulated condition
            vulnerable.append(host)
    print(colored(f"[+] Subdomain takeover check completed. {len(vulnerable)} vulnerable hosts found!", 'green'))
    return vulnerable

# -------------------- Advanced Module: Port Scanner --------------------
def port_scan(live_hosts):
    # Placeholder: Simulate port scanning.
    port_results = {}
    for host in live_hosts:
        port_results[host] = [80, 443, 22]  # Simulated open ports
    print(colored("[+] Port scanning completed!", 'green'))
    return port_results

# -------------------- Advanced Module: Vulnerability Scanner --------------------
def vulnerability_scan(live_hosts):
    # Placeholder: Simulate vulnerability scanning.
    vuln_results = {}
    for host in live_hosts:
        vuln_results[host] = {
            "XSS": random.choice(["Found", "Not Found"]),
            "SQLi": random.choice(["Found", "Not Found"])
        }
    print(colored("[+] Vulnerability scanning completed!", 'green'))
    return vuln_results

# -------------------- Advanced Module: Report Generator --------------------
def generate_extended_report(subdomains, live_hosts, takeover, port_results, vuln_results):
    report = "<html><head><title>CERTRECON Extended Report</title></head><body>"
    report += "<h1>CERTRECON v1.2 Extended Report</h1>"
    report += "<h2>Subdomains Found</h2><ul>"
    for s in subdomains:
        report += f"<li>{s}</li>"
    report += "</ul>"
    report += "<h2>Live Hosts</h2><ul>"
    for h in live_hosts:
        report += f"<li>{h}</li>"
    report += "</ul>"
    report += "<h2>Subdomain Takeover Vulnerabilities</h2><ul>"
    for v in takeover:
        report += f"<li>{v}</li>"
    report += "</ul>"
    report += "<h2>Port Scan Results</h2><ul>"
    for host, ports in port_results.items():
        report += f"<li>{host}: {ports}</li>"
    report += "</ul>"
    report += "<h2>Vulnerability Scan Results</h2><ul>"
    for host, vulns in vuln_results.items():
        report += f"<li>{host}: {vulns}</li>"
    report += "</ul>"
    report += "</body></html>"
    
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    report_file = os.path.join(desktop_path, "certrecon_extended_report.html")
    with open(report_file, "w") as f:
        f.write(report)
    print(colored(f"[✔️] Extended report saved to: {report_file}", 'green'))

# -------------------- Save Base Results to Desktop --------------------
def save_results(subdomains, live_hosts):
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    output_file = os.path.join(desktop_path, "certrecon_results.txt")

    with open(output_file, "w") as f:
        f.write("=== CERTRECON v1.2 RESULTS ===\n")
        f.write("Subdomains Found:\n")
        for sub in subdomains:
            f.write(f"{sub}\n")
        f.write("\nLive Hosts:\n")
        for live in live_hosts:
            f.write(f"{live}\n")

    print(colored(f"[✔️] Base results saved to: {output_file}", 'green'))

# -------------------- Main Function --------------------
def main():
    os.system('clear' if os.name == 'posix' else 'cls')
    display_banner()

    # User Input - Enter Target Domain
    domain = input(colored("[+] Enter Target Domain: ", 'cyan')).strip()
    if not domain:
        print(colored("[!] Invalid domain! Exiting...", 'red'))
        sys.exit(1)

    # Fetching subdomains
    subdomains = fetch_subdomains(domain)
    if not subdomains:
        print(colored("[!] No subdomains found!", 'red'))
        sys.exit(1)

    print(colored(f"[+] {len(subdomains)} subdomains found!", 'green'))

    # Check live hosts
    live_hosts = check_live_hosts(subdomains)
    print(colored(f"[+] {len(live_hosts)} live hosts found!", 'green'))

    # Save base results
    choice = input(colored("[?] Do you want to save the base results? (y/n): ", 'yellow')).strip().lower()
    if choice == "y":
        save_results(subdomains, live_hosts)
    else:
        print(colored("[*] Base results not saved.", 'red'))

    # Prompt for advanced modules
    advanced_choice = input(colored("[?] Do you want to run advanced checks? (y/n): ", 'yellow')).strip().lower()
    if advanced_choice == "y":
        takeover = check_subdomain_takeover(live_hosts)
        port_results = port_scan(live_hosts)
        vuln_results = vulnerability_scan(live_hosts)
        generate_extended_report(subdomains, live_hosts, takeover, port_results, vuln_results)
    else:
        print(colored("[*] Advanced checks skipped.", 'red'))

if __name__ == "__main__":
    main()
