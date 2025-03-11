import os
import re
import subprocess
import argparse

# List of log files to scan (Modify this list as needed)
log_files = [
    "/var/log/apache2/access.log",
    "/var/log/apache2/7019.org-access.log",
    "/var/log/apache2/computersciencewiki.org-access.log",
    "/var/log/apache2/games.mackenty.org-access.log",
    "/var/log/apache2/mackenty.org-access.log",
    "/var/log/apache2/new.computersciencewiki.org-access.log",
    "/var/log/apache2/faq.computersciencewiki.org-access.log",
    "/var/log/apache2/courses.computersciencewiki.org-access.log",
    "/var/log/apache2/dailynotes.computersciencewiki.org-access.log"
]

# Define regex pattern to match "wp" and extract the IP address
wp_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).*?"GET .*?wp-.*?"', re.IGNORECASE)

# Store unique IPs to avoid duplicate blocking
blocked_ips = set()

def parse_log_file(log_file, dry_run=False):
    """Search a specific Apache log file for 'wp' requests and extract IPs."""
    if not os.path.isfile(log_file):
        print(f"[ERROR] Log file does not exist: {log_file}")
        return

    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                match = wp_pattern.search(line)
                if match:
                    ip_address = match.group(1)
                    if ip_address not in blocked_ips:
                        if dry_run:
                            print(f"[DRY RUN] Would block: {ip_address} (found in {log_file})")
                        else:
                            print(f"[!] Found WP probe in {log_file} from {ip_address}. Blocking...")
                            blocked_ips.add(ip_address)
                            block_ip(ip_address)
    except Exception as e:
        print(f"[ERROR] Could not read {log_file}: {e}")

def block_ip(ip):
    """Block the given IP using UFW."""
    try:
        command = ["sudo", "ufw", "insert", "1", "deny", "from", ip]
        subprocess.run(command, check=True)
        print(f"[+] Successfully blocked {ip}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to block {ip}: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan Apache logs for 'wp' probes and block IPs using UFW.")
    parser.add_argument("--dry-run", action="store_true", help="Simulate the script without blocking IPs")

    args = parser.parse_args()
    
    for log_file in log_files:
        parse_log_file(log_file, dry_run=args.dry_run)
