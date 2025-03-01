import subprocess
import os

# Define report directory
REPORT_DIR = "/home/blackhat/tools/scan_reports"
os.makedirs(REPORT_DIR, exist_ok=True)

def scan_ports(target):
    output_file = os.path.join(REPORT_DIR, "scan_results.txt")  
    print(f"[+] Scanning open ports on {target}...")
    subprocess.run(["nmap", "-sS", "-p-", "-T4", target], stdout=open(output_file, "w"))

def check_vulnerabilities(target):
    output_file = os.path.join(REPORT_DIR, "vuln_results.txt")  
    print(f"[+] Checking for vulnerabilities on {target}...")
    subprocess.run(["nmap", "-sV", "--script", "vuln", target], stdout=open(output_file, "w"))

def scan_web_server(target):
    output_file = os.path.join(REPORT_DIR, "web_scan.txt")
    print(f"[+] Scanning web server vulnerabilities on {target}...")
    subprocess.run(["nikto", "-h", target], stdout=open(output_file, "w"))

def check_weak_ssh(target, username):
    output_file = os.path.join(REPORT_DIR, "ssh_bruteforce.txt") 
    print(f"[+] Checking for weak SSH credentials on {target}...")
    subprocess.run(["hydra", "-l", username, "-P", "/usr/share/wordlists/big.txt", target, "ssh", "-t", "4"], stdout=open(output_file, "w"))

def generate_report():
    report_path = os.path.join(REPORT_DIR, "Security_Report.txt")
    print(f"\n[=] Generating security report in {report_path}\n")
    with open(report_path, "w") as report:
        report.write(" Vulnerability Scan Report \n\n")
        report.write("Open Ports:\n")
        report.write(open(os.path.join(REPORT_DIR, "scan_results.txt")).read())
        report.write("\n Known Vulnerabilities:\n")
        report.write(open(os.path.join(REPORT_DIR, "vuln_results.txt")).read())
        report.write("\n Web Server Security:\n")
        report.write(open(os.path.join(REPORT_DIR, "web_scan.txt")).read())
        report.write("\n SSH Report:\n")
        report.write(open(os.path.join(REPORT_DIR, "ssh_bruteforce.txt")).read())

if __name__=="__main__":
    print("Welcome to justscanIT!Securing you now.\n")
    target = input("Enter target IP or domain: ")
    username = input("Enter SSH username (if checking SSH): ")

    print("\n[1] Scan open ports")
    print("[2] Check for vulnerabilities")
    print("[3] Scan web server security")
    print("[4] Test SSH for weak passwords")
    print("[5] Run full security scan")
    
    choice = input("\nSelect an option: ")

    if choice == "1":
        scan_ports(target)
    elif choice == "2":
        check_vulnerabilities(target)
    elif choice == "3":
        scan_web_server(target)
    elif choice == "4":
        check_weak_ssh(target, username)
    elif choice == "5":
        scan_ports(target)
        check_vulnerabilities(target)
        scan_web_server(target)
        check_weak_ssh(target, username)
        generate_report()
    else:
        print("Invalid option selected.")
