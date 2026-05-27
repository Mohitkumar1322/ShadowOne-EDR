import psutil
import requests
import time
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)

BACKEND_URL = "http://127.0.0.1:8000/telemetry"

# Suspicious keywords for detection
SUSPICIOUS_KEYWORDS = [
    "powershell",
    "encodedcommand",
    "cmd.exe",
    "curl",
    "wget",
    "nc.exe",
    "netcat",
    "mimikatz",
    "certutil",
    "bitsadmin",
]

def check_threat(telemetry):
    cmdline = telemetry["cmdline"].lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in cmdline:
            return {
                "alert": True,
                "severity": "HIGH",
                "reason": f"Suspicious keyword detected: {keyword}"
            }

    return {
        "alert": False
    }

print(Fore.GREEN + "[+] EDR Telemetry Agent Started...\n")

while True:
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            parent_pid = proc.ppid()

            try:
                parent_name = psutil.Process(parent_pid).name()
            except:
                parent_name = "Unknown"

            telemetry = {
                "pid": proc.info['pid'],
                "ppid": parent_pid,
                "process_name": proc.info['name'],
                "parent_process": parent_name,
                "cmdline": " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
            }

            # Send telemetry to backend
            try:
                response = requests.post(
                    BACKEND_URL,
                    json=telemetry,
                    timeout=5
                )
            except requests.exceptions.RequestException as e:
                print(Fore.YELLOW + f"[!] Backend connection failed: {e}")

            # Threat Detection
            result = check_threat(telemetry)

            if result["alert"]:
                print(Fore.RED + "\n🚨 THREAT DETECTED 🚨")
                print(Fore.RED + f"Process Name   : {telemetry['process_name']}")
                print(Fore.RED + f"PID            : {telemetry['pid']}")
                print(Fore.RED + f"Parent Process : {telemetry['parent_process']}")
                print(Fore.RED + f"Command Line   : {telemetry['cmdline']}")
                print(Fore.RED + f"Reason         : {result['reason']}")
                print(Fore.RED + "-" * 60)

            else:
                print(Fore.CYAN + f"[+] Safe Process: {telemetry['process_name']}")

        except (psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess) as e:
            print(Fore.YELLOW + f"[!] Skipped process: {e}")

        except Exception as e:
            print(Fore.YELLOW + f"[!] Error: {e}")

    time.sleep(10)