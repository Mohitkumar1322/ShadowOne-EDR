def detect_suspicious(cmdline):
    if "powershell" in cmdline.lower() and "-enc" in cmdline.lower():
        return "Encoded PowerShell Detected"

    return None