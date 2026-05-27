def detect_suspicious(process, parent, cmdline):

    process = process.lower()
    parent = parent.lower()
    cmdline = cmdline.lower()

    # Encoded PowerShell
    if "powershell" in process and "-enc" in cmdline:
        return {
            "alert": "Encoded PowerShell",
            "severity": "high",
            "mitre": "T1059.001"
        }

    # Office spawning cmd
    if "winword.exe" in parent and "cmd.exe" in process:
        return {
            "alert": "Office Spawned CMD",
            "severity": "critical",
            "mitre": "T1204"
        }

    # CMD spawning PowerShell
    if "cmd.exe" in parent and "powershell.exe" in process:
        return {
            "alert": "CMD Spawned PowerShell",
            "severity": "medium",
            "mitre": "T1059"
        }

    return None