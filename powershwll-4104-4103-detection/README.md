# PowerShell Logging Lab

## Goal

Detect suspicious PowerShell activity using Windows Event Logs.

---

# Environment

| Component | Value |
|---|---|
| OS | Windows 11 |
| Logs | Microsoft-Windows-PowerShell/Operational |
| Tool | Event Viewer |

---

# 1. Enable Script Block Logging

```powershell
HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
```

```powershell
EnableScriptBlockLogging = 1
```

![Enable Logging](screenshots/powershell-logging-enabled.png)

---

# 2. Execute Encoded PowerShell

```powershell
powershell -enc SQB1AHgA
```

![Encoded Command](screenshots/powershell-logging-enabled.png)

---

# 3. Analyze Logs

| Event ID | Purpose |
|---|---|
| 4103 | Module logging |
| 4104 | Script block logging |

![4104](screenshots/event-4104-overviev.png)

![4103](screenshots/vent-4103-details.png)

---

# IOC

| Indicator | Description |
|---|---|
| `powershell.exe` | PowerShell execution |
| `-enc` | Encoded command |
| `Invoke-Expression` | Suspicious execution |
| `4103` | Module logging |
| `4104` | Script block logging |

---

# XML Analysis

Reviewed raw XML event data.

![XML](screenshots/xml-analysis.png)

---

# MITRE ATT&CK

| Technique | ID |
|---|---|
| PowerShell | T1059.001 |
| Obfuscated Files | T1027 |
