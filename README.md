# privATM
Yet Another PrivEsc &amp; User Enum Script

We started working on a script, that can be used on real systems, focussing on things that:
- Still work > 2024
- Can be exploited in pure `Powershell` / `C#` code - so your AMSI evaded shell won't suck as hard
- Doesn't take forever to run
- Light-weight script that won't trigger much

CTF scripts like WinPEAS are awesome, but on real systems it can take forever to run - if you can get it to run without triggering 100 alerts.

## WIP - Work In Progress
We just started working on this. Come back in 3 months or later. Sorry.


### TODO list
- Certify
- Potatoes
- Bloodhound compatible data
- Extra Stealth Mode: No `whoami` etc.

(may or may not happen)

## Usage Example
```powershell
$ .\privATM.ps1

Technique
---------                           -------------------------------------------
1. SePrivileges                     9. Insecure GPO Permissions
2. Service Misconfigurations        10. COM Object Abuse
3. Scheduled Tasks                  11. DCOM Lateral Movement
4. WMI Event Subscription Abuse     12. Exploiting Weak EFS Settings
5. Token Impersonation/Manipulation 13. Certify SAN
6. Registry Key Abuse               14. Check for presence of vuln drivers
7. CVE-2021-36934 (SAM Hive Access) 15. Run additional checks for SH collection
8. Autorun Program Abuse


a - Scan & Try, all techniques  s - Scan only, all techniques  e - Enumerate system basics

Enter number(s) (e.g., 1,5-7,9) or 'a' for all...

Your selection: 1

[!] Found Privs for: DESKTOP-0B1KLOS\occide

[+] SeChangeNotifyPrivilege Allows bypassing some security checks, such as traversing directories. Typically low-risk.
[+] SeUndockPrivilege       Allows undocking the machine. Not generally useful for privilege escalation.
[+] SeTimeZonePrivilege     Allows changing the time zone, which is typically considered low-risk for privilege escalation.
[+] SeLockMemoryPrivilege   Allows locking memory, which could potentially be used to interfere with system stability.
[+] SeShutdownPrivilege     Allows shutting down the system, useful for denial-of-service attacks, but not privilege escalation.
[+] SeTimeZonePrivilege     Allows changing the time zone. Not generally useful for privilege escalation.
[+] SeUndockPrivilege       Allows a machine to be undocked. Generally not useful for privilege escalation.


[💀] Testing SeChangeNotifyPrivilege...
[+] You can try bypassing traverse checking to access files in restricted folders, where nested file or folder is accessible to user, e.g using Test-Path
```

```powershell
$ .\privATM.ps1

Technique
---------                           -------------------------------------------
1. SeImpersonatePrivilege           8. Autorun Program Abuse
2. Service Misconfigurations        9. Insecure GPO Permissions
3. Scheduled Tasks                  10. COM Object Abuse
4. WMI Event Subscription Abuse     11. DCOM Lateral Movement
5. Token Impersonation/Manipulation 12. Exploiting Weak EFS Settings
6. Registry Key Abuse               13. Certify SAN
7. CVE-2021-36934 (SAM Hive Access) 14. Run additional checks for SH collection

a - Scan & Try, all techniques  s - Scan only, all techniques  e - Enumerate system basics

Enter number(s) (e.g., 1,5-7,9) or 'a' for all...

Your selection: 2
[*] Trying to find writable env-path before System32...
[+] E:\Program Files (x86)\IncrediBuild
[+] C:\NASM
[+] D:\AI-Tools\Ollama
[+] D:\AI-Tools\ComfyUI_windows_portable\piper-phonemize\lib
[+] .
```

## Bloodhound Data Collection
We started working on data collection for Bloodhound ingestion. Because Sharphound is heavily flagged (including the reflective powershell loader), we're trying to incorporate a **light / stealth** enum for similar data - not sure if we can achieve compatibility in the end, but we'll keep working on it, or provide our own frontend.

We consider `privileges` (also 2nd hand, through a group or machine) as rather **well-known** and usually easy path, that Pentesters should quickly recognize (if they can be enumerated that is). So we may resort towards a rather quick print-out in bright-green colour, if it becomes too complicated to implement.

```powershell
Your selection: 14
[*] Starting additional SH-focused collection...
Note: This is not intended to be run alone, but relies on data
from check 1-13 to make a proper, SH / BH json file.

[+] Local Admins collected using Get-LocalGroupMember
[+] Logged-on users collected
[+] Active Sessions collected
[+] Network shares collected
[+] Domain information collected
[+] Group memberships collected
[+] AntiVirus products collected via WMI
[-] No firewall products found or no output.
[+] User rights assignments collected
[+] Installed services collected
[-] Group policies collection not applicable for standalone machine
[+] Token delegation info collected
[-] Trust relationships not applicable for standalone machine
[+] Trying to collect and reference latest 200 Events, may take a minute...
[+] Last 200 system events collected with paths resolution, example:


SourceName : PowerShell
Message    : Details zur Pipelineausführung für die Befehlszeile:     Write-Host [+] Trying to collect and   
             refere
Path       : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe



[*] Finished SH-focused data collection.
[+] Data stored at C:\Temp\stealth_data.json.
```

## Vuln Drivers
Loading of vulnerable drivers like `Capcom.sys` (not included, put in same folder) when `SeLoadDriverPrivilege` is present as well as generic check for common vulnerable drivers already installed on the system.

We haven't yet fully tested if we can pull off driver loading, purely with Powershell / c# - it's right now one of many TODO items that may or may not work in the end. The exploitation of already installed drivers should however work anyways.

```powershell
[💀] Looking for presence of vulnerable drivers already installed...
[+] PROCEXP152.sys is present at C:\Windows\System32\drivers\PROCEXP152.SYS
Driver for Process Explorer, potential to allow privilege escalation by exploiting weak IOCTL. Medium severity.

Technique
---------                           -------------------------------------------
1. SePrivileges                     9. Insecure GPO Permissions
2. Service Misconfigurations        10. COM Object Abuse
3. Scheduled Tasks                  11. DCOM Lateral Movement
4. WMI Event Subscription Abuse     12. Exploiting Weak EFS Settings
5. Token Impersonation/Manipulation 13. Certify SAN
6. Registry Key Abuse               14. Check for presence of vuln drivers
7. CVE-2021-36934 (SAM Hive Access) 15. Run additional checks for SH collection
8. Autorun Program Abuse


a - Scan & Try, all techniques  s - Scan only, all techniques  e - Enumerate system basics
Enter number(s) (e.g., 1,5-7,9) or 'a' for all...
Your selection:
```
