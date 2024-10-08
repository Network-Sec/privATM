# privATM
Yet Another PrivEsc &amp; User Enum Script

We started working on a script, that can be used on real systems.

## WIP - Work In Progress
We already made good progress but are still far from what we'd like to deliver in the final version. 

### TODO list
- Certify
- Potatoes
- Bloodhound compatible data
- Extra Stealth Mode: No `whoami` etc.
- Vuln Driver exploit
- etc.

## Usage Example
```
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

[!] Found Privs for: DESKTOP-EX4MPL3\testuser

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

## Env Pathes
Of course, there are more ways to do this, but if you're lucky enough, this is probably the quickest and easiest. 

```
Your selection: 2
[*] Trying to find writable env-path before System32...
[+] E:\Program Files (x86)\IncrediBuild
[+] C:\NASM
[+] D:\AI-Tools\Ollama
[+] D:\AI-Tools\ComfyUI_windows_portable\piper-phonemize\lib
[+] .
```

## Bloodhound Data Collection
We started working on data collection for Bloodhound ingestion - not sure if we can achieve compatibility in the end, but we'll keep working on it.

```
Your selection: 15
[💀] Starting additional SH-focused collection...
Note: This is not intended to be run alone, but relies on data
from the other checks.

[+] Local Admins collected using Get-LocalGroupMember
DESKTOP-EX4MPL3\Administrator
DESKTOP-EX4MPL3\testuser

[+] Active sessions collected: 4 active sessions found.
[+] Network shares collected

Name   Path       Description
----   ----       -----------
ADMIN$ C:\Windows Remoteverwaltung
C$     C:\        Standardfreigabe
D$     D:\        Standardfreigabe
E$     E:\        Standardfreigabe
G$     G:\        Standardfreigabe
IPC$              Remote-IPC

[+] Domain information collected, machine is domain joined?
False
[+] Group memberships collected
[💀] Trying to get Group infos (limited on non-AD machines), may take a minute...
[+] Found Group infos, printing first 5:

Name        Value
----        -----
Description Administratoren haben uneingeschränkten Vollzugriff auf den Computer bzw. die Domäne.
Name        {Administratoren}
Members     {Administrator, testuser}
Description Benutzer können keine zufälligen oder beabsichtigten Änderungen am System durchführen und dürfen die meisten herkömmlichen Anwendungen ausfü...
Name        {Benutzer}
Members     {$null, $null, mimitest}
Description Mitglieder dieser Gruppe können Distributed-COM-Objekte auf diesem Computer starten, aktivieren und verwenden.
Name        {Distributed COM-Benutzer}
Members     {}
Description Mitglieder dieser Gruppe dürfen Ereignisprotokolle des lokalen Computers lesen
Name        {Ereignisprotokollleser}
Members     {}
Description Mitglieder dieser Gruppe können systemweite Einstellungen ändern.
Name        {Gerätebesitzer}
Members     {}

[+] AntiVirus products collected via WMI
[-] No firewall products found or no output.
[+] Collected Named Pipes
[+] Collected Full Powershell History
[+] User rights assignments collected



Name               FullName Domain          SID
----               -------- ------          ---
Administrator               DESKTOP-EX4MPL3 S-1-5-21-1861850896-3805680650-3336260861-500
DefaultAccount              DESKTOP-EX4MPL3 S-1-5-21-1861850896-3805680650-3336260861-503
Gast                        DESKTOP-EX4MPL3 S-1-5-21-1861850896-3805680650-3336260861-501
mimitest           mimitest DESKTOP-EX4MPL3 S-1-5-21-1861850896-3805680650-3336260861-1002
testuser                      DESKTOP-EX4MPL3 S-1-5-21-1861850896-3805680650-3336260861-1001
WDAGUtilityAccount          DESKTOP-EX4MPL3 S-1-5-21-1861850896-3805680650-3336260861-504


[+] Installed services collected, showing first 20

Name                     State   StartMode
----                     -----   ---------
AJRouter                 Stopped Manual
ALG                      Stopped Manual
AppIDSvc                 Stopped Manual
Appinfo                  Running Manual
AppMgmt                  Stopped Manual
AppReadiness             Stopped Manual
AppVClient               Stopped Disabled
AppXSvc                  Running Manual

[-] Group policies collection not applicable for standalone machine
[+] Token delegation info collected
[-] Trust relationships not applicable for standalone machine
[+] Trying to collect and reference latest 200 Events, may take a minute...
[+] Last 200 system events collected with paths resolution, example:

SourceName : PowerShell
Message    : Details zur Pipelineausführung für die Befehlszeile:     Write-Output [+] Trying to collect and refe
Path       : C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe

[-] No Wi-Fi profiles found
[💀] Finished SH-focused data collection.
[+] Data stored at C:\Temp\stealth_data.json.
```

## Vuln Drivers
Detection and eventually loading & exploitation of vulnerable drivers like `Capcom.sys` (not included, put in same folder) when `SeLoadDriverPrivilege` is present as well as generic check for common vulnerable drivers already installed on the system.

```
Your selection: 14

[💀] Looking for presence of vulnerable drivers already installed...
[+] PROCEXP152.sys is present at C:\Windows\System32\drivers\PROCEXP152.SYS
Driver for Process Explorer, potential to allow privilege escalation by exploiting weak IOCTL. Medium severity.
```

## Cred Search
We carefully implemented a `credential discovery` logic, trying to balance speed, coverage and false-positives / true-positives rate. 

Credential search is always a balancing act, we're happy with this config as it is, but it will **certainly** not match every scenario, machine and probably not CTFs. 
```
Processing Files
Processing file 254 of 2946 - C:\Users\testuser\bookmarks-2024-04-21.json - 1 MB
[oooooooooooo                                                                                    ]
                                                                                 
[💀] Looking for easy creds...

Momentan gespeicherte Anmeldeinformationen:

    Ziel: MicrosoftAccount:target=SSO_POP_User:user=example@gmx.com
    Typ: Allgemeine
    Benutzer: example@gmx.com
    Nur für diese Sitzung gespeichert

    Ziel: MicrosoftAccount:target=SSO_POP_Device
    Typ: Allgemeine
    Benutzer: asfrtgbfnosgd2iq
    Nur für diese Sitzung gespeichert

    Ziel: LegacyGeneric:target=sftp://root@81.110.150.18
    Typ: Allgemeine
    Benutzer: root

[+] Browser Creds match, file is accessible: C:\Users\testuser\AppData\Local\Google\Chrome\User Data\Default\Login Data
[+] Browser Creds match, file is accessible: C:\Users\testuser\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data
[+] Browser Creds match, file is accessible: C:\Users\testuser\AppData\Local\Microsoft\Edge\User Data\Default\Login Data
[+] Browser Creds match, file is accessible: C:\Users\testuser\AppData\Roaming\Mozilla\Firefox\Profiles\va21nfat.default-release\logins.json
[+] Browser Creds match, file is accessible: C:\Users\testuser\AppData\Roaming\Mozilla\Firefox\Profiles\4zzo5h1t.default-release\logins.json

[💀] Scanning for creds in files
[*] Starting directory & file discovery recursively, this will take a while...
[*] Total files to search: 2946
------------------------------------------------------------------------------------------------------------------------------------------------------------
[+] [Email Address] File: C:\Users\testuser\.autogenstudio\database.sqlite
Line 1: U3AE5663ec93-f6db-4f7e-8f37-68bd05fe155dguestuser@gmail.com2024-06-12T01:00:05.244355ll

Additional matches in this file: 34

------------------------------------------------------------------------------------------------------------------------------------------------------------
[+] [Private Key] File: C:\Users\testuser\.ollama\id_ed25519
Line 1: -----BEGIN OPENSSH PRIVATE KEY-----

------------------------------------------------------------------------------------------------------------------------------------------------------------
[+] [Email Address] File: C:\Users\testuser\.recon-ng\modules.yml
Line 1: - author: example (testuser@gmail.com)

Additional matches in this file: 126

------------------------------------------------------------------------------------------------------------------------------------------------------------
[+] [password] File: C:\Users\testuser\embedding\ollama_embedder.py
Line 1: edis.Redis(host='192.168.178.16', port=3379, db=0, password='my_redis_Pa$$wOrD')

Additional matches in this file: 1

------------------------------------------------------------------------------------------------------------------------------------------------------------
[+] [Private Key] File: C:\Users\testuser\.ssh\id_rsa_old
Line 1: -----BEGIN RSA PRIVATE KEY-----

------------------------------------------------------------------------------------------------------------------------------------------------------------
[+] [username and password in URL] File: C:\Users\testuser\LinkShortener_WebApp\.env
Line 1: MONGODB_URI=mongodb://testuser:IhAn3325JAnql_AIhn335a@127.0.0.1:27017/privurl

------------------------------------------------------------------------------------------------------------------------------------------------------------ 
[+] Total Matches: 584

[?] If you're in a desktop session, should we display all findings in a new Desktop-Window (y/n)?
```
When the search is finished, we offer the user to display results in a `Grid-View`, a Windows Desktop list-window that can be sorted and filtered.
