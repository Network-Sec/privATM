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
1. SeImpersonatePrivilege           8. Autorun Program Abuse
2. Service Misconfigurations        9. Insecure GPO Permissions
3. Scheduled Tasks                  10. COM Object Abuse
4. WMI Event Subscription Abuse     11. DCOM Lateral Movement
5. Token Impersonation/Manipulation 12. Exploiting Weak EFS Settings
6. Registry Key Abuse               13. Run additional checks for SH collection
7. CVE-2021-36934 (SAM Hive Access)

a - Scan & Try, all techniques  s - Scan only, all techniques  e - Enumerate system basics

Enter number(s) (e.g., 1,5-7,9) or 'a' for all...

Your selection: 1
Checking for User Rights Assignments...
Checking for SeImpersonatePrivilege...
[+] Current User: DESKTOP-EXAMPLE\username

[*] Enumerating User Privileges:
SeLockMemoryPrivilege         Sperren von Seiten im Speicher                  Deaktiviert
SeShutdownPrivilege           Herunterfahren des Systems                      Deaktiviert
SeChangeNotifyPrivilege       Auslassen der durchsuchenden Überprüfung        Aktiviert
SeUndockPrivilege             Entfernen des Computers von der Docking-Station Deaktiviert
SeIncreaseWorkingSetPrivilege Arbeitssatz eines Prozesses vergrößern          Deaktiviert
SeTimeZonePrivilege           Ändern der Zeitzone                             Deaktiviert

[*] Enumerating User Groups:
Administratoren
Leistungsprotokollbenutzer
Remotedesktopbenutzer
docker-users
Message Capture Users

[+] Retrieved additional user account details.
[+] User Details:
AuthenticationType: NTLM
Disabled: False
FullName:
ImpersonationLevel: None
IsAnonymous: False
IsAuthenticated: True
IsGuest: False
IsSystem: False
LocalAccount: True
Lockout: False
SID: S-1-5-21-18634534596-123456788-33345345861-1001
Token: 7488
TokenHandle: 7528

[+] Got User SIDs (not printing to keep output short)
[-] No IdentityReference found for the current user.
[-] :( DESKTOP-EXAMPLE\username does NOT have SeImpersonatePrivilege.
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
6. Registry Key Abuse               13. Run additional checks for SH collection
7. CVE-2021-36934 (SAM Hive Access)

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

We consider `privileges` (also 2nd hand, through a group or machine) as rather **well-known** and usually easy path, that Pentesters should quickly recognize. So we may resort towards a rather quick print-out in bright-green colour, if it becomes too complicated to implement.

```powershell
Your selection: 13
[*] Starting additional SH-focused collection...
Note: This is not intended to be run alone, but relies on data
from check 1-12 to make a proper, SH / BH json file.
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
