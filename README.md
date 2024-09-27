# privATM
Yet Another PrivEsc &amp; User Enum Script

We started working on a script, that can used on real systems, focussing on things that:
- Still work > 2024
- Can be exploited in pure `Powershell` / `C#` code - so your AMSI evaded shell won't suck as hard
- Doesn't take forever

CTF scripts like WinPEAS are awesome, but on real systems it can take forever to run - if you can get it to run without triggering 100 alerts.

## WIP - Work In Progress
We just started working on this. Come back in 3 months or later. Sorry.

Yes, things like Certify and Potatoes are on the TODO list.

## Usage Example
```powershell
$ .\privATM.ps1

Technique
---------                           -----------------------------------
1. SeImpersonatePrivilege           7. CVE-2021-36934 (SAM Hive Access)
2. Service Misconfigurations        8. Autorun Program Abuse
3. Scheduled Tasks                  9. Insecure GPO Permissions
4. WMI Event Subscription Abuse     10. COM Object Abuse
5. Token Impersonation/Manipulation 11. DCOM Lateral Movement
6. Registry Key Abuse               12. Exploiting Weak EFS Settings

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
