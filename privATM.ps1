Add-Type -AssemblyName System.DirectoryServices

# Debug mode variable
$DEBUG_MODE = $false

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Security.Principal;
using System.Collections;
using System.Text;

public class PrivilegeFetcher
{
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool LookupPrivilegeName(string lpSystemName, ref LUID lpLuid, System.Text.StringBuilder lpName, ref int cchName);

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    const int TokenPrivileges = 3; // TokenPrivileges enum
    const uint SE_PRIVILEGE_ENABLED = 0x00000002;

    public static void FetchPrivileges()
    {
        IntPtr processHandle = GetCurrentProcess();
        IntPtr tokenHandle;

        if (OpenProcessToken(processHandle, 0x0008, out tokenHandle)) // TOKEN_QUERY
        {
            // Get token privileges
            int tokenInfoLength = 0;
            GetTokenInformation(tokenHandle, TokenPrivileges, IntPtr.Zero, 0, out tokenInfoLength);

            IntPtr tokenInfo = Marshal.AllocHGlobal(tokenInfoLength);
            if (GetTokenInformation(tokenHandle, TokenPrivileges, tokenInfo, tokenInfoLength, out tokenInfoLength))
            {
                // First, read the privilege count
                uint privilegeCount = (uint)Marshal.ReadInt32(tokenInfo);

                // Offset to start reading privileges
                IntPtr privilegesPtr = new IntPtr(tokenInfo.ToInt64() + sizeof(uint));

                for (int i = 0; i < privilegeCount; i++)
                {
                    LUID_AND_ATTRIBUTES luidAndAttributes = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(privilegesPtr, typeof(LUID_AND_ATTRIBUTES));
                    LUID luid = luidAndAttributes.Luid;

                    // Lookup privilege name
                    System.Text.StringBuilder privilegeName = new System.Text.StringBuilder(256);
                    int nameLength = privilegeName.Capacity;
                    if (LookupPrivilegeName(null, ref luid, privilegeName, ref nameLength))
                    {
                        string name = privilegeName.ToString();
                        bool isEnabled = (luidAndAttributes.Attributes & SE_PRIVILEGE_ENABLED) == SE_PRIVILEGE_ENABLED;
                        Console.WriteLine("Privilege: {0}, Enabled: {1}", name, isEnabled);
                    }
                    else
                    {
                        Console.WriteLine("Failed to lookup privilege name.");
                    }

                    // Move the pointer to the next privilege
                    privilegesPtr = new IntPtr(privilegesPtr.ToInt64() + Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES)));
                }
            }
            Marshal.FreeHGlobal(tokenInfo);
        }
        else
        {
            Console.WriteLine("Failed to open process token.");
        }
    }
}

public class PrivilegeFetcher2
{
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int LsaOpenPolicy(IntPtr systemName, ref LSA_OBJECT_ATTRIBUTES objAttributes, int desiredAccess, out IntPtr policyHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int LsaEnumerateAccountRights(IntPtr policyHandle, IntPtr accountSid, out IntPtr userRights, out int countOfRights);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int LsaClose(IntPtr policyHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupAccountName(string lpSystemName, string lpAccountName, IntPtr Sid, ref int cbSid, StringBuilder ReferencedDomainName, ref int cchReferencedDomainName, out int peUse);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int LsaNtStatusToWinError(int status);

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [DllImport("netapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int NetLocalGroupEnum(
        string serverName, 
        int level, 
        out IntPtr bufPtr, 
        int prefMaxLen, 
        out int totalEntries, 
        out int totalBytesNeeded, 
        out IntPtr resumeHandle
    );

    [DllImport("netapi32.dll", SetLastError = true)]
    public static extern int NetApiBufferFree(IntPtr buffer);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct LOCALGROUP_INFO_0
    {
        public IntPtr grpi0_name;
    }

    public static List<string> GetGroupPrivileges(string groupName)
    {
        var output = new List<string>();
        IntPtr policyHandle;

        // Set LSA Object Attributes to zero
        LSA_OBJECT_ATTRIBUTES lsaAttributes = new LSA_OBJECT_ATTRIBUTES();
        lsaAttributes.Length = Marshal.SizeOf(lsaAttributes);

        int result = LsaOpenPolicy(IntPtr.Zero, ref lsaAttributes, 0x00000800, out policyHandle);
        if (result != 0)
        {
            output.Add("[-] Failed to open LSA policy. Error Code: " + LsaNtStatusToWinError(result));
            return output;
        }

        IntPtr sid = GetGroupSid(groupName);
        if (sid == IntPtr.Zero)
        {
            output.Add("[-] Failed to retrieve SID for group: " + groupName);
            return output;
        }

        IntPtr userRights;
        int countOfRights;
        result = LsaEnumerateAccountRights(policyHandle, sid, out userRights, out countOfRights);

        if (result != 0)
        {
            output.Add("[-] Failed to enumerate account rights. Error Code: " + LsaNtStatusToWinError(result));
        }
        else if (userRights == IntPtr.Zero || countOfRights == 0)
        {
            output.Add("[-] No privileges found for this group.");
        }
        else
        {
            IntPtr iter = userRights;
            for (int i = 0; i < countOfRights; i++)
            {
                try
                {
                    string privilege = Marshal.PtrToStringUni(Marshal.ReadIntPtr(iter));
                    output.Add("  - Privilege: " + privilege);
                    iter = IntPtr.Add(iter, IntPtr.Size);
                }
                catch (AccessViolationException)
                {
                    output.Add("[-] Failed to read privilege from memory.");
                    break;
                }
            }
        }

        LsaClose(policyHandle);
        return output;
    }

    public static List<string> GetLocalGroups()
    {
        var groups = new List<string>();
        IntPtr bufPtr = IntPtr.Zero;
        IntPtr resumeHandle = IntPtr.Zero;
        int totalEntries;
        int totalBytesNeeded;

        int result = NetLocalGroupEnum(
            null, // local machine
            0,    // information level 0 (group names)
            out bufPtr, 
            -1,   // unlimited buffer size
            out totalEntries, 
            out totalBytesNeeded, 
            out resumeHandle
        );

        if (result == 0 && bufPtr != IntPtr.Zero)
        {
            try
            {
                int structSize = Marshal.SizeOf(typeof(LOCALGROUP_INFO_0));
                for (int i = 0; i < totalEntries; i++)
                {
                    IntPtr current = IntPtr.Add(bufPtr, i * structSize);
                    LOCALGROUP_INFO_0 groupInfo = (LOCALGROUP_INFO_0)Marshal.PtrToStructure(current, typeof(LOCALGROUP_INFO_0));

                    string groupName = Marshal.PtrToStringAuto(groupInfo.grpi0_name);
                    groups.Add(groupName);
                }
            }
            finally
            {
                NetApiBufferFree(bufPtr);
            }
        }
        else
        {
            groups.Add("[-] Failed to retrieve local groups. Error Code: {result}");
        }

        return groups;
    }

    public static IntPtr GetGroupSid(string groupName)
    {
        int sidSize = 0;
        int domainNameSize = 0;
        int peUse;

        // Call with null values to get the required buffer sizes
        LookupAccountName(null, groupName, IntPtr.Zero, ref sidSize, null, ref domainNameSize, out peUse);

        // Allocate buffers
        IntPtr sid = Marshal.AllocHGlobal(sidSize);
        StringBuilder domainName = new StringBuilder(domainNameSize);

        bool success = LookupAccountName(null, groupName, sid, ref sidSize, domainName, ref domainNameSize, out peUse);

        if (!success)
        {
            Marshal.FreeHGlobal(sid);
            return IntPtr.Zero;
        }

        return sid;
    }
}

public class Win32 {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);
    
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();
}
"@
function splitStringToColumns {
    param (
        [string]$inputString
    )

    # Initialize an array to hold the columns as strings
    $columns = @()

    # Split the input by newline to handle multiple lines
    $inputLines = $inputString -split "`n"

    # Process each line in the input
    foreach ($line in $inputLines) {
        # Trim the line to remove leading/trailing whitespace
        $line = $line.Trim()

        # Skip empty lines
        if (-not [string]::IsNullOrWhiteSpace($line)) {
            # Split the line into parts based on whitespace (one or more spaces or tabs)
            $parts = $line -split '\s+'

            # Add parts to the corresponding column index
            for ($i = 0; $i -lt $parts.Length; $i++) {
                if ($columns.Count -le $i) {
                    $columns += ""  # Dynamically add new columns
                }
                $columns[$i] += $parts[$i] + "`n"  # Append the part with a newline
            }
        }
    }
    return $columns
}
function runSubprocess {
    param(
        [string]$filename,
        [string]$argList
    )
    $processInfo = New-Object System.Diagnostics.ProcessStartInfo
    $processInfo.FileName =  $filename
    $processInfo.Arguments = $argList
    $processInfo.RedirectStandardOutput = $true
    $processInfo.UseShellExecute = $false
    $processInfo.CreateNoWindow = $true

    # Create the process
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $processInfo

    # Start the process
    $process.Start() | Out-Null

    # Read the output
    $output = $process.StandardOutput.ReadToEnd()
    
    # Wait for the process to exit
    $process.WaitForExit()

    # Output the result
    return $output
}
function Get-LocalAdminGroupName {
    try {
        $adminGroup = (Get-WmiObject -Class Win32_Group -Filter "SID='S-1-5-32-544'").Name
        return $adminGroup
    } catch {
        Write-Output "[-] Failed to get Administrators group name: $_"
        return $null
    }
}

# This is intended to get at least some info when no LDAP is present (non AD machine)
function Get-AllLocalGroupsInfo {
    # Get the local computer entry
    $localComputer = New-Object System.DirectoryServices.DirectoryEntry("WinNT://$($env:COMPUTERNAME),computer")

    $groupDetailsList = @()

    # Iterate through each child of the local computer entry
    foreach ($child in $localComputer.Children) {
        if ($child.SchemaClassName -eq 'Group') {
            $groupEntry = New-Object System.DirectoryServices.DirectoryEntry($child.Path)

            $groupDetails = @{
                Name        = $groupEntry.Name
                Description = $groupEntry.Properties["Description"].Value
                Members     = @()
                # Probably not working
                # Privileges  = @()
            }

            # List group members
            try {
                $members = $groupEntry.Invoke("Members")
                foreach ($member in $members) {
                    $memberEntry = New-Object System.DirectoryServices.DirectoryEntry($member)
                    if ($memberEntry -ne $null) {
                        $groupDetails.Members += $memberEntry.Name
                    }
                }
            } catch {
                Write-Error "Error retrieving members for group '$($groupEntry.Name)': $_"
            }

            # Attempt to get privileges
            
            #try {
                # This will likely need to be adjusted based on your environment
            #    $privileges = $groupEntry.Properties["Privileges"].Value
            #    if ($privileges -ne $null) {
            #        $groupDetails.Privileges = $privileges
            #    } 
            #} catch {
            #    Write-Error "Error retrieving privileges for group '$($groupEntry.Name)': $_"
            #}
            
            $groupDetailsList += $groupDetails
        }
    }

    return $groupDetailsList
}

# Collect local administrators (language independent)
function collect_LAs {
    # Get the local Administrators group name based on SID
    $localAdminGroupName = Get-LocalAdminGroupName

    if ($localAdminGroupName -eq $null) {
        Write-Output "[-] Could not determine the local administrators group name."
        return
    }

    # First attempt using Get-LocalGroupMember
    try {
        $localAdmins = Get-LocalGroupMember -Group $localAdminGroupName | Select-Object -ExpandProperty Name
        $gCollect['SH_Data']['LocalAdmins'] = $localAdmins
        Write-Output "[+] Local Admins collected using Get-LocalGroupMember"
        Write-Output $localAdmins
    } catch {
        Write-Output "[-] Get-LocalGroupMember failed, attempting WMI method: $_"
        
        # Fallback to WMI method
        try {
            $localAdmins = Get-WmiObject -Query "ASSOCIATORS OF {Win32_Group.Domain='$env:COMPUTERNAME', Name='$localAdminGroupName'} WHERE AssocClass=Win32_GroupUser" | Select-Object -ExpandProperty Name
            $gCollect['SH_Data']['LocalAdmins'] = $localAdmins
            Write-Output "[+] Local Admins collected using WMI method"
            Write-Output $localAdmins
        } catch {
            Write-Output "[-] WMI method failed: $_"
        }
    }
}

# Global data object
$gCollect = @{
    UserDetails = @{}
    Privileges = @{}
    Groups = @{}
    OtherData = @{}
}

function sh_check {
    Write-Output "[*] Starting additional SH-focused collection..." 
    Write-Output "Note: This is not intended to be run alone, but relies on data"
    Write-Output "from check 1-12 to make a proper, SH / BH json file."
    Write-Output " "

    # Initialize collections if needed
    if (-not $gCollect['SH_Data']) {
        $gCollect['SH_Data'] = @{
            LocalAdmins       = @{}
            LoggedOnUsers     = @{}
            ActiveSessions    = @{}
            NetworkShares     = @{}
            DomainInfo        = @{}
            GroupMemberships   = @{}
            GroupPolicies      = @{}
            TokenDelegation    = @{}
            TrustRelationships = @{}
            SecurityPolicies   = @{}
            AntiVirusProducts  = @{}
            Firewalls          = @{}
            InstalledServices   = @{}
            SecuritySettings    = @{}
            SystemEvents       = @{}
        }
    }

    # Check Local Admins
    collect_LAs

    # Check Active Sessions
    try {
        $activeSessions = @()

        # Get all logon sessions
        $logonSessions = Get-WmiObject -Class Win32_LogonSession | Where-Object { $_.LogonType -eq 2 }

        foreach ($session in $logonSessions) {
            # Get the associated logged-on user
            $loggedOnUsers = Get-WmiObject -Class Win32_LoggedOnUser | Where-Object { $_.Dependent -like "*LogonId=`"$($session.LogonId)`"" }
            
            foreach ($user in $loggedOnUsers) {
                # Extract the username from Antecedent
                $username = ($user.Antecedent -replace '\\\\.\\root\\cimv2:Win32_Account.Domain="[^"]+",Name="', '') -replace '"$', ''
                
                # Create a custom object for each session/user pair
                $activeSessions += [PSCustomObject]@{
                    UserName    = $username
                    SessionID   = $session.LogonId
                    LogonType   = $session.LogonType
                    StartTime   = $session.StartTime
                }
            }
        }

        $gCollect['SH_Data']['ActiveSessions'] = $activeSessions
        Write-Output "[+] Active sessions collected: $($activeSessions.Count) active sessions found."
    } catch {
        Write-Output "[-] Failed to collect active sessions: $_"
    }

    # Enumerate Network Shares
    try {
        $networkShares = Get-WmiObject -Class Win32_Share | Select-Object Name, Path, Description
        $gCollect['SH_Data']['NetworkShares'] = $networkShares
        Write-Output "[+] Network shares collected"
        Write-Output $networkShares | Format-Table -AutoSize
    } catch {
        Write-Output "[-] Failed to collect network shares: $_"
    }

    # Collect Domain Information (if domain-joined)
    $isDomainJoined = $null
    try {
        $isDomainJoined = (Get-WmiObject Win32_ComputerSystem).PartOfDomain
        $gCollect['SH_Data']['DomainInfo'] = $isDomainJoined
        Write-Output "[+] Domain information collected, machine is domain joined? " $isDomainJoined
    } catch {
        Write-Output "[-] Failed to collect domain information: $_"
    }

    # Enumerate Group Memberships
    try {
        $userGroups = Get-WmiObject -Query "ASSOCIATORS OF {Win32_UserAccount.Domain='$env:USERDOMAIN',Name='$env:USERNAME'} WHERE AssocClass=Win32_GroupUser"
        $gCollect['SH_Data']['GroupMemberships'] = $userGroups | Select-Object Name
        Write-Output "[+] Group memberships collected"
    } catch {
        Write-Output "[-] Failed to collect group memberships: $_"
    }

    # TODO - Try C# group permission enum
    Write-Output "[*] Trying to get Group infos (limited on non-AD machines)"
    $allGroupInfo = Get-AllLocalGroupsInfo
    Write-Output $allGroupInfo 
    Write-Output " "

    # Collect AntiVirus Products
    try {
        $securityPolicies = Get-WmiObject -Namespace "ROOT\SecurityCenter2" -Class "AntiVirusProduct" -ErrorAction Stop
        $gCollect['SH_Data']['AntiVirusProducts'] = $securityPolicies | Select-Object -Property displayName, path, productState
        Write-Output "[+] AntiVirus products collected via WMI"
    } catch {
        Write-Output "[-] Failed to collect AntiVirus products: $_"
    }

    # Collect Firewall Information
    try {
        $firewalls = Get-WmiObject -Namespace "ROOT\SecurityCenter2" -Class "FirewallProduct" -ErrorAction Stop
        if ($firewalls) {
            $gCollect['SH_Data']['Firewalls'] = $firewalls | Select-Object -Property displayName, path, productState
            Write-Output "[+] Firewall products collected"
        } else {
            Write-Output "[-] No firewall products found or no output."
        }
    } catch {
        Write-Output "[-] Failed to collect firewall products: $_"
    }

    # Get Named Pipes
    try {
        $namedPipes = [System.IO.Directory]::GetFiles("\\.\\pipe\\")
        if ($namedPipes) {
            Write-Output "[+] Collected Named Pipes, 10 examples"
            if ($DEBUG_MODE) {
                 Write-Output $namedPipes | Select-Object -First 10
            }
        }
        else {
            Write-Output "[-] Failed to collect Named Pipes"
        }
    } catch { 
        Write-Output "[-] Failed to collect Named Pipes with error"
    }

    # Get Full Powershell History
    try {
        $powershellHistory = type (Get-PSReadLineOption).HistorySavePath
        if ($powershellHistory) {
            Write-Output "[+] Collected Full Powershell History"
        }
        else {
            Write-Output "[-] Failed to collect Full Powershell History"
        }
    } catch { 
        Write-Output "[-] Failed to collect Full Powershell History with error"
    }

    # Check User Rights Assignment (not using Win32_UserRight)
    try {
        $userRights = Get-WmiObject -Namespace "ROOT\CIMv2" -Class "Win32_UserAccount" -ErrorAction Stop | Where-Object { $_.LocalAccount -eq $true }
        $gCollect['SH_Data']['UserRights'] = $userRights 
        Write-Output "[+] User rights assignments collected"
        Write-Output $userRights | Select-Object -Property Name, Lockout
    } catch {
        Write-Output "[-] Failed to collect user rights assignments: $_"
    }

    # Collect Installed Services
    try {
        $services = Get-WmiObject -Class Win32_Service -ErrorAction Stop
        $gCollect['SH_Data']['InstalledServices'] = $services
        Write-Output "[+] Installed services collected, showing first 20"
        Write-Output $services | Select-Object -First 20 | Select-Object -Property Name, State, StartMode | Format-Table -AutoSize
        # We could check for Desktop or Shell and then use proper windows to display long list stuff
        # Write-Output $services | Select-Object -Property Name, State, StartMode | Out-GridView -Title "Installed Services" -PassThru
    } catch {
        Write-Output "[-] Failed to collect installed services: $_"
    }

    # Check Group Policies applied to user
    try {
        if ($isDomainJoined) {
            # For domain-joined machines
            $groupPolicies = Get-WmiObject -Namespace "ROOT\RSOP" -Class "RSOP_PolicySetting" -ErrorAction Stop
            $gCollect['SH_Data']['GroupPolicies'] = $groupPolicies
            Write-Output "[+] Group policies collected for domain-joined machine"
        } else {
            # For standalone machines
            Write-Output "[-] Group policies collection not applicable for standalone machine"
        }
    } catch {
        Write-Output "[-] Failed to collect group policies: $_"
    }

    # Check Token Delegation
    try {
        $token = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $gCollect['SH_Data']['TokenDelegation'] = @{
            UserName = $token.Name
            ImpersonationLevel = $token.ImpersonationLevel
            IsAuthenticated = $token.IsAuthenticated
        }
        Write-Output "[+] Token delegation info collected"
    } catch {
        Write-Output "[-] Failed to collect token delegation info: $_"
    }

    # Enumerate Trust Relationships
    try {
        if ($isDomainJoined) {
            $trustRelationships = Get-WmiObject -Namespace "ROOT\Microsoft\Windows\ActiveDirectory" -Class "TrustRelationship" -ErrorAction Stop
            $gCollect['SH_Data']['TrustRelationships'] = $trustRelationships
            Write-Output "[+] Trust relationships collected for domain-joined machine"
        } else {
            Write-Output "[-] Trust relationships not applicable for standalone machine"
        }
    } catch {
        Write-Output "[-] Failed to collect trust relationships: $_"
    }

    # Collect System Events with a limit of the last 200 entries
    Write-Output "[+] Trying to collect and reference latest 200 Events, may take a minute..."
    try {
        $events = Get-WmiObject -Namespace "ROOT\CIMv2" -Class "Win32_NTLogEvent" -ErrorAction Stop | 
                Sort-Object TimeGenerated -Descending | 
                Select-Object -First 200
        
        $gCollect['SH_Data']['SystemEvents'] = @()

        foreach ($event in $events) {
            # Initialize an empty hashtable to store event details
            $eventDetails = @{
                LogFile      = $event.LogFile
                EventCode    = $event.EventCode
                EventType    = $event.EventType
                SourceName   = $event.SourceName
                Message      = $event.Message
                TimeGenerated = $event.TimeGenerated
                Path         = $null # Placeholder for path
            }

            # Try to get the path from Win32_Service
            $service = Get-WmiObject -Class Win32_Service -Filter "Name='$($event.SourceName)'" -ErrorAction SilentlyContinue
            if ($service) {
                $eventDetails.Path = $service.PathName -replace '"', '' # Clean quotes
            } else {
                # If not found in services, try Win32_Process
                $process = Get-WmiObject -Class Win32_Process -Filter "Name='$($event.SourceName).exe'" -ErrorAction SilentlyContinue
                if ($process) {
                    $eventDetails.Path = $process.ExecutablePath
                }
            }

            # Add event details to the collection
            $gCollect['SH_Data']['SystemEvents'] += $eventDetails
        }
    } catch {
        Write-Output "[-] Failed to collect system events: $_"
    }

    try {
        Write-Output "[+] Last 200 system events collected with paths resolution, example:"
        $firstEvent = $gCollect['SH_Data']['SystemEvents'][0]
        $formattedEvent = [PSCustomObject]@{
            SourceName    = $firstEvent.SourceName
            Message       = $firstEvent.Message[0..100] -join ''
            Path          = $firstEvent.Path[0]
        } 
        Write-Output $formattedEvent | Format-List
    } catch {
        Write-Output "[-] Failed to display system event example"
    }


    Write-Output "[*] Finished SH-focused data collection."
}

function sh_translate {
    # Initialize Transformed object
    $gCollect['Transformed'] = @{
        "nodes" = @()
    }

    # Transform UserDetails to nodes
    if ($gCollect['UserDetails']) {
        $userNode = @{
            "objectid" = $gCollect['UserDetails']['SID'] # Using SID as a unique identifier
            "name" = $gCollect['UserDetails']['FullName']
            "type" = "user"
            "isGuest" = $gCollect['UserDetails']['IsGuest']
        }
        $gCollect['Transformed']['nodes'] += $userNode
    }

    # Transform Groups
    if ($gCollect['Groups']) {
        foreach ($group in $gCollect['Groups']['UserGroups']) {
            $node = @{
                "objectid" = $group.Name # Ensure this is unique
                "name" = $group.Name
                "type" = "group"
            }
            $gCollect['Transformed']['nodes'] += $node
        }
    }

    # Transform Privileges
    if ($gCollect['Privileges']) {
        foreach ($privilege in $gCollect['Privileges']) {
            $node = @{
                "objectid" = "$($privilege.UserName)_$($privilege.Privilege)" # Unique identifier
                "name" = $privilege.Privilege
                "type" = "privilege"
                "user" = $privilege.UserName
            }
            $gCollect['Transformed']['nodes'] += $node
        }
    }

    # Note: Skip edges for now since BloodHound will construct those from nodes.
}
function sh_store {
    # Store the transformed data to disk or send it somewhere
    $storagePath = "C:\Temp\stealth_data.json"
    
    $jsonData = $gCollect['Transformed'] | ConvertTo-Json -Depth 3
    Set-Content -Path $storagePath -Value $jsonData

    Write-Output "[+] Data stored at $storagePath."
    if ($DEBUG_MODE) {
        Write-Output "[+] Global Object Data: " 
        $gCollect | ConvertTo-Json -Depth 3 | Write-Output
    }
}
function run_SH_collection {
    # some further checks / data collection not covered by other checks
    sh_check

    # translation and storage of ALL collected data
    sh_translate
    sh_store
}
function Get-AccessTokenHandle {
    [IntPtr]$tokenHandle = [IntPtr]::Zero
    try {
        if ([Win32]::OpenProcessToken([Win32]::GetCurrentProcess(), 0x0008, [ref]$tokenHandle)) {
            return $tokenHandle
        } else {
            return [IntPtr]::Zero
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] Error retrieving Access Token Handle: $_" }
        return [IntPtr]::Zero
    }
}
function checkSeImpersonatePrivilege {
    if ($DEBUG_MODE) { Write-Output "Checking for SeImpersonatePrivilege..." }

    # Get the current user
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userName = $user.Name

    Write-Output "[+] Current User: $userName" 
    Write-Output ""

    # Easy way
    Write-Output "[*] Enumerating User Privileges:" 
    $whoamiPriv = runSubprocess "whoami" "/priv"
    # $whoamiGroups = runSubprocess "whoami" "/groups"

    # Exclude the first three lines for header
    $lines = $whoamiPriv -split "`n" 
    $filteredOutput = $lines[6..$lines.Length] -join "`n"
    Write-Output $filteredOutput 

    Write-Output "[*] Enumerating User Groups:" 
    $userGroups = Get-WmiObject -Query "ASSOCIATORS OF {Win32_UserAccount.Domain='$env:USERDOMAIN',Name='$env:USERNAME'} WHERE AssocClass=Win32_GroupUser" |  Select-Object -ExpandProperty Name 
    $userGroups.foreach({ Write-Output "$_" })
    Write-Output ""

    # Initialize User Token and Privileges
    $userDetails = @{}
    $userToken = $null
    $privileges = $null
    $hasImpersonatePrivilege = $false

    # Store details from GetCurrent object
    $userDetails['AuthenticationType'] = $user.AuthenticationType
    $userDetails['ImpersonationLevel'] = $user.ImpersonationLevel
    $userDetails['IsAuthenticated'] = $user.IsAuthenticated
    $userDetails['IsGuest'] = $user.IsGuest
    $userDetails['IsSystem'] = $user.IsSystem
    $userDetails['IsAnonymous'] = $user.IsAnonymous
    $userDetails['Token'] = $userToken = $user.Token

    # Retrieve the Access Token Handle
    $tokenHandle = Get-AccessTokenHandle
    if ($tokenHandle -ne [IntPtr]::Zero) {
        $userDetails['TokenHandle'] = $tokenHandle
    } else {
        Write-Output "[-] Failed to retrieve Access Token Handle."
    }
    
    # Use WMI to get additional user details
    try {
        $userAccount = Get-WmiObject -Class Win32_Account -Filter "Name='$($userName.Split('\')[1])'" | Select-Object *
        if ($userAccount) {
            $userDetails['LocalAccount'] = $userAccount.LocalAccount
            $userDetails['Disabled'] = $userAccount.Disabled
            $userDetails['Lockout'] = $userAccount.Lockout
            $userDetails['SID'] = $userAccount.SID
            $userDetails['FullName'] = $userAccount.FullName
            Write-Output "[+] Retrieved additional user account details."
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] Error retrieving user account details: $_" }
    }

    # Print interesting user details
    Write-Output "[+] User Details:"
    foreach ($key in $userDetails.Keys | Sort-Object -Unique) {
        Write-Output "$key`: $($userDetails[$key])"
    }
    Write-Output ""

    # Try to retrieve user privileges
    try {
        $privileges = New-Object System.Security.Principal.WindowsPrincipal($user)
        if ($privileges) {
            Write-Output "[+] Got User SIDs (not printing to keep output short)"
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] Error retrieving user privileges: $_" }
    }

    # Attempt to get the IdentityReference
    $idRef = $null
    try {
        $idRef = $privileges.GetAuthorizationRules()[0].IdentityReference.Value
        if ($idRef) {
            Write-Output "[+] User IdentityReference: $idRef"
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] No IdentityReference found for the current user." }
    }

    # Check for SeImpersonatePrivilege
    try {
        foreach ($claim in $privileges.Claims) {
            if ($claim.Value -eq "Impersonate") {
                $hasImpersonatePrivilege = $true
                break
            }
        }

        if ($hasImpersonatePrivilege) {
            Write-Output "[!] :) $userName has SeImpersonatePrivilege." 
        } else {
            Write-Output "[-] :( $userName does NOT have SeImpersonatePrivilege." 
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] Error checking SeImpersonatePrivilege: $_" }
    }

    # Add data to global object for SH
    $gCollect['Privileges'] += @{  
        "Privilege" = "SeImpersonatePrivilege"  
        "UserName"  = $userName
        "HasPrivilege" = $hasImpersonatePrivilege
        "UserPrivileges" = $filteredOutput  
    }

    $gCollect['Groups'] += @{
        "UserGroups" = $userGroups
    }

    $gCollect['UserDetails'] += @{
        "Name"                = $userName
        "AuthenticationType"  = $userAccount.AuthenticationType
        "ImpersonationLevel"  = $userAccount.ImpersonationLevel
        "IsAuthenticated"     = $userAccount.IsAuthenticated
        "IsGuest"             = $userAccount.IsGuest
        "IsSystem"            = $userAccount.IsSystem
        "IsAnonymous"         = $userAccount.IsAnonymous
        "Token"               = $userAccount.Token
        "TokenHandle"         = $userAccount.TokenHandle
        "LocalAccount"        = $userAccount.LocalAccount
        "Disabled"            = $userAccount.Disabled
        "Lockout"             = $userAccount.Lockout
        "SID"                 = $userAccount.SID
        "FullName"            = $userAccount.FullName
    }

    return $hasImpersonatePrivilege
}

# Functions for each technique - checks and execution
function checkUserRightsAssignments {
    if ($DEBUG_MODE) { Write-Output "Checking for User Rights Assignments..." }
    checkSeImpersonatePrivilege
}

function tryUserRightsAssignments {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via User Rights Assignments..." }
    # Logic for exploiting User Rights Assignments
}
function checkServiceMisconfigurations {
    if ($DEBUG_MODE) { Write-Output "Checking for Service Misconfigurations..." }
    
    $writeableEnvPath = @{
        "Path"         = @()
        "Permissions"  = @()
    }

    Write-Host "[*] Trying to find writable env-path before System32..."
    $env:Path -split ";" | ForEach-Object {
        try {
            # Attempt to create a temporary file in the current path
            echo "test" > "$_\t"

            if ($?) {
                # If the file creation was successful, add to the writable paths
                $writeableEnvPath["Path"] += $_
                Write-Output "[+] $_"
                $writeableEnvPath["Permissions"] += icacls.exe $_ 
                Remove-Item "$_\t" -ErrorAction SilentlyContinue 
            }             
            if ($_.ToLower() -eq "c:\windows\system32") {
                # Exit the loop if we reach the System32 path
                return
            }
        }
        catch { 
            #Write-Output "[!] Error accessing $_" 
        }
    }

}


function tryServiceMisconfigurations {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via Service Misconfigurations..." }
    # Logic for exploiting service misconfigurations
}

function checkScheduledTasks {
    if ($DEBUG_MODE) { Write-Output "Checking for Scheduled Tasks..." }
    # Logic for checking scheduled tasks
}

function tryScheduledTasks {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via Scheduled Tasks..." }
    # Logic for exploiting scheduled tasks
}

function checkWMIEventSubscription {
    if ($DEBUG_MODE) { Write-Output "Checking for WMI Event Subscription Abuse..." }
    # Logic for checking WMI event subscription abuse
}

function tryWMIEventSubscription {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via WMI Event Subscription..." }
    # Logic for exploiting WMI event subscription
}

function checkTokenImpersonation {
    if ($DEBUG_MODE) { Write-Output "Checking for Token Impersonation/Manipulation..." }
    # Logic for checking token impersonation
}

function tryTokenImpersonation {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via Token Impersonation..." }
    # Logic for token impersonation exploit
}

function checkRegistryKeyAbuse {
    if ($DEBUG_MODE) { Write-Output "Checking for Registry Key Abuse..." }
    # Logic for checking registry key abuse
}

function tryRegistryKeyAbuse {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via Registry Key Abuse..." }
    # Logic for registry key exploitation
}

function checkSAMHiveAccess {
    if ($DEBUG_MODE) { Write-Output "Checking for SAM Hive Access..." }
    # Logic for checking CVE-2021-36934
}

function trySAMHiveAccess {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via SAM Hive Access..." }
    # Logic for exploiting CVE-2021-36934
}

function checkAutorunAbuse {
    if ($DEBUG_MODE) { Write-Output "Checking for Autorun Program Abuse..." }
    # Logic for checking autorun abuse
}

function tryAutorunAbuse {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via Autorun Program Abuse..." }
    # Logic for exploiting autorun programs
}

function checkGPOAbuse {
    if ($DEBUG_MODE) { Write-Output "Checking for Insecure GPO Permissions..." }
    # Logic for checking GPO abuse
}

function tryGPOAbuse {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via GPO Permissions..." }
    # Logic for exploiting GPO permissions
}

function checkCOMObjectAbuse {
    if ($DEBUG_MODE) { Write-Output "Checking for COM Object Abuse..." }
    # Logic for checking COM object abuse
}

function tryCOMObjectAbuse {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via COM Object Abuse..." }
    # Logic for exploiting COM objects
}

function checkDCOMLateralMovement {
    if ($DEBUG_MODE) { Write-Output "Checking for DCOM Lateral Movement..." }
    # Logic for checking DCOM lateral movement
}

function tryDCOMLateralMovement {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via DCOM Lateral Movement..." }
    # Logic for DCOM lateral movement exploitation
}

function checkEFSSettings {
    if ($DEBUG_MODE) { Write-Output "Checking for Weak EFS Settings..." }
    # Logic for checking EFS settings
}

function tryEFSSettings {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via Weak EFS Settings..." }
    # Logic for exploiting weak EFS
}

# New function for enumerating system basics
function enumerateSystemBasics {
    if ($DEBUG_MODE) { Write-Output "Enumerating system basics..." }
    # Logic to find root processes, writable paths, and registry access
}

# Skeleton function for enumeration
function runEnumeration {
    enumerateSystemBasics
    # Other enumeration logic can go here
}

# Menu displayfunction 
function showMenu {
    # Manually assign techniques to an indexed array
    $techniques = @{}
    $techniques[1] = "SeImpersonatePrivilege"
    $techniques[2] = "Service Misconfigurations"
    $techniques[3] = "Scheduled Tasks"
    $techniques[4] = "WMI Event Subscription Abuse"
    $techniques[5] = "Token Impersonation/Manipulation"
    $techniques[6] = "Registry Key Abuse"
    $techniques[7] = "CVE-2021-36934 (SAM Hive Access)"
    $techniques[8] = "Autorun Program Abuse"
    $techniques[9] = "Insecure GPO Permissions"
    $techniques[10] = "COM Object Abuse"
    $techniques[11] = "DCOM Lateral Movement"
    $techniques[12] = "Exploiting Weak EFS Settings"
    $techniques[13] = "Run additional checks for SH collection"

    # Prepare an array to hold the formatted output
    $output = @()

    # Fill output array with techniques, including numbers
    for ($i = 1; $i -le $techniques.Count; $i++) {
        $output += "$i. $($techniques[$i])"
    }

    # Calculate number of columns and format output for two columns
    $numRows = [math]::Ceiling($output.Count / 2)
    $formattedOutput = @()

    for ($i = 0; $i -lt $numRows; $i++) {
        $col1 = if ($i -lt $numRows) { $output[$i] } else { "" }
        $col2 = if ($i + $numRows -lt $output.Count) { $output[$i + $numRows] } else { "" }
        $formattedOutput += [PSCustomObject]@{ Technique = $col1; Column2 = $col2 }
    }

    # Print techniques in two columns
    $formattedOutput | Format-Table -AutoSize -Property Technique, @{Label="";Expression={$_.Column2}}

    # Print letter options in a separate line
    Write-Output "a - Scan & Try, all techniques  s - Scan only, all techniques  e - Enumerate system basics"
    Write-Output "Enter number(s) (e.g., 1,5-7,9) or 'a' for all..."
}

# Input processing
function processInput {
    param (
        [string]$cliInput
    )

    if ($DEBUG_MODE) { Write-Output "Beg. parsedInput var:" $cliInput }

    $scanOnly = $false
    $tryAll = $false
    $optionCount = 13

    if ($cliInput -eq 'a') {
        return @{ Selections = 1..$optionCount; ScanOnly = $scanOnly; TryAll = $tryAll }
    } elseif ($cliInput -like 's*') {
        $cliInput = $cliInput.Substring(1)  # Remove 's' prefix for scanning only
        $scanOnly = $true
    } elseif ($cliInput -like 't*') {
        $cliInput = $cliInput.Substring(1)  # Remove 't' prefix for trying
        $tryAll = $true
    }
    
    $inputArray = $cliInput -split ','
    $parsedInput = @()  # Initialize an empty array for parsed input

    foreach ($item in $inputArray) {
        if ($item -match '^(\d+)-(\d+)$') {
            # Handle ranges (e.g., 5-7)
            $range = $item -split '-'
            $start = [int]$range[0]
            $end = [int]$range[1]
            if ($start -le $end -and $start -ge 1 -and $end -le 12) {
                $parsedInput += $start..$end
            } else {
                if ($DEBUG_MODE) { Write-Output "Invalid range: $item" }
            }
        } elseif ($item -match '^\d+$') {
            # Handle single numbers (1-12)
            $num = [int]$item
            if ($num -ge 1 -and $num -le $optionCount) {
                $parsedInput += $num
            } else {
                if ($DEBUG_MODE) { Write-Output "Invalid selection: $item" }
            }
        } else {
            if ($DEBUG_MODE) { Write-Output "Invalid input: $item" }
        }
    }

    $parsedInput = $parsedInput | Sort-Object -Unique
    if ($DEBUG_MODE) { Write-Output "End. parsedInput var:" $parsedInput }

    return @{ Selections = $parsedInput; ScanOnly = $scanOnly; TryAll = $tryAll }
}

# Main function that runs the selected techniques
function main {
    showMenu
    $choice = Read-Host "Your selection"
    if ($DEBUG_MODE) { Write-Output "Raw Input:" $choice }

    $inputData = processInput $choice
    $selections = $inputData.Selections
    $scanOnly = $inputData.ScanOnly

    if ($DEBUG_MODE) { Write-Output "Processed Selections:" $selections }

    if ($selections.Count -eq 0) {
        Write-Output "No valid selections made. Exiting..."
        return
    }

    foreach ($selection in $selections) {
        switch ($selection) {
            1 { 
                $hasImpersonatePrivilege = checkUserRightsAssignments; 
                if ((-not $scanOnly) -and ($hasImpersonatePrivilege)) { tryUserRightsAssignments } 
            }
            2 { checkServiceMisconfigurations; if (-not $scanOnly) { tryServiceMisconfigurations } }
            3 { checkScheduledTasks; if (-not $scanOnly) { tryScheduledTasks } }
            4 { checkWMIEventSubscription; if (-not $scanOnly) { tryWMIEventSubscription } }
            5 { checkTokenImpersonation; if (-not $scanOnly) { tryTokenImpersonation } }
            6 { checkRegistryKeyAbuse; if (-not $scanOnly) { tryRegistryKeyAbuse } }
            7 { checkSAMHiveAccess; if (-not $scanOnly) { trySAMHiveAccess } }
            8 { checkAutorunAbuse; if (-not $scanOnly) { tryAutorunAbuse } }
            9 { checkGPOAbuse; if (-not $scanOnly) { tryGPOAbuse } }
            10 { checkCOMObjectAbuse; if (-not $scanOnly) { tryCOMObjectAbuse } }
            11 { checkDCOMLateralMovement; if (-not $scanOnly) { tryDCOMLateralMovement } }
            12 { checkEFSSettings; if (-not $scanOnly) { tryEFSSettings } }
            13 { run_SH_collection; }
            default { Write-Output "Invalid selection: $selection" }
        }
    }
}

main
