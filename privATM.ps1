# Debug mode variable
$DEBUG_MODE = $false

Add-Type @"
using System;
using System.Runtime.InteropServices;

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

function Get-AccessTokenHandle {
    [IntPtr]$tokenHandle = [IntPtr]::Zero
    try {
        if ([Win32]::OpenProcessToken([Win32]::GetCurrentProcess(), 0x0008, [ref]$tokenHandle)) {
            return $tokenHandle
        } else {
            return [IntPtr]::Zero
        }
    } catch {
        if ($DEBUG_MODE) { Write-Host "[-] Error retrieving Access Token Handle: $_" }
        return [IntPtr]::Zero
    }
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

function checkSeImpersonatePrivilege {
    if ($DEBUG_MODE) { Write-Host "Checking for SeImpersonatePrivilege..." }

    # Get the current user
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $userName = $user.Name

    Write-Host "[+] Current User: $userName" -ForegroundColor Yellow
    Write-Host ""

    # Easy way
    Write-Host "[*] Enumerating User Privileges:" -ForegroundColor Green
    $whoamiPriv = runSubprocess "whoami" "/priv"
    # $whoamiGroups = runSubprocess "whoami" "/groups"

    # Exclude the first three lines for header
    $lines = $whoamiPriv -split "`n" 
    $filteredOutput = $lines[6..$lines.Length] -join "`n"
    Write-Host $filteredOutput 

    Write-Host "[*] Enumerating User Groups:" -ForegroundColor Cyan
    $userGroups = Get-WmiObject -Query "ASSOCIATORS OF {Win32_UserAccount.Domain='$env:USERDOMAIN',Name='$env:USERNAME'} WHERE AssocClass=Win32_GroupUser" |  Select-Object -ExpandProperty Name 
    $userGroups.foreach({ Write-Host "$_" })
    Write-Host ""

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
        Write-Host "[-] Failed to retrieve Access Token Handle."
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
            Write-Host "[+] Retrieved additional user account details."
        }
    } catch {
        if ($DEBUG_MODE) { Write-Host "[-] Error retrieving user account details: $_" }
    }

    # Print interesting user details
    Write-Host "[+] User Details:"
    foreach ($key in $userDetails.Keys | Sort-Object -Unique) {
        Write-Host "$key`: $($userDetails[$key])"
    }
    Write-Host ""

    # Try to retrieve user privileges
    try {
        $privileges = New-Object System.Security.Principal.WindowsPrincipal($user)
        if ($privileges) {
            Write-Host "[+] Got User SIDs (not printing to keep output short)"
        }
    } catch {
        if ($DEBUG_MODE) { Write-Host "[-] Error retrieving user privileges: $_" }
    }

    # Attempt to get the IdentityReference
    $idRef = $null
    try {
        $idRef = $privileges.GetAuthorizationRules()[0].IdentityReference.Value
        if ($idRef) {
            Write-Host "[+] User IdentityReference: $idRef"
        }
    } catch {
        if ($DEBUG_MODE) { Write-Host "[-] No IdentityReference found for the current user." }
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
            Write-Host "[!] :) $userName has SeImpersonatePrivilege." -ForegroundColor Green
        } else {
            Write-Host "[-] :( $userName does NOT have SeImpersonatePrivilege." -ForegroundColor Red
        }
    } catch {
        if ($DEBUG_MODE) { Write-Host "[-] Error checking SeImpersonatePrivilege: $_" }
    }

    return $hasImpersonatePrivilege
}

# Functions for each technique - checks and execution
function checkUserRightsAssignments {
    if ($DEBUG_MODE) { Write-Host "Checking for User Rights Assignments..." }
    checkSeImpersonatePrivilege
}

function tryUserRightsAssignments {
    if ($DEBUG_MODE) { Write-Host "Attempting Privilege Escalation via User Rights Assignments..." }
    # Logic for exploiting User Rights Assignments
}

function checkServiceMisconfigurations {
    if ($DEBUG_MODE) { Write-Host "Checking for Service Misconfigurations..." }
    # Logic for checking service misconfigurations
}

function tryServiceMisconfigurations {
    if ($DEBUG_MODE) { Write-Host "Attempting Privilege Escalation via Service Misconfigurations..." }
    # Logic for exploiting service misconfigurations
}

function checkScheduledTasks {
    if ($DEBUG_MODE) { Write-Host "Checking for Scheduled Tasks..." }
    # Logic for checking scheduled tasks
}

function tryScheduledTasks {
    if ($DEBUG_MODE) { Write-Host "Attempting Privilege Escalation via Scheduled Tasks..." }
    # Logic for exploiting scheduled tasks
}

function checkWMIEventSubscription {
    if ($DEBUG_MODE) { Write-Host "Checking for WMI Event Subscription Abuse..." }
    # Logic for checking WMI event subscription abuse
}

function tryWMIEventSubscription {
    if ($DEBUG_MODE) { Write-Host "Attempting Privilege Escalation via WMI Event Subscription..." }
    # Logic for exploiting WMI event subscription
}

function checkTokenImpersonation {
    if ($DEBUG_MODE) { Write-Host "Checking for Token Impersonation/Manipulation..." }
    # Logic for checking token impersonation
}

function tryTokenImpersonation {
    if ($DEBUG_MODE) { Write-Host "Attempting Privilege Escalation via Token Impersonation..." }
    # Logic for token impersonation exploit
}

function checkRegistryKeyAbuse {
    if ($DEBUG_MODE) { Write-Host "Checking for Registry Key Abuse..." }
    # Logic for checking registry key abuse
}

function tryRegistryKeyAbuse {
    if ($DEBUG_MODE) { Write-Host "Attempting Privilege Escalation via Registry Key Abuse..." }
    # Logic for registry key exploitation
}

function checkSAMHiveAccess {
    if ($DEBUG_MODE) { Write-Host "Checking for SAM Hive Access..." }
    # Logic for checking CVE-2021-36934
}

function trySAMHiveAccess {
    if ($DEBUG_MODE) { Write-Host "Attempting Privilege Escalation via SAM Hive Access..." }
    # Logic for exploiting CVE-2021-36934
}

function checkAutorunAbuse {
    if ($DEBUG_MODE) { Write-Host "Checking for Autorun Program Abuse..." }
    # Logic for checking autorun abuse
}

function tryAutorunAbuse {
    if ($DEBUG_MODE) { Write-Host "Attempting Privilege Escalation via Autorun Program Abuse..." }
    # Logic for exploiting autorun programs
}

function checkGPOAbuse {
    if ($DEBUG_MODE) { Write-Host "Checking for Insecure GPO Permissions..." }
    # Logic for checking GPO abuse
}

function tryGPOAbuse {
    if ($DEBUG_MODE) { Write-Host "Attempting Privilege Escalation via GPO Permissions..." }
    # Logic for exploiting GPO permissions
}

function checkCOMObjectAbuse {
    if ($DEBUG_MODE) { Write-Host "Checking for COM Object Abuse..." }
    # Logic for checking COM object abuse
}

function tryCOMObjectAbuse {
    if ($DEBUG_MODE) { Write-Host "Attempting Privilege Escalation via COM Object Abuse..." }
    # Logic for exploiting COM objects
}

function checkDCOMLateralMovement {
    if ($DEBUG_MODE) { Write-Host "Checking for DCOM Lateral Movement..." }
    # Logic for checking DCOM lateral movement
}

function tryDCOMLateralMovement {
    if ($DEBUG_MODE) { Write-Host "Attempting Privilege Escalation via DCOM Lateral Movement..." }
    # Logic for DCOM lateral movement exploitation
}

function checkEFSSettings {
    if ($DEBUG_MODE) { Write-Host "Checking for Weak EFS Settings..." }
    # Logic for checking EFS settings
}

function tryEFSSettings {
    if ($DEBUG_MODE) { Write-Host "Attempting Privilege Escalation via Weak EFS Settings..." }
    # Logic for exploiting weak EFS
}

# New function for enumerating system basics
function enumerateSystemBasics {
    if ($DEBUG_MODE) { Write-Host "Enumerating system basics..." }
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
    Write-Host "a - Scan & Try, all techniques  s - Scan only, all techniques  e - Enumerate system basics"
    Write-Host "Enter number(s) (e.g., 1,5-7,9) or 'a' for all..."
}

# Input processing
function processInput {
    param (
        [string]$cliInput
    )

    if ($DEBUG_MODE) { Write-Host "Beg. parsedInput var:" $cliInput }

    $scanOnly = $false
    $tryAll = $false
    
    if ($cliInput -eq 'a') {
        return @{ Selections = 1..12; ScanOnly = $scanOnly; TryAll = $tryAll }
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
                if ($DEBUG_MODE) { Write-Host "Invalid range: $item" }
            }
        } elseif ($item -match '^\d+$') {
            # Handle single numbers (1-12)
            $num = [int]$item
            if ($num -ge 1 -and $num -le 12) {
                $parsedInput += $num
            } else {
                if ($DEBUG_MODE) { Write-Host "Invalid selection: $item" }
            }
        } else {
            if ($DEBUG_MODE) { Write-Host "Invalid input: $item" }
        }
    }

    $parsedInput = $parsedInput | Sort-Object -Unique
    if ($DEBUG_MODE) { Write-Host "End. parsedInput var:" $parsedInput }

    return @{ Selections = $parsedInput; ScanOnly = $scanOnly; TryAll = $tryAll }
}

# Main function that runs the selected techniques
function main {
    showMenu
    $choice = Read-Host "Your selection"
    if ($DEBUG_MODE) { Write-Host "Raw Input:" $choice }

    $inputData = processInput $choice
    $selections = $inputData.Selections
    $scanOnly = $inputData.ScanOnly

    if ($DEBUG_MODE) { Write-Host "Processed Selections:" $selections }

    if ($selections.Count -eq 0) {
        Write-Host "No valid selections made. Exiting..."
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
            default { Write-Host "Invalid selection: $selection" }
        }
    }
}

main
