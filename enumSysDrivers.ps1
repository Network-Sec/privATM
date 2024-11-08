# Set up URLs and paths
$downloadUrl = "https://aka.ms/VulnerableDriverBlockList"
$zipPath = "$env:TEMP\VulnerableDriverBlockList.zip"
$extractPath = "C:\Windows\Temp\VulnerableDriverBlockList"

# Download the ZIP file
Write-Output "Downloading the Vulnerable Driver Blocklist ZIP..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath

# Extract the ZIP contents
Write-Output "Extracting ZIP contents to $extractPath..."
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

# Verify if extracted content has an additional directory level
$subDirectory = Get-ChildItem -Path $extractPath | Where-Object { $_.PSIsContainer } | Select-Object -First 1
if ($subDirectory) {
    $extractPath = $subDirectory.FullName  # Adjust path to the inner directory
}

# Check and list files in the adjusted extractPath
Write-Output "Listing extracted files in adjusted path:"
Get-ChildItem -Path $extractPath | ForEach-Object { Write-Output $_.Name }

# Define the path to the XML blocklist file
$xmlAuditPath = Join-Path -Path $extractPath -ChildPath "SiPolicy_Audit.xml"

# Check if the XML file exists before proceeding
if (-Not (Test-Path -Path $xmlAuditPath)) {
    Write-Output "Error: XML file 'SiPolicy_Audit.xml' not found in extracted contents. Exiting script."
    exit
}

# Load XML content from the audit blocklist file
[xml]$auditXml = Get-Content -Path $xmlAuditPath

# Collect blocked driver details from the XML
$blockedDrivers = @()
foreach ($rule in $auditXml.SelectNodes("//FileRule")) {
    if ($rule.FileName -like "*.sys") {
        $blockedDrivers += @{
            FileName = $rule.FileName.ToLower()
            FileHash = $rule.FileHash
            Publisher = $rule.Publisher
        }
    }
}

# Get list of installed kernel-mode drivers (.sys files) on the system
Write-Output "Enumerating installed kernel-mode drivers (.sys files)..."
$installedDrivers = Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -like "*.sys" } | Select-Object DisplayName, PathName, Description, State

# Compare installed kernel-mode drivers with the blocklist
Write-Output "Comparing installed kernel-mode drivers with the blocklist..."
$matches = @()
$notBlockedDrivers = @()

foreach ($installedDriver in $installedDrivers) {
    $isBlocked = $false
    $driverFileName = [System.IO.Path]::GetFileName($installedDriver.PathName).ToLower()

    foreach ($blockedDriver in $blockedDrivers) {
        if ($driverFileName -eq $blockedDriver.FileName) {
            $isBlocked = $true
            $matches += [PSCustomObject]@{
                DriverDisplayName = $installedDriver.DisplayName
                DriverPath = $installedDriver.PathName
                DriverDescription = $installedDriver.Description
                DriverState = $installedDriver.State
                BlockedFileName = $blockedDriver.FileName
                Publisher = $blockedDriver.Publisher
            }
            break
        }
    }

    if (-not $isBlocked) {
        # Collect non-blocked .sys drivers for separate output
        $notBlockedDrivers += $driverFileName
    }
}

# Display matched blocked drivers
if ($matches.Count -gt 0) {
    Write-Output "Found vulnerable kernel-mode drivers installed:"
    $matches | Format-Table -AutoSize
} else {
    Write-Output "No vulnerable kernel-mode drivers found among installed drivers."
}

# Display non-blocked kernel-mode drivers
Write-Output "Non-blocked kernel-mode drivers (.sys files):"
$notBlockedDrivers | Sort-Object | Format-Table -AutoSize

# Cleanup: Remove the downloaded and extracted files
Remove-Item -Path $zipPath -Force
Remove-Item -Path $extractPath -Recurse -Force
