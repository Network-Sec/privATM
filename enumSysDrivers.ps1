# Set up URLs and paths
$downloadUrl = "https://aka.ms/VulnerableDriverBlockList"
$zipPath = "$env:TEMP\VulnerableDriverBlockList.zip"
$extractPath = "$env:TEMP\VulnerableDriverBlockList"

# Download the ZIP file
Write-Output "Downloading the Vulnerable Driver Blocklist ZIP..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath

# Extract the ZIP contents
Write-Output "Extracting ZIP contents to $extractPath..."
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

# List extracted files for debugging
Write-Output "Listing extracted files:"
Get-ChildItem -Path $extractPath | ForEach-Object { Write-Output $_.Name }

# Initialize array to hold all blocked drivers across XML files
$allBlockedDrivers = @()

# Process each XML file in the extracted directory
$xmlFiles = Get-ChildItem -Path $extractPath -Filter "*.xml"
foreach ($xmlFile in $xmlFiles) {
    Write-Output "Processing blocklist from file: $($xmlFile.Name)"
    [xml]$xmlContent = Get-Content -Path $xmlFile.FullName

    # Extract vulnerable .sys driver names from FileRule nodes
    foreach ($rule in $xmlContent.SelectNodes("//FileRule")) {
        if ($rule.FileName -like "*.sys") {
            $allBlockedDrivers += $rule.FileName.ToLower()  # Collect only .sys names in lowercase
        }
    }
}

# Debug output of all unique blocked drivers found in blocklists
$allBlockedDrivers = $allBlockedDrivers | Sort-Object -Unique
Write-Output "Blocked drivers (.sys files) from blocklist files:"
$allBlockedDrivers | ForEach-Object { Write-Output $_ }

# Enumerate installed kernel-mode drivers (.sys files)
Write-Output "Enumerating installed kernel-mode drivers (.sys files)..."
$installedDrivers = Get-WmiObject Win32_SystemDriver | Where-Object { $_.PathName -like "*.sys" } | Select-Object DisplayName, PathName, Description, State

# Compare installed drivers with the blocklist
Write-Output "Comparing installed drivers with the full blocklist..."
$matches = @()
$notBlockedDrivers = @()

foreach ($installedDriver in $installedDrivers) {
    $driverFileName = [System.IO.Path]::GetFileName($installedDriver.PathName).ToLower()
    
    if ($allBlockedDrivers -contains $driverFileName) {
        # Match found, add to matches list with details
        $matches += [PSCustomObject]@{
            DriverDisplayName = $installedDriver.DisplayName
            DriverPath = $installedDriver.PathName
            DriverDescription = $installedDriver.Description
            DriverState = $installedDriver.State
            BlockedFileName = $driverFileName
        }
    } else {
        # No match, add to non-blocked list
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
