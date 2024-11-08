# Set up URLs and paths
$downloadUrl = "https://aka.ms/VulnerableDriverBlockList"
$zipPath = "$env:TEMP\VulnerableDriverBlockList.zip"
$extractPath = "$env:TEMP\VulnerableDriverBlockList"

# _DEBUG_ flag to control debugging output
$DEBUG_ = $false  # Set to $false for minimal output

# Download the ZIP file
Write-Output "Downloading the Vulnerable Driver Blocklist ZIP..."
Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath

# List extracted files for debugging (recursive search)
if ($DEBUG) {
    Write-Output "Listing extracted files (including nested directories):"
    Get-ChildItem -Path $extractPath -Recurse | ForEach-Object { Write-Output $_.FullName }
}

# Initialize array to hold all blocked drivers across XML files
$allBlockedDrivers = @()

# Process each XML file in the extracted directory (including nested subdirectories)
$xmlFiles = Get-ChildItem -Path $extractPath -Recurse -Filter "*.xml"
foreach ($xmlFile in $xmlFiles) {
    if ($DEBUG) {
        Write-Output "Processing blocklist from file: $($xmlFile.Name)"
    }

    [xml]$xmlContent = Get-Content -Path $xmlFile.FullName

    # Define namespace manager to handle the XML namespace
    $namespaceManager = New-Object System.Xml.XmlNamespaceManager($xmlContent.NameTable)
    $namespaceManager.AddNamespace("sipolicy", "urn:schemas-microsoft-com:sipolicy")

    if ($DEBUG) {
        # Debug print to inspect the first 100 characters of XML content to check structure
        Write-Output "XML Content Preview: $($xmlContent.OuterXml.Substring(0, 100))"
    }

    # Process Deny elements (for blocked .sys files)
    $denyNodes = $xmlContent.SelectNodes("//sipolicy:SiPolicy/sipolicy:FileRules/sipolicy:Deny", $namespaceManager)
    
    if ($DEBUG) {
        Write-Output  "Found $($denyNodes.Count) Deny nodes."
    }

    foreach ($deny in $denyNodes) {
        if ($deny.FileName -like "*.sys") {
            $allBlockedDrivers += $deny.FileName.ToLower()  # Collect only .sys names in lowercase
        }
    }

    # Process FileAttrib elements (for files with attributes, potentially including .sys)
    $attribNodes = $xmlContent.SelectNodes("//sipolicy:SiPolicy/sipolicy:FileRules/sipolicy:FileAttrib", $namespaceManager)

    
    if ($DEBUG) {
        Write-Output "Found $($attribNodes.Count) FileAttrib nodes."
    }

    foreach ($attrib in $attribNodes) {
        if ($attrib.FileName -like "*.sys") {
            $allBlockedDrivers += $attrib.FileName.ToLower()  # Collect only .sys names in lowercase
        }
    }
}

# Debug output of all unique blocked drivers found in blocklists (if debugging is enabled)
$allBlockedDrivers = $allBlockedDrivers | Sort-Object -Unique

# Print blocked drivers in the desired format
if ($DEBUG) {
    Write-Output "Processing complete. Found blocked drivers:"
    Write-Output "$($allBlockedDrivers -join ' ')"  # Join without newlines
}

Write-Output "Total number of blocked drivers found: $($allBlockedDrivers.Count)"
if ($DEBUG_) {
    Write-Output "Blocked drivers (.sys files) from blocklist files:"
    $allBlockedDrivers | ForEach-Object { Write-Output $_ }
}

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
    Write-Output "Found blocked kernel-mode drivers installed:"
    $matches 
} else {
    Write-Output "No blocked kernel-mode drivers found among installed drivers."
}

# Display non-blocked kernel-mode drivers
Write-Output "Non-blocked kernel-mode drivers (.sys files) found on this system:"
Write-Output "$($notBlockedDrivers -join ' ')" 

# Cleanup: Remove the downloaded and extracted files
Remove-Item -Path $zipPath -Force
Remove-Item -Path $extractPath -Recurse -Force
