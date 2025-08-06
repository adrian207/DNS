 # DNS Site Mismatch Audit - Find IP addresses not in the same site as requesting DC
# This script identifies DNS records where the IP address belongs to a different site than the DC

#region Core Functions

function Get-ADSiteSubnets {
    <#
    .SYNOPSIS
    Gets all AD sites and their associated subnets for IP-to-site mapping
    #>
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        
        $Sites = Get-ADReplicationSite -Filter * -Properties Location, Description
        $Subnets = Get-ADReplicationSubnet -Filter * -Properties Site, Location, Description
        
        $SiteSubnetMap = @{}
        
        foreach ($Subnet in $Subnets) {
            $SiteSubnetMap[$Subnet.Name] = @{
                SiteName = $Subnet.Site.Split(',')[0].Replace('CN=', '')
                SubnetName = $Subnet.Name
                Location = $Subnet.Location
                Description = $Subnet.Description
            }
        }
        
        $SiteInfo = @{}
        foreach ($Site in $Sites) {
            $SiteSubnets = $Subnets | Where-Object { $_.Site -like "*$($Site.Name)*" }
            $SiteInfo[$Site.Name] = @{
                SiteName = $Site.Name
                Location = $Site.Location
                Description = $Site.Description
                Subnets = $SiteSubnets.Name
            }
        }
        
        return @{
            SiteSubnetMap = $SiteSubnetMap
            SiteInfo = $SiteInfo
        }
    }
    catch {
        Write-Error "Failed to get AD site information: $($_.Exception.Message)"
        return $null
    }
}

function Get-IPAddressSite {
    param(
        [string]$IPAddress,
        [hashtable]$SiteSubnetMap
    )
    
    <#
    .SYNOPSIS
    Determines which AD site an IP address belongs to based on subnet configuration
    #>
    
    try {
        $IP = [System.Net.IPAddress]::Parse($IPAddress)
        
        foreach ($SubnetString in $SiteSubnetMap.Keys) {
            try {
                # Parse subnet (e.g., "192.168.1.0/24")
                $SubnetParts = $SubnetString.Split('/')
                $NetworkIP = [System.Net.IPAddress]::Parse($SubnetParts[0])
                $PrefixLength = [int]$SubnetParts[1]
                
                # Convert to binary for comparison
                $IPBytes = $IP.GetAddressBytes()
                $NetworkBytes = $NetworkIP.GetAddressBytes()
                
                # Calculate subnet mask
                $MaskBits = 0xFFFFFFFF -shl (32 - $PrefixLength)
                $MaskBytes = [System.BitConverter]::GetBytes($MaskBits)
                if ([System.BitConverter]::IsLittleEndian) {
                    [Array]::Reverse($MaskBytes)
                }
                
                # Apply mask to both IP and network
                $MaskedIP = @()
                $MaskedNetwork = @()
                for ($i = 0; $i -lt 4; $i++) {
                    $MaskedIP += $IPBytes[$i] -band $MaskBytes[$i]
                    $MaskedNetwork += $NetworkBytes[$i] -band $MaskBytes[$i]
                }
                
                # Check if IP is in this subnet
                $Match = $true
                for ($i = 0; $i -lt 4; $i++) {
                    if ($MaskedIP[$i] -ne $MaskedNetwork[$i]) {
                        $Match = $false
                        break
                    }
                }
                
                if ($Match) {
                    return $SiteSubnetMap[$SubnetString]
                }
            }
            catch {
                # Skip invalid subnet formats
                continue
            }
        }
        
        return @{
            SiteName = "Unknown"
            SubnetName = "No matching subnet"
            Location = ""
            Description = ""
        }
    }
    catch {
        return @{
            SiteName = "Invalid IP"
            SubnetName = "Parse error"
            Location = ""
            Description = ""
        }
    }
}

function Get-DomainControllerSites {
    <#
    .SYNOPSIS
    Gets all domain controllers and their site assignments
    #>
    
    try {
        $DCs = Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, Site, OperatingSystem, Hostname
        
        Write-Host "Found $($DCs.Count) domain controllers:" -ForegroundColor Green
        foreach ($DC in $DCs) {
            Write-Host "  $($DC.Name) - $($DC.IPv4Address) - Site: $($DC.Site)" -ForegroundColor Yellow
        }
        
        return $DCs
    }
    catch {
        Write-Error "Failed to get domain controllers: $($_.Exception.Message)"
        return $null
    }
}

function Get-DNSRecordsFromDC {
    param(
        [string]$DCName,
        [string]$DCSite,
        [string]$DCIPAddress,
        [hashtable]$SiteSubnetMap,
        [string[]]$ZoneFilter = @(),
        [switch]$IncludeDynamicRecords
    )
    
    <#
    .SYNOPSIS
    Gets DNS records from a specific DC and identifies site mismatches
    #>
    
    Write-Host "`nScanning DNS records on DC: $DCName (Site: $DCSite)" -ForegroundColor Cyan
    
    $SiteMismatchRecords = @()
    
    try {
        # Test connectivity
        if (!(Test-Connection -ComputerName $DCName -Count 1 -Quiet)) {
            Write-Warning "Cannot reach DC: $DCName"
            return $SiteMismatchRecords
        }
        
        # Get DNS zones
        $Zones = Get-DnsServerZone -ComputerName $DCName -ErrorAction Stop
        
        if ($ZoneFilter.Count -gt 0) {
            $Zones = $Zones | Where-Object { $_.ZoneName -in $ZoneFilter }
        }
        
        # Focus on forward lookup zones
        $ForwardZones = $Zones | Where-Object { $_.IsReverseLookupZone -eq $false -and $_.ZoneType -ne "Forwarder" }
        
        Write-Host "Processing $($ForwardZones.Count) forward lookup zones" -ForegroundColor Yellow
        
        foreach ($Zone in $ForwardZones) {
            Write-Host "  Scanning zone: $($Zone.ZoneName)" -ForegroundColor Gray
            
            try {
                # Get A and AAAA records (IP addresses)
                $ResourceRecords = Get-DnsServerResourceRecord -ComputerName $DCName -ZoneName $Zone.ZoneName -ErrorAction Stop
                $IPRecords = $ResourceRecords | Where-Object { $_.RecordType -in @("A", "AAAA") }
                
                # Filter static vs dynamic if needed
                if (!$IncludeDynamicRecords) {
                    $IPRecords = $IPRecords | Where-Object { $_.TimeToLive.TotalSeconds -eq 0 }
                }
                
                foreach ($Record in $IPRecords) {
                    $IPAddress = if ($Record.RecordType -eq "A") { 
                        $Record.RecordData.IPv4Address.ToString() 
                    } else { 
                        $Record.RecordData.IPv6Address.ToString() 
                    }
                    
                    # Skip IPv6 for now (focus on IPv4)
                    if ($Record.RecordType -eq "AAAA") { continue }
                    
                    # Skip localhost and private ranges if they're not in subnets
                    if ($IPAddress.StartsWith("127.") -or $IPAddress.StartsWith("169.254.")) { continue }
                    
                    # Determine which site this IP belongs to
                    $IPSite = Get-IPAddressSite -IPAddress $IPAddress -SiteSubnetMap $SiteSubnetMap
                    
                    # Check for site mismatch
                    if ($IPSite.SiteName -ne $DCSite -and $IPSite.SiteName -ne "Unknown") {
                        $FQDN = if ($Record.HostName -eq "@") { $Zone.ZoneName } else { "$($Record.HostName).$($Zone.ZoneName)" }
                        
                        $MismatchRecord = [PSCustomObject]@{
                            DCName = $DCName
                            DCSite = $DCSite
                            DCIPAddress = $DCIPAddress
                            ZoneName = $Zone.ZoneName
                            RecordName = $Record.HostName
                            FQDN = $FQDN
                            RecordType = $Record.RecordType
                            IPAddress = $IPAddress
                            IPSite = $IPSite.SiteName
                            IPSubnet = $IPSite.SubnetName
                            IPSiteLocation = $IPSite.Location
                            SiteMismatch = $true
                            TTL = $Record.TimeToLive.TotalSeconds
                            IsStatic = $Record.TimeToLive.TotalSeconds -eq 0
                            MismatchType = if ($IPSite.SiteName -eq "Unknown") { "IP not in any configured subnet" } else { "IP in different site" }
                            AuditDate = Get-Date
                        }
                        
                        $SiteMismatchRecords += $MismatchRecord
                    }
                }
            }
            catch {
                Write-Warning "Error processing zone $($Zone.ZoneName): $($_.Exception.Message)"
            }
        }
        
        Write-Host "  Found $($SiteMismatchRecords.Count) site mismatches on this DC" -ForegroundColor $(if($SiteMismatchRecords.Count -gt 0){"Red"}else{"Green"})
    }
    catch {
        Write-Error "Error processing DC $DCName : $($_.Exception.Message)"
    }
    
    return $SiteMismatchRecords
}

function Start-DNSSiteMismatchAudit {
    param(
        [string[]]$ZoneFilter = @(),
        [switch]$IncludeDynamicRecords,
        [switch]$IncludeUnknownSubnets,
        [string]$ExportPath = "C:\DNSAudit"
    )
    
    <#
    .SYNOPSIS
    Main function to audit all DCs for DNS site mismatches
    #>
    
    Write-Host "=== DNS SITE MISMATCH AUDIT ===" -ForegroundColor Cyan
    Write-Host "Start Time: $(Get-Date)" -ForegroundColor Yellow
    
    # Create export directory
    if (!(Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
        Write-Host "Created export directory: $ExportPath" -ForegroundColor Green
    }
    
    # Get AD site and subnet information
    Write-Host "`nGetting Active Directory site and subnet information..." -ForegroundColor Cyan
    $SiteData = Get-ADSiteSubnets
    if (!$SiteData) {
        Write-Error "Cannot retrieve AD site information. Exiting."
        return
    }
    
    Write-Host "Found $($SiteData.SiteInfo.Count) sites with $($SiteData.SiteSubnetMap.Count) subnets" -ForegroundColor Green
    
    # Get all domain controllers
    Write-Host "`nGetting domain controllers..." -ForegroundColor Cyan
    $DCs = Get-DomainControllerSites
    if (!$DCs) {
        Write-Error "Cannot retrieve domain controllers. Exiting."
        return
    }
    
    # Process each DC
    $AllMismatchRecords = @()
    $DCProcessingResults = @()
    
    foreach ($DC in $DCs) {
        $DCResult = [PSCustomObject]@{
            DCName = $DC.Name
            DCSite = $DC.Site
            DCIPAddress = $DC.IPv4Address
            ProcessingStatus = "Processing..."
            RecordsScanned = 0
            MismatchesFound = 0
            ProcessingTime = $null
        }
        
        $StartTime = Get-Date
        
        try {
            $Mismatches = Get-DNSRecordsFromDC -DCName $DC.Name -DCSite $DC.Site -DCIPAddress $DC.IPv4Address -SiteSubnetMap $SiteData.SiteSubnetMap -ZoneFilter $ZoneFilter -IncludeDynamicRecords:$IncludeDynamicRecords
            
            $AllMismatchRecords += $Mismatches
            
            $DCResult.ProcessingStatus = "Completed"
            $DCResult.MismatchesFound = $Mismatches.Count
            $DCResult.ProcessingTime = ((Get-Date) - $StartTime).TotalSeconds
        }
        catch {
            $DCResult.ProcessingStatus = "Failed: $($_.Exception.Message)"
            $DCResult.ProcessingTime = ((Get-Date) - $StartTime).TotalSeconds
        }
        
        $DCProcessingResults += $DCResult
    }
    
    # Filter results if requested
    if (!$IncludeUnknownSubnets) {
        $AllMismatchRecords = $AllMismatchRecords | Where-Object { $_.IPSite -ne "Unknown" }
    }
    
    # Generate reports
    $TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Main mismatch report
    $MismatchReportPath = "$ExportPath\DNS_Site_Mismatches_$TimeStamp.csv"
    $AllMismatchRecords | Export-Csv -Path $MismatchReportPath -NoTypeInformation
    
    # DC processing summary
    $DCReportPath = "$ExportPath\DC_Processing_Summary_$TimeStamp.csv"
    $DCProcessingResults | Export-Csv -Path $DCReportPath -NoTypeInformation
    
    # Site summary report
    $SiteSummary = $AllMismatchRecords | Group-Object IPSite | Select-Object @{Name="Site";Expression={$_.Name}}, Count | Sort-Object Count -Descending
    $SiteSummaryPath = "$ExportPath\Site_Mismatch_Summary_$TimeStamp.csv"
    $SiteSummary | Export-Csv -Path $SiteSummaryPath -NoTypeInformation
    
    # Display results
    Write-Host "`n=== AUDIT COMPLETE ===" -ForegroundColor Green
    Write-Host "End Time: $(Get-Date)" -ForegroundColor Yellow
    Write-Host "Total Site Mismatches Found: $($AllMismatchRecords.Count)" -ForegroundColor $(if($AllMismatchRecords.Count -gt 0){"Red"}else{"Green"})
    Write-Host "Domain Controllers Processed: $($DCProcessingResults.Count)" -ForegroundColor Green
    
    if ($AllMismatchRecords.Count -gt 0) {
        Write-Host "`n=== TOP SITES WITH MISMATCHES ===" -ForegroundColor Yellow
        $SiteSummary | Select-Object -First 10 | Format-Table -AutoSize
        
        Write-Host "`n=== SAMPLE MISMATCHES ===" -ForegroundColor Yellow
        $AllMismatchRecords | Select-Object -First 5 FQDN, IPAddress, IPSite, DCSite, MismatchType | Format-Table -AutoSize
    }
    
    Write-Host "`nReports saved to:" -ForegroundColor Cyan
    Write-Host "  Site Mismatches: $MismatchReportPath" -ForegroundColor White
    Write-Host "  DC Processing: $DCReportPath" -ForegroundColor White  
    Write-Host "  Site Summary: $SiteSummaryPath" -ForegroundColor White
    
    return $AllMismatchRecords
}

#endregion

# ===================================================================
# CONFIGURATION - MODIFY THESE SETTINGS
# ===================================================================

Write-Host "=== DNS SITE MISMATCH AUDIT SCRIPT ===" -ForegroundColor Cyan
Write-Host "This script will scan all domain controllers and find DNS records" -ForegroundColor Yellow
Write-Host "where IP addresses belong to different sites than the hosting DC." -ForegroundColor Yellow

# CONFIGURATION SETTINGS
$ExportDirectory = "C:\DNSAudit"  # Where to save reports
$ZonesToScan = @()  # Leave empty for all zones, or specify zones: @("company.com", "internal.local")
$IncludeDynamicRecords = $false  # Set to $true to include DHCP/dynamic records
$IncludeUnknownSubnets = $true  # Set to $false to exclude IPs not in any configured subnet

Write-Host "`nCurrent Settings:" -ForegroundColor Green
Write-Host "Export Directory: $ExportDirectory" -ForegroundColor White
Write-Host "Zone Filter: $(if($ZonesToScan.Count -eq 0){'All Zones'}else{$ZonesToScan -join ', '})" -ForegroundColor White
Write-Host "Include Dynamic Records: $IncludeDynamicRecords" -ForegroundColor White
Write-Host "Include Unknown Subnets: $IncludeUnknownSubnets" -ForegroundColor White

Write-Host "`nThis audit will:" -ForegroundColor Cyan
Write-Host "1. Scan all domain controllers in the forest" -ForegroundColor White
Write-Host "2. Get AD site and subnet configuration" -ForegroundColor White
Write-Host "3. Examine DNS A records on each DC" -ForegroundColor White
Write-Host "4. Identify IP addresses that belong to different sites" -ForegroundColor White
Write-Host "5. Generate detailed CSV reports" -ForegroundColor White

Write-Host "`nPress Enter to start the audit, or Ctrl+C to cancel..." -ForegroundColor Yellow
Read-Host

# RUN THE AUDIT
try {
    $Results = Start-DNSSiteMismatchAudit -ZoneFilter $ZonesToScan -IncludeDynamicRecords:$IncludeDynamicRecords -IncludeUnknownSubnets:$IncludeUnknownSubnets -ExportPath $ExportDirectory
    
    Write-Host "`nAudit completed successfully!" -ForegroundColor Green
    
    if ($Results.Count -gt 0) {
        Write-Host "`nACTION REQUIRED: Site mismatches found!" -ForegroundColor Red
        Write-Host "Review the generated reports for detailed information." -ForegroundColor Yellow
    } else {
        Write-Host "`nGOOD NEWS: No site mismatches found!" -ForegroundColor Green
    }
}
catch {
    Write-Error "Audit failed: $($_.Exception.Message)"
    Write-Host "`nCommon issues:" -ForegroundColor Yellow
    Write-Host "1. Active Directory module not available" -ForegroundColor White
    Write-Host "2. Insufficient permissions to query DNS/AD" -ForegroundColor White
    Write-Host "3. Domain controllers unreachable" -ForegroundColor White
    Write-Host "4. Not running on domain-joined machine" -ForegroundColor White
}

Write-Host "`nScript completed." -ForegroundColor Cyan 
