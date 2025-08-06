 # DNS Static Entries Audit Script
# Creates comprehensive CSV reports of all static DNS entries

#region Main Functions

function Get-DNSStaticEntries {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$DNSServers,
        
        [string[]]$ZoneFilter = @(),  # Optional: Filter specific zones
        [string[]]$RecordTypeFilter = @("A", "AAAA", "CNAME", "MX", "PTR", "SRV", "TXT", "NS"),  # Record types to audit
        [switch]$IncludeDynamicRecords,  # Include dynamic records in report
        [switch]$IncludeTimestamp,       # Include timestamp information
        [string]$ExportPath = "C:\DNSAudit"
    )
    
    <#
    .SYNOPSIS
    Audits all static DNS entries from specified DNS servers
    
    .DESCRIPTION
    Connects to DNS servers and extracts all static DNS records, 
    formatting them into a comprehensive CSV report
    
    .PARAMETER DNSServers
    Array of DNS server names or IP addresses to audit
    
    .PARAMETER ZoneFilter
    Optional array of specific zone names to audit. If empty, audits all zones.
    
    .PARAMETER RecordTypeFilter
    Array of DNS record types to include in audit (default: common record types)
    
    .PARAMETER IncludeDynamicRecords
    Switch to include dynamic/scavenged records in the report
    
    .PARAMETER IncludeTimestamp
    Switch to include timestamp information for records
    #>
    
    Write-Host "Starting DNS Static Entries Audit..." -ForegroundColor Cyan
    Write-Host "Target DNS Servers: $($DNSServers -join ', ')" -ForegroundColor Yellow
    
    # Create export directory
    if (!(Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
        Write-Host "Created export directory: $ExportPath" -ForegroundColor Green
    }
    
    $AllDNSRecords = @()
    $AuditSummary = @()
    
    foreach ($DNSServer in $DNSServers) {
        Write-Host "`nProcessing DNS Server: $DNSServer" -ForegroundColor Green
        
        try {
            # Test connectivity to DNS server
            if (!(Test-Connection -ComputerName $DNSServer -Count 1 -Quiet)) {
                Write-Warning "Cannot reach DNS server: $DNSServer"
                continue
            }
            
            # Get all zones from the DNS server
            $Zones = Get-DnsServerZone -ComputerName $DNSServer -ErrorAction Stop
            
            if ($ZoneFilter.Count -gt 0) {
                $Zones = $Zones | Where-Object { $_.ZoneName -in $ZoneFilter }
                Write-Host "Filtering zones: $($ZoneFilter -join ', ')" -ForegroundColor Yellow
            }
            
            Write-Host "Found $($Zones.Count) zones to process" -ForegroundColor Yellow
            
            $ServerRecordCount = 0
            
            foreach ($Zone in $Zones) {
                Write-Host "  Processing zone: $($Zone.ZoneName)" -ForegroundColor Cyan
                
                try {
                    # Get all resource records in the zone
                    $ResourceRecords = Get-DnsServerResourceRecord -ComputerName $DNSServer -ZoneName $Zone.ZoneName -ErrorAction Stop
                    
                    # Filter by record type
                    $FilteredRecords = $ResourceRecords | Where-Object { $_.RecordType -in $RecordTypeFilter }
                    
                    # Filter static vs dynamic records if specified
                    if (!$IncludeDynamicRecords) {
                        $FilteredRecords = $FilteredRecords | Where-Object { 
                            $_.TimeToLive.TotalSeconds -ne 0 -or $_.RecordType -in @("NS", "SOA", "CNAME", "MX", "SRV", "TXT")
                        }
                    }
                    
                    foreach ($Record in $FilteredRecords) {
                        $RecordData = Parse-DNSRecordData -Record $Record
                        
                        $DNSEntry = [PSCustomObject]@{
                            DNSServer = $DNSServer
                            ZoneName = $Zone.ZoneName
                            ZoneType = $Zone.ZoneType
                            RecordName = $Record.HostName
                            FQDN = if ($Record.HostName -eq "@") { $Zone.ZoneName } else { "$($Record.HostName).$($Zone.ZoneName)" }
                            RecordType = $Record.RecordType
                            RecordData = $RecordData.Data
                            TTL = $Record.TimeToLive.TotalSeconds
                            IsStatic = $Record.TimeToLive.TotalSeconds -eq 0 -or $Record.RecordType -in @("NS", "SOA", "CNAME", "MX", "SRV", "TXT")
                            Priority = $RecordData.Priority
                            Weight = $RecordData.Weight
                            Port = $RecordData.Port
                            Target = $RecordData.Target
                            CreatedDate = if ($IncludeTimestamp) { $Record.Timestamp } else { $null }
                            AuditDate = Get-Date
                        }
                        
                        $AllDNSRecords += $DNSEntry
                        $ServerRecordCount++
                    }
                    
                    Write-Host "    Found $($FilteredRecords.Count) records" -ForegroundColor Gray
                }
                catch {
                    Write-Warning "Error processing zone $($Zone.ZoneName) on $DNSServer : $($_.Exception.Message)"
                }
            }
            
            # Create server summary
            $ServerSummary = [PSCustomObject]@{
                DNSServer = $DNSServer
                TotalZones = $Zones.Count
                TotalRecords = $ServerRecordCount
                StaticRecords = ($AllDNSRecords | Where-Object { $_.DNSServer -eq $DNSServer -and $_.IsStatic }).Count
                DynamicRecords = ($AllDNSRecords | Where-Object { $_.DNSServer -eq $DNSServer -and !$_.IsStatic }).Count
                AuditDate = Get-Date
            }
            
            $AuditSummary += $ServerSummary
            Write-Host "Completed $DNSServer - Total Records: $ServerRecordCount" -ForegroundColor Green
        }
        catch {
            Write-Error "Error processing DNS server $DNSServer : $($_.Exception.Message)"
        }
    }
    
    # Generate reports
    Generate-DNSAuditReports -DNSRecords $AllDNSRecords -AuditSummary $AuditSummary -ExportPath $ExportPath
    
    return $AllDNSRecords
}

function Parse-DNSRecordData {
    param($Record)
    
    $RecordData = @{
        Data = ""
        Priority = $null
        Weight = $null
        Port = $null
        Target = $null
    }
    
    switch ($Record.RecordType) {
        "A" { 
            $RecordData.Data = $Record.RecordData.IPv4Address.ToString()
        }
        "AAAA" { 
            $RecordData.Data = $Record.RecordData.IPv6Address.ToString()
        }
        "CNAME" { 
            $RecordData.Data = $Record.RecordData.HostNameAlias
            $RecordData.Target = $Record.RecordData.HostNameAlias
        }
        "MX" { 
            $RecordData.Data = "$($Record.RecordData.Preference) $($Record.RecordData.MailExchange)"
            $RecordData.Priority = $Record.RecordData.Preference
            $RecordData.Target = $Record.RecordData.MailExchange
        }
        "PTR" { 
            $RecordData.Data = $Record.RecordData.PtrDomainName
            $RecordData.Target = $Record.RecordData.PtrDomainName
        }
        "SRV" { 
            $RecordData.Data = "$($Record.RecordData.Priority) $($Record.RecordData.Weight) $($Record.RecordData.Port) $($Record.RecordData.DomainName)"
            $RecordData.Priority = $Record.RecordData.Priority
            $RecordData.Weight = $Record.RecordData.Weight
            $RecordData.Port = $Record.RecordData.Port
            $RecordData.Target = $Record.RecordData.DomainName
        }
        "TXT" { 
            $RecordData.Data = $Record.RecordData.DescriptiveText -join " "
        }
        "NS" { 
            $RecordData.Data = $Record.RecordData.NameServer
            $RecordData.Target = $Record.RecordData.NameServer
        }
        "SOA" { 
            $RecordData.Data = "$($Record.RecordData.PrimaryServer) $($Record.RecordData.ResponsiblePerson)"
            $RecordData.Target = $Record.RecordData.PrimaryServer
        }
        default { 
            $RecordData.Data = $Record.RecordData.ToString()
        }
    }
    
    return $RecordData
}

function Generate-DNSAuditReports {
    param(
        [PSObject[]]$DNSRecords,
        [PSObject[]]$AuditSummary,
        [string]$ExportPath
    )
    
    $TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    # Main DNS Records Report
    $MainReportPath = "$ExportPath\DNS_Static_Entries_$TimeStamp.csv"
    $DNSRecords | Export-Csv -Path $MainReportPath -NoTypeInformation
    Write-Host "Main DNS audit report exported to: $MainReportPath" -ForegroundColor Green
    
    # Summary Report
    $SummaryReportPath = "$ExportPath\DNS_Audit_Summary_$TimeStamp.csv"
    $AuditSummary | Export-Csv -Path $SummaryReportPath -NoTypeInformation
    Write-Host "DNS audit summary exported to: $SummaryReportPath" -ForegroundColor Green
    
    # Record Type Summary
    $RecordTypeSummary = $DNSRecords | Group-Object RecordType | Select-Object @{Name="RecordType";Expression={$_.Name}}, Count | Sort-Object Count -Descending
    $RecordTypeReportPath = "$ExportPath\DNS_RecordType_Summary_$TimeStamp.csv"
    $RecordTypeSummary | Export-Csv -Path $RecordTypeReportPath -NoTypeInformation
    Write-Host "Record type summary exported to: $RecordTypeReportPath" -ForegroundColor Green
    
    # Zone Summary
    $ZoneSummary = $DNSRecords | Group-Object ZoneName | Select-Object @{Name="ZoneName";Expression={$_.Name}}, Count | Sort-Object Count -Descending
    $ZoneReportPath = "$ExportPath\DNS_Zone_Summary_$TimeStamp.csv"
    $ZoneSummary | Export-Csv -Path $ZoneReportPath -NoTypeInformation
    Write-Host "Zone summary exported to: $ZoneReportPath" -ForegroundColor Green
    
    # Static vs Dynamic Summary (if dynamic records were included)
    $StaticDynamicSummary = $DNSRecords | Group-Object IsStatic | Select-Object @{Name="RecordType";Expression={if($_.Name -eq "True"){"Static"}else{"Dynamic"}}}, Count
    $StaticDynamicReportPath = "$ExportPath\DNS_Static_Dynamic_Summary_$TimeStamp.csv"
    $StaticDynamicSummary | Export-Csv -Path $StaticDynamicReportPath -NoTypeInformation
    Write-Host "Static/Dynamic summary exported to: $StaticDynamicReportPath" -ForegroundColor Green
    
    # Generate HTML Summary Dashboard
    Generate-HTMLDashboard -DNSRecords $DNSRecords -AuditSummary $AuditSummary -ExportPath $ExportPath -TimeStamp $TimeStamp
}

function Generate-HTMLDashboard {
    param(
        [PSObject[]]$DNSRecords,
        [PSObject[]]$AuditSummary,
        [string]$ExportPath,
        [string]$TimeStamp
    )
    
    $TotalRecords = $DNSRecords.Count
    $StaticRecords = ($DNSRecords | Where-Object IsStatic).Count
    $UniqueZones = ($DNSRecords | Select-Object ZoneName -Unique).Count
    
    $HTMLContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>DNS Audit Dashboard - $TimeStamp</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; text-align: center; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; }
        .stat-label { font-size: 0.9em; opacity: 0.9; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
        th { background-color: #f2f2f2; font-weight: bold; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .section { margin: 30px 0; }
        .section h2 { color: #444; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>DNS Audit Dashboard</h1>
        <p style="text-align: center; color: #666;">Generated on $(Get-Date)</p>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$TotalRecords</div>
                <div class="stat-label">Total DNS Records</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$StaticRecords</div>
                <div class="stat-label">Static Records</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$UniqueZones</div>
                <div class="stat-label">DNS Zones</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$($AuditSummary.Count)</div>
                <div class="stat-label">DNS Servers</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Server Summary</h2>
            $($AuditSummary | ConvertTo-Html -Fragment -Property DNSServer, TotalZones, TotalRecords, StaticRecords, DynamicRecords)
        </div>
        
        <div class="section">
            <h2>Top 10 Zones by Record Count</h2>
            $(($DNSRecords | Group-Object ZoneName | Sort-Object Count -Descending | Select-Object -First 10 @{Name="Zone";Expression={$_.Name}}, Count) | ConvertTo-Html -Fragment)
        </div>
        
        <div class="section">
            <h2>Record Type Distribution</h2>
            $(($DNSRecords | Group-Object RecordType | Sort-Object Count -Descending | Select-Object @{Name="Record Type";Expression={$_.Name}}, Count) | ConvertTo-Html -Fragment)
        </div>
    </div>
</body>
</html>
"@
    
    $HTMLReportPath = "$ExportPath\DNS_Audit_Dashboard_$TimeStamp.html"
    $HTMLContent | Out-File -FilePath $HTMLReportPath -Encoding UTF8
    Write-Host "HTML dashboard exported to: $HTMLReportPath" -ForegroundColor Green
}

#endregion

#region Specialized Audit Functions

function Get-DNSOrphanedRecords {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject[]]$DNSRecords
    )
    
    <#
    .SYNOPSIS
    Identifies potentially orphaned DNS records (A records without PTR, etc.)
    #>
    
    $ARecords = $DNSRecords | Where-Object { $_.RecordType -eq "A" }
    $PTRRecords = $DNSRecords | Where-Object { $_.RecordType -eq "PTR" }
    
    $OrphanedARecords = @()
    
    foreach ($ARecord in $ARecords) {
        $IPAddress = $ARecord.RecordData
        $ReverseDNSName = Convert-IPToReverseDNS -IPAddress $IPAddress
        
        $MatchingPTR = $PTRRecords | Where-Object { $_.RecordName -eq $ReverseDNSName -and $_.Target -eq $ARecord.FQDN }
        
        if (!$MatchingPTR) {
            $OrphanedARecords += [PSCustomObject]@{
                FQDN = $ARecord.FQDN
                IPAddress = $IPAddress
                Zone = $ARecord.ZoneName
                DNSServer = $ARecord.DNSServer
                Issue = "No matching PTR record"
            }
        }
    }
    
    return $OrphanedARecords
}

function Convert-IPToReverseDNS {
    param([string]$IPAddress)
    
    $Octets = $IPAddress.Split('.')
    [Array]::Reverse($Octets)
    return ($Octets -join '.') + '.in-addr.arpa'
}

function Get-DNSDuplicateRecords {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject[]]$DNSRecords
    )
    
    <#
    .SYNOPSIS
    Identifies duplicate DNS records (same name, different data)
    #>
    
    $DuplicateGroups = $DNSRecords | Group-Object FQDN, RecordType | Where-Object Count -gt 1
    
    $Duplicates = @()
    foreach ($Group in $DuplicateGroups) {
        $Records = $Group.Group
        if (($Records.RecordData | Get-Unique).Count -gt 1) {  # Different data values
            foreach ($Record in $Records) {
                $Duplicates += [PSCustomObject]@{
                    FQDN = $Record.FQDN
                    RecordType = $Record.RecordType
                    RecordData = $Record.RecordData
                    Zone = $Record.ZoneName
                    DNSServer = $Record.DNSServer
                    DuplicateCount = $Group.Count
                }
            }
        }
    }
    
    return $Duplicates
}

#endregion

#region Usage Examples and Main Execution

function Start-DNSStaticAudit {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$DNSServers,
        
        [string[]]$ZoneFilter = @(),
        [switch]$IncludeDynamicRecords,
        [switch]$IncludeTimestamp,
        [switch]$FindOrphaned,
        [switch]$FindDuplicates,
        [string]$ExportPath = "C:\DNSAudit"
    )
    
    Write-Host "=== DNS Static Entries Audit ===" -ForegroundColor Cyan
    Write-Host "Start Time: $(Get-Date)" -ForegroundColor Yellow
    
    # Main audit
    $AllRecords = Get-DNSStaticEntries -DNSServers $DNSServers -ZoneFilter $ZoneFilter -IncludeDynamicRecords:$IncludeDynamicRecords -IncludeTimestamp:$IncludeTimestamp -ExportPath $ExportPath
    
    if ($AllRecords.Count -eq 0) {
        Write-Warning "No DNS records found!"
        return
    }
    
    # Additional analysis
    if ($FindOrphaned) {
        Write-Host "`nSearching for orphaned records..." -ForegroundColor Yellow
        $OrphanedRecords = Get-DNSOrphanedRecords -DNSRecords $AllRecords
        if ($OrphanedRecords.Count -gt 0) {
            $TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $OrphanedPath = "$ExportPath\DNS_Orphaned_Records_$TimeStamp.csv"
            $OrphanedRecords | Export-Csv -Path $OrphanedPath -NoTypeInformation
            Write-Host "Found $($OrphanedRecords.Count) orphaned records. Report: $OrphanedPath" -ForegroundColor Red
        }
    }
    
    if ($FindDuplicates) {
        Write-Host "`nSearching for duplicate records..." -ForegroundColor Yellow
        $DuplicateRecords = Get-DNSDuplicateRecords -DNSRecords $AllRecords
        if ($DuplicateRecords.Count -gt 0) {
            $TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $DuplicatePath = "$ExportPath\DNS_Duplicate_Records_$TimeStamp.csv"
            $DuplicateRecords | Export-Csv -Path $DuplicatePath -NoTypeInformation
            Write-Host "Found $($DuplicateRecords.Count) duplicate records. Report: $DuplicatePath" -ForegroundColor Red
        }
    }
    
    Write-Host "`n=== Audit Complete ===" -ForegroundColor Green
    Write-Host "End Time: $(Get-Date)" -ForegroundColor Yellow
    Write-Host "Total Records Processed: $($AllRecords.Count)" -ForegroundColor Green
    Write-Host "Reports saved to: $ExportPath" -ForegroundColor Green
}

#endregion

<#
USAGE EXAMPLES:

# Basic audit of all static entries from specific DNS servers
Start-DNSStaticAudit -DNSServers @("dns1.company.com", "dns2.company.com")

# Audit specific zones only
Start-DNSStaticAudit -DNSServers @("dns1.company.com") -ZoneFilter @("company.com", "internal.local")

# Comprehensive audit including dynamic records and analysis
Start-DNSStaticAudit -DNSServers @("dns1.company.com", "dns2.company.com") -IncludeDynamicRecords -FindOrphaned -FindDuplicates -ExportPath "C:\DNSReports"

# Quick audit with timestamps
Start-DNSStaticAudit -DNSServers @("192.168.1.10") -IncludeTimestamp
#> 
