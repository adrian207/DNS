 # SIMPLE DNS AUDIT - DIRECT EXECUTION
# Copy and paste this entire script, then modify the variables at the bottom

#region DNS Audit Functions (Copy this entire section)

function Get-DNSStaticEntries {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$DNSServers,
        [string[]]$ZoneFilter = @(),
        [string[]]$RecordTypeFilter = @("A", "AAAA", "CNAME", "MX", "PTR", "SRV", "TXT", "NS"),
        [switch]$IncludeDynamicRecords,
        [string]$ExportPath = "C:\DNSAudit"
    )
    
    Write-Host "Starting DNS Static Entries Audit..." -ForegroundColor Cyan
    Write-Host "Target DNS Servers: $($DNSServers -join ', ')" -ForegroundColor Yellow
    
    # Create export directory
    if (!(Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
        Write-Host "Created export directory: $ExportPath" -ForegroundColor Green
    }
    
    $AllDNSRecords = @()
    
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
                        # Parse record data based on type
                        $RecordData = ""
                        $Priority = $null
                        $Target = $null
                        
                        switch ($Record.RecordType) {
                            "A" { $RecordData = $Record.RecordData.IPv4Address.ToString() }
                            "AAAA" { $RecordData = $Record.RecordData.IPv6Address.ToString() }
                            "CNAME" { 
                                $RecordData = $Record.RecordData.HostNameAlias
                                $Target = $Record.RecordData.HostNameAlias
                            }
                            "MX" { 
                                $RecordData = "$($Record.RecordData.Preference) $($Record.RecordData.MailExchange)"
                                $Priority = $Record.RecordData.Preference
                                $Target = $Record.RecordData.MailExchange
                            }
                            "PTR" { 
                                $RecordData = $Record.RecordData.PtrDomainName
                                $Target = $Record.RecordData.PtrDomainName
                            }
                            "SRV" { 
                                $RecordData = "$($Record.RecordData.Priority) $($Record.RecordData.Weight) $($Record.RecordData.Port) $($Record.RecordData.DomainName)"
                                $Priority = $Record.RecordData.Priority
                                $Target = $Record.RecordData.DomainName
                            }
                            "TXT" { $RecordData = $Record.RecordData.DescriptiveText -join " " }
                            "NS" { 
                                $RecordData = $Record.RecordData.NameServer
                                $Target = $Record.RecordData.NameServer
                            }
                            default { $RecordData = $Record.RecordData.ToString() }
                        }
                        
                        $DNSEntry = [PSCustomObject]@{
                            DNSServer = $DNSServer
                            ZoneName = $Zone.ZoneName
                            ZoneType = $Zone.ZoneType
                            RecordName = $Record.HostName
                            FQDN = if ($Record.HostName -eq "@") { $Zone.ZoneName } else { "$($Record.HostName).$($Zone.ZoneName)" }
                            RecordType = $Record.RecordType
                            RecordData = $RecordData
                            TTL = $Record.TimeToLive.TotalSeconds
                            IsStatic = $Record.TimeToLive.TotalSeconds -eq 0 -or $Record.RecordType -in @("NS", "SOA", "CNAME", "MX", "SRV", "TXT")
                            Priority = $Priority
                            Target = $Target
                            AuditDate = Get-Date
                        }
                        
                        $AllDNSRecords += $DNSEntry
                    }
                    
                    Write-Host "    Found $($FilteredRecords.Count) records" -ForegroundColor Gray
                }
                catch {
                    Write-Warning "Error processing zone $($Zone.ZoneName) on $DNSServer : $($_.Exception.Message)"
                }
            }
        }
        catch {
            Write-Error "Error processing DNS server $DNSServer : $($_.Exception.Message)"
        }
    }
    
    # Export to CSV
    $TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $ReportPath = "$ExportPath\DNS_Static_Entries_$TimeStamp.csv"
    $AllDNSRecords | Export-Csv -Path $ReportPath -NoTypeInformation
    
    Write-Host "`n=== AUDIT COMPLETE ===" -ForegroundColor Green
    Write-Host "Total Records Found: $($AllDNSRecords.Count)" -ForegroundColor Green
    Write-Host "Report saved to: $ReportPath" -ForegroundColor Green
    
    # Display summary
    Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
    $AllDNSRecords | Group-Object RecordType | Sort-Object Count -Descending | ForEach-Object {
        Write-Host "  $($_.Name): $($_.Count) records" -ForegroundColor Yellow
    }
    
    return $AllDNSRecords
}

#endregion

# ===================================================================
# MODIFY THESE VARIABLES FOR YOUR ENVIRONMENT, THEN RUN THE SCRIPT
# ===================================================================

Write-Host "=== DNS STATIC ENTRIES AUDIT SCRIPT ===" -ForegroundColor Cyan
Write-Host "Modify the variables below, then run this script" -ForegroundColor Yellow

# CHANGE THESE VALUES FOR YOUR ENVIRONMENT:
$MyDNSServers = @("LONDC01", "LONDC03", "SEADC01", "SEADC02", "LSNDC01", "LSNDC01", "BELDC01", "BELDC02")  # Replace with your DNS servers
$MyExportPath = "C:\DNSAudit"  # Where to save reports
$MyZoneFilter = @()  # Leave empty for all zones, or specify: @("yourdomain.com", "internal.local")

# Optional settings:
$IncludeDynamicRecords = $false  # Set to $true to include dynamic records
$RecordTypesToAudit = @("A", "AAAA", "CNAME", "MX", "PTR", "SRV", "TXT", "NS")  # Record types to include

Write-Host "`nCurrent Settings:" -ForegroundColor Green
Write-Host "DNS Servers: $($MyDNSServers -join ', ')" -ForegroundColor White
Write-Host "Export Path: $MyExportPath" -ForegroundColor White
Write-Host "Zone Filter: $(if($MyZoneFilter.Count -eq 0){'All Zones'}else{$MyZoneFilter -join ', '})" -ForegroundColor White
Write-Host "Include Dynamic Records: $IncludeDynamicRecords" -ForegroundColor White

Write-Host "`nPress Enter to start the audit, or Ctrl+C to cancel..." -ForegroundColor Yellow
Read-Host

# RUN THE AUDIT
try {
    $Results = Get-DNSStaticEntries -DNSServers $MyDNSServers -ExportPath $MyExportPath -ZoneFilter $MyZoneFilter -RecordTypeFilter $RecordTypesToAudit -IncludeDynamicRecords:$IncludeDynamicRecords
    
    # Show first 10 records as preview
    Write-Host "`n=== PREVIEW (First 10 records) ===" -ForegroundColor Cyan
    $Results | Select-Object -First 10 | Format-Table -AutoSize
    
    Write-Host "`nAudit completed successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Audit failed: $($_.Exception.Message)"
    Write-Host "Common issues:" -ForegroundColor Yellow
    Write-Host "1. DNS server names are incorrect or unreachable" -ForegroundColor White
    Write-Host "2. Insufficient permissions to query DNS servers" -ForegroundColor White
    Write-Host "3. DNS PowerShell module not available" -ForegroundColor White
}

Write-Host "`nScript completed. Check the export directory for your reports." -ForegroundColor Cyan 
