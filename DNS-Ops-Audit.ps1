 # PowerShell 5.1 Compatible DNS Service Functionality Test
# Fixed null-coalescing operator issues for older PowerShell versions

#region Helper Functions for PowerShell 5.1 Compatibility

function Get-SafeCount {
    param($Collection)
    if ($Collection) { return $Collection.Count } else { return 0 }
}

function Get-SafeValue {
    param($Value, $Default = 0)
    if ($null -eq $Value) { return $Default } else { return $Value }
}

#endregion

#region Core DNS Testing Functions

function Test-DNSServiceHealth {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DCName
    )
    
    $ServiceTests = @()
    
    try {
        Write-Host "Testing DNS service health on $DCName..." -ForegroundColor Cyan
        
        # Test 1: DNS Service Status
        try {
            $DNSService = Get-Service -ComputerName $DCName -Name "DNS" -ErrorAction Stop
            $ServiceTests += [PSCustomObject]@{
                DCName = $DCName
                TestName = "DNS Service Status"
                Status = if ($DNSService.Status -eq "Running") { "PASS" } else { "FAIL" }
                Details = "Service Status: $($DNSService.Status)"
                Value = $DNSService.Status
            }
        }
        catch {
            $ServiceTests += [PSCustomObject]@{
                DCName = $DCName
                TestName = "DNS Service Status"
                Status = "FAIL"
                Details = "Cannot query DNS service: $($_.Exception.Message)"
                Value = "Error"
            }
        }
        
        # Test 2: DNS Server Configuration Access
        try {
            $DNSConfig = Get-DnsServer -ComputerName $DCName -ErrorAction Stop
            $ServiceTests += [PSCustomObject]@{
                DCName = $DCName
                TestName = "DNS Configuration Access"
                Status = "PASS"
                Details = "DNS Server Version: $($DNSConfig.ServerSetting.MajorVersion).$($DNSConfig.ServerSetting.MinorVersion)"
                Value = "$($DNSConfig.ServerSetting.MajorVersion).$($DNSConfig.ServerSetting.MinorVersion)"
            }
        }
        catch {
            $ServiceTests += [PSCustomObject]@{
                DCName = $DCName
                TestName = "DNS Configuration Access"
                Status = "FAIL"
                Details = "Cannot access DNS configuration: $($_.Exception.Message)"
                Value = "Error"
            }
        }
        
        # Test 3: DNS Zones Loading
        try {
            $Zones = Get-DnsServerZone -ComputerName $DCName -ErrorAction Stop
            $ServiceTests += [PSCustomObject]@{
                DCName = $DCName
                TestName = "DNS Zones Loading"
                Status = "PASS"
                Details = "Total Zones: $($Zones.Count)"
                Value = $Zones.Count
            }
        }
        catch {
            $ServiceTests += [PSCustomObject]@{
                DCName = $DCName
                TestName = "DNS Zones Loading"
                Status = "FAIL"
                Details = "Cannot load DNS zones: $($_.Exception.Message)"
                Value = 0
            }
        }
        
        # Test 4: Event Log Check (Recent DNS Errors)
        try {
            $DNSEvents = Get-WinEvent -ComputerName $DCName -FilterHashtable @{LogName='DNS Server'; Level=2,3; StartTime=(Get-Date).AddHours(-24)} -MaxEvents 10 -ErrorAction SilentlyContinue
            $EventCount = Get-SafeCount $DNSEvents
            
            $ServiceTests += [PSCustomObject]@{
                DCName = $DCName
                TestName = "Recent DNS Errors (24h)"
                Status = if ($EventCount -eq 0) { "PASS" } elseif ($EventCount -le 5) { "WARN" } else { "FAIL" }
                Details = "Error/Warning events in last 24 hours: $EventCount"
                Value = $EventCount
            }
        }
        catch {
            $ServiceTests += [PSCustomObject]@{
                DCName = $DCName
                TestName = "Recent DNS Errors (24h)"
                Status = "WARN"
                Details = "Cannot access DNS event log: $($_.Exception.Message)"
                Value = "Unknown"
            }
        }
        
    }
    catch {
        Write-Error "Error testing DNS service health on $DCName : $($_.Exception.Message)"
    }
    
    return $ServiceTests
}

function Test-DNSResolution {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DCName,
        [string[]]$TestQueries = @()
    )
    
    # Default test queries if none provided
    if ($TestQueries.Count -eq 0) {
        $TestQueries = @(
            "google.com",
            "microsoft.com",
            $env:USERDNSDOMAIN,
            "localhost"
        )
        
        # Add SRV record test if we have a domain
        if ($env:USERDNSDOMAIN) {
            $TestQueries += "_ldap._tcp.$env:USERDNSDOMAIN"
        }
    }
    
    $ResolutionTests = @()
    
    Write-Host "Testing DNS resolution on $DCName..." -ForegroundColor Cyan
    
    foreach ($Query in $TestQueries) {
        try {
            $StartTime = Get-Date
            $Result = Resolve-DnsName -Name $Query -Server $DCName -ErrorAction Stop
            $ResponseTime = ((Get-Date) - $StartTime).TotalMilliseconds
            
            $ResultIP = "N/A"
            if ($Result -and $Result[0].IPAddress) {
                $ResultIP = ($Result | Where-Object { $_.IPAddress } | Select-Object -First 3 | ForEach-Object { $_.IPAddress }) -join ", "
            }
            
            $ResolutionTests += [PSCustomObject]@{
                DCName = $DCName
                Query = $Query
                Status = "PASS"
                ResponseTime_ms = [math]::Round($ResponseTime, 2)
                RecordType = if ($Result -and $Result[0].Type) { $Result[0].Type } else { "Unknown" }
                Result = $ResultIP
                Details = "Resolved successfully"
            }
        }
        catch {
            $ResolutionTests += [PSCustomObject]@{
                DCName = $DCName
                Query = $Query
                Status = "FAIL"
                ResponseTime_ms = 0
                RecordType = "None"
                Result = "No resolution"
                Details = $_.Exception.Message
            }
        }
    }
    
    return $ResolutionTests
}

function Test-DNSZoneReplication {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$DomainControllers,
        [string[]]$ZonesToTest = @()
    )
    
    Write-Host "Testing DNS zone replication between DCs..." -ForegroundColor Cyan
    
    $ReplicationTests = @()
    
    # Get zones from first DC as baseline
    try {
        $BaselineDC = $DomainControllers[0]
        $BaselineZones = Get-DnsServerZone -ComputerName $BaselineDC -ErrorAction Stop
        
        if ($ZonesToTest.Count -gt 0) {
            $BaselineZones = $BaselineZones | Where-Object { $_.ZoneName -in $ZonesToTest }
        }
        
        Write-Host "Using $BaselineDC as baseline with $($BaselineZones.Count) zones" -ForegroundColor Yellow
        
        foreach ($Zone in $BaselineZones) {
            # Skip certain zone types
            if ($Zone.ZoneType -eq "Forwarder" -or $Zone.IsReverseLookupZone) {
                continue
            }
            
            Write-Host "  Testing zone: $($Zone.ZoneName)" -ForegroundColor Gray
            
            # Get a sample record from baseline zone
            try {
                $BaselineRecords = Get-DnsServerResourceRecord -ComputerName $BaselineDC -ZoneName $Zone.ZoneName -ErrorAction Stop | Where-Object { $_.RecordType -eq "A" } | Select-Object -First 3
                
                foreach ($DC in $DomainControllers) {
                    if ($DC -eq $BaselineDC) { continue }
                    
                    try {
                        # Check if zone exists on this DC
                        $TargetZone = Get-DnsServerZone -ComputerName $DC -Name $Zone.ZoneName -ErrorAction Stop
                        
                        # Check if sample records exist
                        $MatchingRecords = 0
                        $TotalRecords = Get-SafeCount $BaselineRecords
                        
                        foreach ($Record in $BaselineRecords) {
                            try {
                                $TargetRecord = Get-DnsServerResourceRecord -ComputerName $DC -ZoneName $Zone.ZoneName -Name $Record.HostName -RRType $Record.RecordType -ErrorAction SilentlyContinue
                                if ($TargetRecord) {
                                    $MatchingRecords++
                                }
                            }
                            catch {
                                # Record not found on target DC
                            }
                        }
                        
                        $ReplicationScore = if ($TotalRecords -gt 0) { ($MatchingRecords / $TotalRecords) * 100 } else { 100 }
                        
                        $ReplicationTests += [PSCustomObject]@{
                            ZoneName = $Zone.ZoneName
                            BaselineDC = $BaselineDC
                            TargetDC = $DC
                            Status = if ($ReplicationScore -eq 100) { "PASS" } elseif ($ReplicationScore -ge 80) { "WARN" } else { "FAIL" }
                            ReplicationScore = "$ReplicationScore%"
                            MatchingRecords = "$MatchingRecords/$TotalRecords"
                            Details = if ($ReplicationScore -eq 100) { "Perfect replication" } else { "Partial replication issues detected" }
                        }
                    }
                    catch {
                        $ReplicationTests += [PSCustomObject]@{
                            ZoneName = $Zone.ZoneName
                            BaselineDC = $BaselineDC
                            TargetDC = $DC
                            Status = "FAIL"
                            ReplicationScore = "0%"
                            MatchingRecords = "0/0"
                            Details = "Zone not found or inaccessible: $($_.Exception.Message)"
                        }
                    }
                }
            }
            catch {
                Write-Warning "Cannot get records from baseline zone $($Zone.ZoneName): $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Cannot establish baseline from $BaselineDC : $($_.Exception.Message)"
        return $ReplicationTests
    }
    
    return $ReplicationTests
}

function Test-DNSPerformance {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DCName,
        [int]$TestIterations = 10
    )
    
    Write-Host "Testing DNS performance on $DCName..." -ForegroundColor Cyan
    
    $PerformanceTests = @()
    $TestQueries = @("google.com", "microsoft.com")
    
    # Add domain test if available
    if ($env:USERDNSDOMAIN) {
        $TestQueries += $env:USERDNSDOMAIN
    }
    
    foreach ($Query in $TestQueries) {
        $ResponseTimes = @()
        
        for ($i = 1; $i -le $TestIterations; $i++) {
            try {
                $StartTime = Get-Date
                Resolve-DnsName -Name $Query -Server $DCName -ErrorAction Stop | Out-Null
                $ResponseTime = ((Get-Date) - $StartTime).TotalMilliseconds
                $ResponseTimes += $ResponseTime
            }
            catch {
                $ResponseTimes += 9999  # High value for failed queries
            }
        }
        
        $AvgResponse = ($ResponseTimes | Measure-Object -Average).Average
        $MaxResponse = ($ResponseTimes | Measure-Object -Maximum).Maximum
        $MinResponse = ($ResponseTimes | Measure-Object -Minimum).Minimum
        $FailedQueries = ($ResponseTimes | Where-Object { $_ -eq 9999 }).Count
        
        $PerformanceTests += [PSCustomObject]@{
            DCName = $DCName
            Query = $Query
            AvgResponseTime_ms = [math]::Round($AvgResponse, 2)
            MinResponseTime_ms = [math]::Round($MinResponse, 2)
            MaxResponseTime_ms = [math]::Round($MaxResponse, 2)
            FailedQueries = Get-SafeCount $FailedQueries
            SuccessRate = "$((($TestIterations - (Get-SafeCount $FailedQueries)) / $TestIterations) * 100)%"
            Status = if ((Get-SafeCount $FailedQueries) -eq 0 -and $AvgResponse -lt 100) { "EXCELLENT" } 
                    elseif ((Get-SafeCount $FailedQueries) -eq 0 -and $AvgResponse -lt 500) { "GOOD" }
                    elseif ((Get-SafeCount $FailedQueries) -le 2) { "WARN" } else { "FAIL" }
        }
    }
    
    return $PerformanceTests
}

function Test-DNSForwarders {
    param(
        [Parameter(Mandatory=$true)]
        [string]$DCName
    )
    
    Write-Host "Testing DNS forwarders on $DCName..." -ForegroundColor Cyan
    
    $ForwarderTests = @()
    
    try {
        # Get forwarder configuration
        $Forwarders = Get-DnsServerForwarder -ComputerName $DCName -ErrorAction Stop
        
        if ($Forwarders.IPAddress.Count -eq 0) {
            $ForwarderTests += [PSCustomObject]@{
                DCName = $DCName
                ForwarderIP = "None configured"
                Status = "WARN"
                ResponseTime_ms = 0
                Details = "No forwarders configured - using root hints"
            }
        }
        else {
            foreach ($ForwarderIP in $Forwarders.IPAddress) {
                try {
                    # Test if forwarder responds
                    $StartTime = Get-Date
                    $TestResult = Test-NetConnection -ComputerName $ForwarderIP -Port 53 -InformationLevel Quiet
                    $ResponseTime = ((Get-Date) - $StartTime).TotalMilliseconds
                    
                    if ($TestResult) {
                        # Test actual DNS query through forwarder
                        try {
                            $StartTime = Get-Date
                            Resolve-DnsName -Name "google.com" -Server $ForwarderIP -ErrorAction Stop | Out-Null
                            $QueryTime = ((Get-Date) - $StartTime).TotalMilliseconds
                            
                            $ForwarderTests += [PSCustomObject]@{
                                DCName = $DCName
                                ForwarderIP = $ForwarderIP
                                Status = "PASS"
                                ResponseTime_ms = [math]::Round($QueryTime, 2)
                                Details = "Forwarder responding and resolving queries"
                            }
                        }
                        catch {
                            $ForwarderTests += [PSCustomObject]@{
                                DCName = $DCName
                                ForwarderIP = $ForwarderIP
                                Status = "WARN"
                                ResponseTime_ms = [math]::Round($ResponseTime, 2)
                                Details = "Port 53 open but DNS queries failing"
                            }
                        }
                    }
                    else {
                        $ForwarderTests += [PSCustomObject]@{
                            DCName = $DCName
                            ForwarderIP = $ForwarderIP
                            Status = "FAIL"
                            ResponseTime_ms = 0
                            Details = "Forwarder not responding on port 53"
                        }
                    }
                }
                catch {
                    $ForwarderTests += [PSCustomObject]@{
                        DCName = $DCName
                        ForwarderIP = $ForwarderIP
                        Status = "FAIL"
                        ResponseTime_ms = 0
                        Details = "Cannot test forwarder: $($_.Exception.Message)"
                    }
                }
            }
        }
    }
    catch {
        $ForwarderTests += [PSCustomObject]@{
            DCName = $DCName
            ForwarderIP = "Error"
            Status = "FAIL"
            ResponseTime_ms = 0
            Details = "Cannot access forwarder configuration: $($_.Exception.Message)"
        }
    }
    
    return $ForwarderTests
}

#endregion

#region Main Execution Function

function Start-CompleteDNSTest {
    param(
        [string[]]$DomainControllers = @(),
        [string[]]$ZonesToTest = @(),
        [string[]]$CustomQueries = @(),
        [int]$PerformanceIterations = 10,
        [switch]$SkipReplicationTest,
        [switch]$SkipPerformanceTest,
        [string]$ExportPath = "C:\DNSTests"
    )
    
    Write-Host "=== COMPLETE DNS SERVICE FUNCTIONALITY TEST ===" -ForegroundColor Cyan
    Write-Host "Start Time: $(Get-Date)" -ForegroundColor Yellow
    Write-Host "PowerShell Version: $($PSVersionTable.PSVersion.Major)" -ForegroundColor Green
    
    # Create export directory
    if (!(Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
        Write-Host "Created test results directory: $ExportPath" -ForegroundColor Green
    }
    
    # Auto-discover domain controllers if not specified
    if ($DomainControllers.Count -eq 0) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            $DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
            $DomainControllers = $DCs
            Write-Host "Auto-discovered $($DomainControllers.Count) domain controllers" -ForegroundColor Green
        }
        catch {
            Write-Error "Cannot auto-discover domain controllers. Please specify them manually."
            return
        }
    }
    
    Write-Host "Testing DNS on domain controllers: $($DomainControllers -join ', ')" -ForegroundColor Yellow
    
    # Initialize result collections
    $AllServiceHealthResults = @()
    $AllResolutionResults = @()
    $AllReplicationResults = @()
    $AllPerformanceResults = @()
    $AllForwarderResults = @()
    
    # Test each domain controller
    foreach ($DC in $DomainControllers) {
        Write-Host "`n" + "="*60 -ForegroundColor Gray
        Write-Host "TESTING DOMAIN CONTROLLER: $DC" -ForegroundColor Green
        Write-Host "="*60 -ForegroundColor Gray
        
        # Test 1: Service Health
        $ServiceHealth = Test-DNSServiceHealth -DCName $DC
        $AllServiceHealthResults += $ServiceHealth
        
        # Test 2: DNS Resolution
        $Resolution = Test-DNSResolution -DCName $DC -TestQueries $CustomQueries
        $AllResolutionResults += $Resolution
        
        # Test 3: Performance (if not skipped)
        if (!$SkipPerformanceTest) {
            $Performance = Test-DNSPerformance -DCName $DC -TestIterations $PerformanceIterations
            $AllPerformanceResults += $Performance
        }
        
        # Test 4: Forwarders
        $Forwarders = Test-DNSForwarders -DCName $DC
        $AllForwarderResults += $Forwarders
    }
    
    # Test 5: Zone Replication (if not skipped)
    if (!$SkipReplicationTest -and $DomainControllers.Count -gt 1) {
        Write-Host "`n" + "="*60 -ForegroundColor Gray
        Write-Host "TESTING DNS ZONE REPLICATION" -ForegroundColor Green
        Write-Host "="*60 -ForegroundColor Gray
        
        $AllReplicationResults = Test-DNSZoneReplication -DomainControllers $DomainControllers -ZonesToTest $ZonesToTest
    }
    
    # Generate Reports
    $TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    Write-Host "`n" + "="*60 -ForegroundColor Gray
    Write-Host "GENERATING REPORTS" -ForegroundColor Green
    Write-Host "="*60 -ForegroundColor Gray
    
    # Export individual test results
    $AllServiceHealthResults | Export-Csv "$ExportPath\DNS_ServiceHealth_$TimeStamp.csv" -NoTypeInformation
    $AllResolutionResults | Export-Csv "$ExportPath\DNS_Resolution_$TimeStamp.csv" -NoTypeInformation
    $AllForwarderResults | Export-Csv "$ExportPath\DNS_Forwarders_$TimeStamp.csv" -NoTypeInformation
    
    if ($AllPerformanceResults.Count -gt 0) {
        $AllPerformanceResults | Export-Csv "$ExportPath\DNS_Performance_$TimeStamp.csv" -NoTypeInformation
    }
    
    if ($AllReplicationResults.Count -gt 0) {
        $AllReplicationResults | Export-Csv "$ExportPath\DNS_Replication_$TimeStamp.csv" -NoTypeInformation
    }
    
    # Generate Summary Report
    Generate-DNSTestSummary -ServiceHealth $AllServiceHealthResults -Resolution $AllResolutionResults -Replication $AllReplicationResults -Performance $AllPerformanceResults -Forwarders $AllForwarderResults -ExportPath $ExportPath -TimeStamp $TimeStamp
    
    Write-Host "`n=== DNS FUNCTIONALITY TEST COMPLETE ===" -ForegroundColor Green
    Write-Host "End Time: $(Get-Date)" -ForegroundColor Yellow
    Write-Host "Reports saved to: $ExportPath" -ForegroundColor Cyan
    
    return @{
        ServiceHealth = $AllServiceHealthResults
        Resolution = $AllResolutionResults
        Replication = $AllReplicationResults
        Performance = $AllPerformanceResults
        Forwarders = $AllForwarderResults
    }
}

function Generate-DNSTestSummary {
    param(
        $ServiceHealth,
        $Resolution,
        $Replication,
        $Performance,
        $Forwarders,
        $ExportPath,
        $TimeStamp
    )
    
    # Create summary statistics - PowerShell 5.1 compatible
    $Summary = @()
    
    # Service Health Summary
    $HealthStats = $ServiceHealth | Group-Object Status
    $PassCount = Get-SafeValue ($HealthStats | Where-Object Name -eq "PASS" | Select-Object -ExpandProperty Count)
    $WarnCount = Get-SafeValue ($HealthStats | Where-Object Name -eq "WARN" | Select-Object -ExpandProperty Count)
    $FailCount = Get-SafeValue ($HealthStats | Where-Object Name -eq "FAIL" | Select-Object -ExpandProperty Count)
    
    $Summary += [PSCustomObject]@{
        Category = "Service Health"
        PassCount = $PassCount
        WarnCount = $WarnCount
        FailCount = $FailCount
        TotalTests = Get-SafeCount $ServiceHealth
    }
    
    # Resolution Summary
    $ResolutionStats = $Resolution | Group-Object Status
    $ResPassCount = Get-SafeValue ($ResolutionStats | Where-Object Name -eq "PASS" | Select-Object -ExpandProperty Count)
    $ResWarnCount = Get-SafeValue ($ResolutionStats | Where-Object Name -eq "WARN" | Select-Object -ExpandProperty Count)
    $ResFailCount = Get-SafeValue ($ResolutionStats | Where-Object Name -eq "FAIL" | Select-Object -ExpandProperty Count)
    
    $Summary += [PSCustomObject]@{
        Category = "DNS Resolution"
        PassCount = $ResPassCount
        WarnCount = $ResWarnCount
        FailCount = $ResFailCount
        TotalTests = Get-SafeCount $Resolution
    }
    
    # Export summary
    $Summary | Export-Csv "$ExportPath\DNS_TestSummary_$TimeStamp.csv" -NoTypeInformation
    
    # Display summary
    Write-Host "`n=== TEST SUMMARY ===" -ForegroundColor Cyan
    $Summary | Format-Table -AutoSize
    
    # Show critical issues
    $CriticalIssues = @()
    $CriticalIssues += $ServiceHealth | Where-Object Status -eq "FAIL"
    $CriticalIssues += $Resolution | Where-Object Status -eq "FAIL"
    if ($Replication) {
        $CriticalIssues += $Replication | Where-Object Status -eq "FAIL"
    }
    
    if ($CriticalIssues.Count -gt 0) {
        Write-Host "`n=== CRITICAL ISSUES FOUND ===" -ForegroundColor Red
        $CriticalIssues | Select-Object DCName, TestName, Details | Format-Table -AutoSize
    }
    else {
        Write-Host "`n✓ No critical DNS issues found!" -ForegroundColor Green
    }
    
    # Performance summary if available
    if ($Performance -and $Performance.Count -gt 0) {
        $AvgResponseTime = ($Performance | Measure-Object AvgResponseTime_ms -Average).Average
        Write-Host "`n=== PERFORMANCE SUMMARY ===" -ForegroundColor Cyan
        Write-Host "Average DNS Response Time: $([math]::Round($AvgResponseTime, 2))ms" -ForegroundColor Yellow
    }
}

#endregion

# ===================================================================
# CONFIGURATION AND EXECUTION - PowerShell 5.1 Compatible
# ===================================================================

Write-Host "=== PowerShell 5.1 Compatible DNS Test Script ===" -ForegroundColor Cyan
Write-Host "This version works with PowerShell 5.1 and later" -ForegroundColor Yellow

# CONFIGURATION
$TestConfig = @{
    DomainControllers = @()  # Leave empty for auto-discovery
    ZonesToTest = @()        # Leave empty for all zones
    CustomQueries = @()      # Leave empty for default test queries
    PerformanceIterations = 10
    SkipReplicationTest = $false
    SkipPerformanceTest = $false
    ExportPath = "C:\DNSTests"
}

Write-Host "`nCurrent Configuration:" -ForegroundColor Green
Write-Host "Domain Controllers: $(if($TestConfig.DomainControllers.Count -eq 0){'Auto-discover'}else{$TestConfig.DomainControllers -join ', '})" -ForegroundColor White
Write-Host "Export Path: $($TestConfig.ExportPath)" -ForegroundColor White
Write-Host "Performance Iterations: $($TestConfig.PerformanceIterations)" -ForegroundColor White

Write-Host "`nTests included:" -ForegroundColor Cyan
Write-Host "✓ DNS Service Health Check" -ForegroundColor Green
Write-Host "✓ DNS Resolution Testing" -ForegroundColor Green
Write-Host "✓ DNS Forwarder Testing" -ForegroundColor Green
if (!$TestConfig.SkipPerformanceTest) { Write-Host "✓ DNS Performance Testing" -ForegroundColor Green }
if (!$TestConfig.SkipReplicationTest) { Write-Host "✓ DNS Zone Replication Testing" -ForegroundColor Green }

Write-Host "`nPress Enter to start DNS testing, or Ctrl+C to cancel..." -ForegroundColor Yellow
Read-Host

# EXECUTE TESTS
try {
    $TestResults = Start-CompleteDNSTest @TestConfig
    Write-Host "`nDNS functionality testing completed successfully!" -ForegroundColor Green
}
catch {
    Write-Error "DNS testing failed: $($_.Exception.Message)"
    Write-Host "`nCommon issues:" -ForegroundColor Yellow
    Write-Host "1. Insufficient DNS administrative permissions" -ForegroundColor White
    Write-Host "2. Domain controllers unreachable" -ForegroundColor White
    Write-Host "3. DNS service not running on target DCs" -ForegroundColor White
    Write-Host "4. Firewall blocking DNS queries" -ForegroundColor White
}

Write-Host "`nDNS functionality test script completed." -ForegroundColor Cyan 
