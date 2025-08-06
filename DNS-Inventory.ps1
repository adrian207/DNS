 # DNS Server Inventory PowerShell Scripts

#region Method 1: Inventory DNS servers in Active Directory domain
function Get-ADDNSServers {
    <#
    .SYNOPSIS
    Gets all DNS servers from Active Directory domain controllers
    
    .DESCRIPTION
    Queries Active Directory to find domain controllers and checks their DNS service status
    Requires Active Directory PowerShell module
    #>
    
    try {
        # Import AD module if available
        Import-Module ActiveDirectory -ErrorAction Stop
        
        # Get all domain controllers
        $DomainControllers = Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, Site
        
        $DNSServers = @()
        
        foreach ($DC in $DomainControllers) {
            Write-Host "Checking DNS service on $($DC.Name)..." -ForegroundColor Yellow
            
            try {
                # Check if DNS service is running
                $DNSService = Get-Service -ComputerName $DC.Name -Name "DNS" -ErrorAction Stop
                
                # Get DNS server zones
                $Zones = Get-DnsServerZone -ComputerName $DC.Name -ErrorAction SilentlyContinue
                
                $ServerInfo = [PSCustomObject]@{
                    ServerName = $DC.Name
                    IPAddress = $DC.IPv4Address
                    Site = $DC.Site
                    DNSServiceStatus = $DNSService.Status
                    ZoneCount = $Zones.Count
                    Zones = ($Zones | Where-Object {$_.ZoneType -eq "Primary"}).ZoneName -join ", "
                    OSVersion = (Get-CimInstance -ComputerName $DC.Name -ClassName Win32_OperatingSystem).Caption
                    LastBootTime = (Get-CimInstance -ComputerName $DC.Name -ClassName Win32_OperatingSystem).LastBootUpTime
                }
                
                $DNSServers += $ServerInfo
            }
            catch {
                Write-Warning "Could not query DNS service on $($DC.Name): $($_.Exception.Message)"
            }
        }
        
        return $DNSServers
    }
    catch {
        Write-Error "Active Directory module not available or domain not accessible: $($_.Exception.Message)"
        return $null
    }
}

#endregion

#region Method 2: Inventory specific DNS servers by hostname/IP
function Get-SpecificDNSServers {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$ServerList
    )
    
    <#
    .SYNOPSIS
    Inventories specific DNS servers provided in a list
    
    .PARAMETER ServerList
    Array of server names or IP addresses to inventory
    #>
    
    $DNSInventory = @()
    
    foreach ($Server in $ServerList) {
        Write-Host "Inventorying DNS server: $Server" -ForegroundColor Green
        
        try {
            # Test connectivity first
            if (Test-Connection -ComputerName $Server -Count 1 -Quiet) {
                
                # Get DNS service information
                $DNSService = Get-Service -ComputerName $Server -Name "DNS" -ErrorAction Stop
                
                # Get DNS server configuration
                $DNSConfig = Get-DnsServer -ComputerName $Server -ErrorAction Stop
                $Zones = Get-DnsServerZone -ComputerName $Server -ErrorAction Stop
                $Forwarders = Get-DnsServerForwarder -ComputerName $Server -ErrorAction Stop
                
                # Get system information
                $SystemInfo = Get-CimInstance -ComputerName $Server -ClassName Win32_ComputerSystem
                $OSInfo = Get-CimInstance -ComputerName $Server -ClassName Win32_OperatingSystem
                
                $ServerInfo = [PSCustomObject]@{
                    ServerName = $Server
                    FQDN = $SystemInfo.Name + "." + $SystemInfo.Domain
                    ServiceStatus = $DNSService.Status
                    Version = $DNSConfig.ServerSetting.MajorVersion
                    BuildNumber = $DNSConfig.ServerSetting.BuildNumber
                    TotalZones = $Zones.Count
                    PrimaryZones = ($Zones | Where-Object {$_.ZoneType -eq "Primary"}).Count
                    SecondaryZones = ($Zones | Where-Object {$_.ZoneType -eq "Secondary"}).Count
                    StubZones = ($Zones | Where-Object {$_.ZoneType -eq "Stub"}).Count
                    ConditionalForwarderZones = ($Zones | Where-Object {$_.ZoneType -eq "Forwarder"}).Count
                    Forwarders = $Forwarders.IPAddress -join ", "
                    RecursionEnabled = $DNSConfig.ServerSetting.NoRecursion -eq $false
                    OS = $OSInfo.Caption
                    ServicePackLevel = $OSInfo.ServicePackMajorVersion
                    LastBootTime = $OSInfo.LastBootUpTime
                    TotalPhysicalMemory = [math]::Round($SystemInfo.TotalPhysicalMemory / 1GB, 2)
                }
                
                $DNSInventory += $ServerInfo
            }
            else {
                Write-Warning "Cannot reach server: $Server"
            }
        }
        catch {
            Write-Error "Error inventorying $Server : $($_.Exception.Message)"
        }
    }
    
    return $DNSInventory
}

#endregion

#region Method 3: Network discovery of DNS servers
function Find-DNSServersInNetwork {
    param(
        [Parameter(Mandatory=$true)]
        [string]$NetworkRange  # e.g., "192.168.1.0/24"
    )
    
    <#
    .SYNOPSIS
    Scans network range for systems with DNS service running
    
    .PARAMETER NetworkRange
    Network range in CIDR notation (e.g., "192.168.1.0/24")
    #>
    
    # Parse network range
    $Network = $NetworkRange.Split('/')[0]
    $SubnetMask = [int]$NetworkRange.Split('/')[1]
    
    # Calculate IP range (simplified for /24 networks)
    if ($SubnetMask -eq 24) {
        $NetworkBase = $Network.Substring(0, $Network.LastIndexOf('.'))
        $IPRange = 1..254 | ForEach-Object { "$NetworkBase.$_" }
    }
    else {
        Write-Warning "This script is simplified for /24 networks. For other subnet masks, consider using a more comprehensive IP range calculator."
        return
    }
    
    Write-Host "Scanning $($IPRange.Count) IP addresses for DNS servers..." -ForegroundColor Yellow
    
    $DNSServers = @()
    
    $IPRange | ForEach-Object -Parallel {
        $IP = $_
        
        try {
            if (Test-Connection -ComputerName $IP -Count 1 -TimeoutSeconds 2 -Quiet) {
                # Try to query DNS service
                $DNSService = Get-Service -ComputerName $IP -Name "DNS" -ErrorAction SilentlyContinue
                
                if ($DNSService -and $DNSService.Status -eq "Running") {
                    $HostName = [System.Net.Dns]::GetHostEntry($IP).HostName
                    
                    [PSCustomObject]@{
                        IPAddress = $IP
                        HostName = $HostName
                        DNSServiceStatus = $DNSService.Status
                        FoundDateTime = Get-Date
                    }
                }
            }
        }
        catch {
            # Silently continue if can't connect or query
        }
    } -ThrottleLimit 50 | ForEach-Object { $DNSServers += $_ }
    
    return $DNSServers
}

#endregion

#region Method 4: Export results to various formats
function Export-DNSInventory {
    param(
        [Parameter(Mandatory=$true)]
        [PSObject[]]$DNSData,
        
        [Parameter(Mandatory=$true)]
        [string]$ExportPath,
        
        [ValidateSet("CSV", "JSON", "XML", "HTML")]
        [string]$Format = "CSV"
    )
    
    switch ($Format) {
        "CSV" {
            $DNSData | Export-Csv -Path "$ExportPath.csv" -NoTypeInformation
            Write-Host "DNS inventory exported to: $ExportPath.csv" -ForegroundColor Green
        }
        "JSON" {
            $DNSData | ConvertTo-Json -Depth 3 | Out-File -FilePath "$ExportPath.json" -Encoding UTF8
            Write-Host "DNS inventory exported to: $ExportPath.json" -ForegroundColor Green
        }
        "XML" {
            $DNSData | Export-Clixml -Path "$ExportPath.xml"
            Write-Host "DNS inventory exported to: $ExportPath.xml" -ForegroundColor Green
        }
        "HTML" {
            $HTML = $DNSData | ConvertTo-Html -Title "DNS Server Inventory" -Head "<style>table{border-collapse: collapse; width: 100%;} th, td{border: 1px solid #ddd; padding: 8px; text-align: left;} th{background-color: #f2f2f2;}</style>"
            $HTML | Out-File -FilePath "$ExportPath.html" -Encoding UTF8
            Write-Host "DNS inventory exported to: $ExportPath.html" -ForegroundColor Green
        }
    }
}

#endregion

#region Usage Examples
<#
# Example 1: Get DNS servers from Active Directory
$ADDNSServers = Get-ADDNSServers
$ADDNSServers | Format-Table -AutoSize

# Example 2: Inventory specific servers
$ServerList = @("dns1.company.com", "dns2.company.com", "192.168.1.10")
$SpecificServers = Get-SpecificDNSServers -ServerList $ServerList
$SpecificServers | Format-Table -AutoSize

# Example 3: Scan network range
$NetworkDNS = Find-DNSServersInNetwork -NetworkRange "192.168.1.0/24"
$NetworkDNS | Format-Table -AutoSize

# Example 4: Export results
Export-DNSInventory -DNSData $ADDNSServers -ExportPath "C:\DNSInventory\AD_DNS_Servers" -Format "CSV"
Export-DNSInventory -DNSData $SpecificServers -ExportPath "C:\DNSInventory\Specific_DNS_Servers" -Format "HTML"
#>

#endregion

# Main execution function
function Start-DNSInventory {
    param(
        [ValidateSet("AD", "Specific", "Network")]
        [string]$Method = "AD",
        
        [string[]]$ServerList = @(),
        [string]$NetworkRange = "",
        [string]$ExportPath = "C:\DNSInventory",
        [string]$ExportFormat = "CSV"
    )
    
    Write-Host "Starting DNS Server Inventory..." -ForegroundColor Cyan
    Write-Host "Method: $Method" -ForegroundColor Cyan
    
    # Create export directory if it doesn't exist
    if (!(Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }
    
    $Results = switch ($Method) {
        "AD" { 
            Write-Host "Discovering DNS servers in Active Directory..." -ForegroundColor Yellow
            Get-ADDNSServers 
        }
        "Specific" { 
            if ($ServerList.Count -eq 0) {
                Write-Error "ServerList parameter is required for Specific method"
                return
            }
            Get-SpecificDNSServers -ServerList $ServerList 
        }
        "Network" { 
            if ([string]::IsNullOrEmpty($NetworkRange)) {
                Write-Error "NetworkRange parameter is required for Network method"
                return
            }
            Find-DNSServersInNetwork -NetworkRange $NetworkRange 
        }
    }
    
    if ($Results) {
        Write-Host "`nFound $($Results.Count) DNS server(s)" -ForegroundColor Green
        $Results | Format-Table -AutoSize
        
        $ExportFileName = "DNS_Inventory_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Export-DNSInventory -DNSData $Results -ExportPath "$ExportPath\$ExportFileName" -Format $ExportFormat
    }
    else {
        Write-Warning "No DNS servers found or accessible"
    }
}

# Uncomment and modify one of these examples to run:
# Start-DNSInventory -Method "AD" -ExportPath "C:\Reports" -ExportFormat "CSV"
# Start-DNSInventory -Method "Specific" -ServerList @("dns1.domain.com", "dns2.domain.com") -ExportFormat "HTML"
# Start-DNSInventory -Method "Network" -NetworkRange "192.168.1.0/24" -ExportFormat "JSON" 
