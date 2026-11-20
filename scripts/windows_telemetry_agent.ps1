<#
.SYNOPSIS
    H-SOC Native Windows Telemetry Agent
.DESCRIPTION
    Collects Windows Security/System event logs and active TCP network connection metadata,
    normalizes them, and streams them in real-time to the H-SOC SIEM platform.

.PARAMETER Endpoint
    The H-SOC Windows ingestion endpoint URL (default: http://localhost:8000/api/v1/telemetry/windows/ingest)
.PARAMETER IntervalSeconds
    Polling interval in seconds (default: 10)
.PARAMETER MaxEvents
    Maximum events per batch (default: 50)
.PARAMETER Action
    Command to run: Start, Status, Once, TestConnection
#>

param (
    [string]$Endpoint = "http://localhost:8000/api/v1/telemetry/windows/ingest",
    [int]$IntervalSeconds = 10,
    [int]$MaxEvents = 50,
    [ValidateSet("Start", "Status", "Once", "TestConnection")]
    [string]$Action = "Once"
)

$ComputerName = $env:COMPUTERNAME

function Test-HsocConnection {
    Write-Host "[+] Testing connection to H-SOC endpoint: $Endpoint" -ForegroundColor Cyan
    try {
        $statusUrl = $Endpoint.Replace("/ingest", "/status")
        $resp = Invoke-RestMethod -Uri $statusUrl -Method Get -TimeoutSec 5 -ErrorAction Stop
        Write-Host "[OK] H-SOC Windows Telemetry API is reachable!" -ForegroundColor Green
        Write-Host "     Server Hostname: $($resp.hostname)" -ForegroundColor Gray
        Write-Host "     Server Status:   $($resp.status)" -ForegroundColor Gray
        return $true
    } catch {
        Write-Host "[!] Could not reach H-SOC server at $statusUrl: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Get-WindowsSecurityTelemetry {
    param ([int]$Limit = 25)
    $events = @()
    $filterIds = @(4624, 4625, 4720, 4728, 4732, 7045, 4688)

    try {
        # Check Security log first
        $rawEvents = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=$filterIds} -MaxEvents $Limit -ErrorAction SilentlyContinue
        if (-not $rawEvents) {
            # Fallback to System log
            $rawEvents = Get-WinEvent -FilterHashtable @{LogName='System'} -MaxEvents $Limit -ErrorAction SilentlyContinue
        }
    } catch {
        $rawEvents = @()
    }

    if ($rawEvents) {
        foreach ($ev in $rawEvents) {
            $msgSnippet = $ev.Message
            if ($msgSnippet.Length -gt 250) { $msgSnippet = $msgSnippet.Substring(0, 250) }
            
            $events += [PSCustomObject]@{
                source_type = "win_security"
                EventID     = [string]$ev.Id
                TimeCreated = $ev.TimeCreated.ToUniversalTime().ToString('o')
                Computer    = $ComputerName
                raw         = "EventID=$($ev.Id) Computer=$ComputerName Time=$($ev.TimeCreated.ToString('o')) $msgSnippet"
                data        = @{
                    event_id    = [string]$ev.Id
                    computer    = $ComputerName
                    time        = $ev.TimeCreated.ToString('o')
                    description = $msgSnippet
                }
            }
        }
    }
    return $events
}

function Get-WindowsNetworkTelemetry {
    param ([int]$Limit = 25)
    $netItems = @()

    try {
        $conns = Get-NetTCPConnection -State Established,Listen,SynSent -ErrorAction SilentlyContinue |
            Select-Object -First $Limit LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

        if ($conns) {
            foreach ($c in $conns) {
                # Ignore loopback
                if ($c.RemoteAddress -in @('127.0.0.1', '::1', '0.0.0.0', '::') -or -not $c.RemoteAddress) {
                    continue
                }

                $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
                $procName = if ($proc) { $proc.ProcessName } else { "PID_$($c.OwningProcess)" }

                $netItems += [PSCustomObject]@{
                    source_type = "windows_network"
                    type        = "network_connection"
                    src_ip      = $c.LocalAddress
                    dst_ip      = $c.RemoteAddress
                    dst_port    = [int]$c.RemotePort
                    host        = $ComputerName
                    action      = "tcp_connection_$($c.State.ToString().ToLower())"
                    outcome     = "success"
                    TimeCreated = (Get-Date).ToUniversalTime().ToString('o')
                    raw         = "TCP Connection: Local=$($c.LocalAddress):$($c.LocalPort) -> Remote=$($c.RemoteAddress):$($c.RemotePort) State=$($c.State) Process=$procName (PID $($c.OwningProcess))"
                    features    = @{
                        local_port   = [int]$c.LocalPort
                        remote_port  = [int]$c.RemotePort
                        process_name = $procName
                        pid          = [int]$c.OwningProcess
                        state        = [string]$c.State
                    }
                }
            }
        }
    } catch {}

    return $netItems
}

function Send-HsocBatch {
    param ($Batch)
    if (-not $Batch -or $Batch.Count -eq 0) {
        Write-Host "[-] No events to forward in this cycle." -ForegroundColor Gray
        return
    }

    $jsonBody = $Batch | ConvertTo-Json -Compress -Depth 4
    try {
        $res = Invoke-RestMethod -Uri $Endpoint -Method Post -Body $jsonBody -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop
        Write-Host "[OK] Forwarded $($Batch.Count) events -> Server accepted $($res.accepted) (duplicates: $($res.duplicates))" -ForegroundColor Green
    } catch {
        Write-Host "[!] Forwarding error: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# --- Main Dispatch ---
Write-Host "==========================================================" -ForegroundColor DarkCyan
Write-Host " H-SOC Windows Telemetry Agent (Host: $ComputerName)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor DarkCyan

switch ($Action) {
    "TestConnection" {
        Test-HsocConnection
    }
    "Status" {
        Test-HsocConnection
    }
    "Once" {
        Write-Host "[*] Capturing single snapshot..." -ForegroundColor Cyan
        $sec = Get-WindowsSecurityTelemetry -Limit ($MaxEvents / 2)
        $net = Get-WindowsNetworkTelemetry -Limit ($MaxEvents / 2)
        $batch = @($sec) + @($net)
        Write-Host "    Found $($sec.Count) log events and $($net.Count) network connections." -ForegroundColor Gray
        Send-HsocBatch -Batch $batch
    }
    "Start" {
        Write-Host "[*] Starting streaming loop (Interval: ${IntervalSeconds}s). Press Ctrl+C to stop." -ForegroundColor Green
        Test-HsocConnection | Out-Null
        while ($true) {
            $sec = Get-WindowsSecurityTelemetry -Limit ($MaxEvents / 2)
            $net = Get-WindowsNetworkTelemetry -Limit ($MaxEvents / 2)
            $batch = @($sec) + @($net)
            Send-HsocBatch -Batch $batch
            Start-Sleep -Seconds $IntervalSeconds
        }
    }
}
