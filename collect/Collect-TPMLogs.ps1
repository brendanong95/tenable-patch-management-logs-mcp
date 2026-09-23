<#
.SYNOPSIS
  Collect Tenable Patch Management logs from one or more Windows devices into a bundle
  that tenable-patch-management-logs-mcp reads directly (one folder per device).

.DESCRIPTION
  For each device it copies, read-only:
    %ADAPTIVACLIENT%\logs        -> <DEVICE>\PatchClient\logs
    %windir%\AdaptivaSetupLogs   -> <DEVICE>\AdaptivaSetupLogs
    %ADAPTIVASERVER%\logs        -> <DEVICE>\PatchServer\logs   (only with -IncludeServer; on-prem servers)
  plus the Client Validator results stored under HKLM\SOFTWARE\Adaptiva\client
  (check.* values) as ClientValidatorResults.txt.

  Logs are copied with shared read access because the TPM service keeps them open. On
  the target, only a temporary staging folder is created and it is removed afterwards.

  SaaS server logs cannot be collected this way: download them from the Admin Portal
  (gear icon > Logs > Download All Server Logs).

.EXAMPLE
  .\Collect-TPMLogs.ps1
  Collects this machine's client logs.

.EXAMPLE
  .\Collect-TPMLogs.ps1 -ComputerName WS-BAD07, WS-GOOD01 -Days 3
  Collects the last 3 days of logs from two devices over PowerShell remoting (WinRM).
  Include a healthy device so compare_devices has something to compare against.

.EXAMPLE
  .\Collect-TPMLogs.ps1 -ComputerName TPM01 -IncludeServer -Credential (Get-Credential)
  Collects client and server logs from an on-prem TPM server.

.NOTES
  Remote collection needs PowerShell remoting and local administrator rights on the targets.
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName = @($env:COMPUTERNAME),
    [string]$Destination = (Join-Path (Get-Location) ("TPM-Logs-" + (Get-Date -Format 'yyyyMMdd-HHmm'))),
    [ValidateRange(0, 3650)]
    [int]$Days = 0,
    [switch]$IncludeServer,
    [switch]$NoZip,
    [pscredential]$Credential
)

$ErrorActionPreference = 'Stop'

# Runs on the target: stages copies of the logs in %TEMP% and zips them.
$collector = {
    param([int]$Days, [bool]$IncludeServer)
    $ErrorActionPreference = 'Continue'
    $stage = Join-Path $env:TEMP ('tpmlogs_' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    $cutoff = if ($Days -gt 0) { (Get-Date).AddDays(-$Days) } else { [datetime]::MinValue }
    $notes = New-Object System.Collections.Generic.List[string]

    function Copy-LogTree([string]$From, [string]$To) {
        if (-not $From -or -not (Test-Path -LiteralPath $From)) { return "not found: $From" }
        $root = (Resolve-Path -LiteralPath $From).Path.TrimEnd('\')
        $copied = 0
        $failed = 0
        Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $cutoff -or $_.Name -eq 'revision.properties' } |
            ForEach-Object {
                $target = Join-Path $To $_.FullName.Substring($root.Length).TrimStart('\')
                New-Item -ItemType Directory -Path (Split-Path $target) -Force | Out-Null
                try {
                    # The service keeps its logs open: read with shared access.
                    $in = [IO.File]::Open($_.FullName, 'Open', 'Read', 'ReadWrite, Delete')
                    try {
                        $out = [IO.File]::Create($target)
                        try { $in.CopyTo($out) } finally { $out.Dispose() }
                    } finally { $in.Dispose() }
                    (Get-Item -LiteralPath $target).LastWriteTime = $_.LastWriteTime
                    $copied++
                } catch { $failed++ }
            }
        return "copied $copied file(s) from $From" + $(if ($failed) { " ($failed could not be read)" } else { '' })
    }

    $client = [Environment]::GetEnvironmentVariable('ADAPTIVACLIENT', 'Machine')
    if (-not $client) { $client = 'C:\Program Files\Tenable\PatchClient' }
    $notes.Add((Copy-LogTree (Join-Path $client 'logs') (Join-Path $stage 'PatchClient\logs')))
    $notes.Add((Copy-LogTree (Join-Path $env:windir 'AdaptivaSetupLogs') (Join-Path $stage 'AdaptivaSetupLogs')))

    if ($IncludeServer) {
        $server = [Environment]::GetEnvironmentVariable('ADAPTIVASERVER', 'Machine')
        if (-not $server) { $server = 'C:\Program Files\Tenable\PatchServer' }
        $notes.Add((Copy-LogTree (Join-Path $server 'logs') (Join-Path $stage 'PatchServer\logs')))
    }

    $validatorKey = 'HKLM:\SOFTWARE\Adaptiva\client'
    if (Test-Path $validatorKey) {
        $values = Get-ItemProperty -Path $validatorKey
        $lines = $values.PSObject.Properties |
            Where-Object { $_.Name -like 'check.*' } |
            ForEach-Object { '{0} = {1}' -f $_.Name, $_.Value }
        if ($lines) {
            $lines | Set-Content -Path (Join-Path $stage 'PatchClient\logs\ClientValidatorResults.txt') -Encoding UTF8
            $notes.Add("exported $(@($lines).Count) Client Validator result(s)")
        }
    }

    $notes | Set-Content -Path (Join-Path $stage 'collection-notes.txt') -Encoding UTF8
    $zip = "$stage.zip"
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip -Force
    Remove-Item -LiteralPath $stage -Recurse -Force
    [pscustomobject]@{ Zip = $zip; Notes = @($notes) }
}

New-Item -ItemType Directory -Path $Destination -Force | Out-Null
$local = @($env:COMPUTERNAME, 'localhost', '.', '127.0.0.1')

foreach ($computer in $ComputerName) {
    Write-Host "== $computer" -ForegroundColor Cyan
    $deviceFolder = Join-Path $Destination $computer
    try {
        if ($local -contains $computer) {
            $result = & $collector $Days $IncludeServer.IsPresent
            Expand-Archive -LiteralPath $result.Zip -DestinationPath $deviceFolder -Force
            Remove-Item -LiteralPath $result.Zip -Force
        } else {
            $sessionArgs = @{ ComputerName = $computer }
            if ($Credential) { $sessionArgs.Credential = $Credential }
            $session = New-PSSession @sessionArgs
            try {
                $result = Invoke-Command -Session $session -ScriptBlock $collector -ArgumentList $Days, $IncludeServer.IsPresent
                $localZip = Join-Path $Destination "$computer.zip"
                Copy-Item -FromSession $session -Path $result.Zip -Destination $localZip -Force
                Invoke-Command -Session $session -ScriptBlock { param($path) Remove-Item -LiteralPath $path -Force } -ArgumentList $result.Zip
                Expand-Archive -LiteralPath $localZip -DestinationPath $deviceFolder -Force
                Remove-Item -LiteralPath $localZip -Force
            } finally {
                Remove-PSSession $session
            }
        }
        $result.Notes | ForEach-Object { Write-Host "   $_" }
    } catch {
        Write-Warning "$computer failed: $($_.Exception.Message)"
        "FAILED: $($_.Exception.Message)" | Set-Content -Path (Join-Path $Destination "$computer.FAILED.txt") -Encoding UTF8
    }
}

if ($NoZip) {
    Write-Host "`nFolder: $Destination" -ForegroundColor Green
} else {
    $bundle = "$Destination.zip"
    Compress-Archive -Path $Destination -DestinationPath $bundle -Force
    Write-Host "`nBundle: $bundle" -ForegroundColor Green
    Write-Host "Register it with add_log_source, e.g. add_log_source(name='clients', path='$bundle')."
}
