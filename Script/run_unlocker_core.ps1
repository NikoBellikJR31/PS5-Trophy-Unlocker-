param(
    [string]$PS5 = "192.168.1.94",
    [int]$DebugPort = 744,
    [int[]]$FtpPorts = @(2121),
    [ValidateSet("all", "id", "range", "wave", "list")]
    [string]$Mode = "wave",
    [int]$Id = 1,
    [string]$Ids = "",
    [string]$Range = "0-4",
    [int]$Start = 0,
    [int]$Wave = 5,
    [int]$DelaySeconds = 35,
    [int]$ListDelaySeconds = 10,
    [int]$PayloadLogPort = 9021,
    [int]$PayloadLogSeconds = 20,
    [string]$Elf = "",
    [switch]$NoPatch,
    [switch]$DebugReport
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$PackageRoot = Split-Path -Parent $Root
if ([string]::IsNullOrWhiteSpace($Elf)) {
    $Elf = Join-Path $PackageRoot "PS5 Unlocker.elf"
} elseif (-not [System.IO.Path]::IsPathRooted($Elf)) {
    $Elf = Join-Path $PackageRoot $Elf
}
$Config = Join-Path $env:TEMP "trophy_unlocker_config.txt"
$LocalPython = Join-Path $Root "python\python.exe"
$BundledPython = Join-Path $env:USERPROFILE ".cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
$PythonArgs = @()
if (Test-Path -LiteralPath $LocalPython) {
    $Python = $LocalPython
} elseif (Test-Path -LiteralPath $BundledPython) {
    $Python = $BundledPython
} else {
    $PythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($PythonCmd) {
        $Python = $PythonCmd.Source
    } else {
        $PyCmd = Get-Command py.exe -ErrorAction SilentlyContinue
        if ($PyCmd) {
            $Python = $PyCmd.Source
            $PythonArgs = @("-3")
        } else {
            throw "Python introuvable. Installe Python 3 ou modifie la variable `$Python dans ce script."
        }
    }
}
$Deps = Join-Path $Root "pydeps"
$PatchScript = Join-Path $Root "ps5debug_shellcore_gate_602.py"
$Helper = Join-Path $Root "unlock_running_game.py"
$DebugDir = Join-Path $PackageRoot "debug_logs"
$RunId = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportLines = New-Object "System.Collections.Generic.List[string]"
$ExpectedPayloadSelection = ""

function Add-ReportLine {
    param([string]$Line)
    $script:ReportLines.Add($Line) | Out-Null
}

function Write-Status {
    param([string]$Line)
    Write-Host $Line
    Add-ReportLine $Line
}

function New-ReportHeader {
    param([string]$Status)

    @(
        "TROPHY UNLOCKER PS5 ELF",
        ("Status: " + $Status),
        ("Date: " + (Get-Date -Format "yyyy-MM-dd HH:mm:ss")),
        ("PS5: " + $PS5),
        ("DebugPort: " + $DebugPort),
        ("FtpPorts: " + ($FtpPorts -join ",")),
        ("Mode: " + $Mode),
        ("Id: " + $Id),
        ("Ids: " + $Ids),
        ("Range: " + $Range),
        ("Start: " + $Start),
        ("Wave: " + $Wave),
        ("PayloadLogPort: " + $PayloadLogPort),
        ("PayloadLogSeconds: " + $PayloadLogSeconds),
        ("NoPatch: " + [bool]$NoPatch),
        ("DebugReport: " + [bool]$DebugReport),
        ("ELF: " + $Elf),
        ("Python: " + $Python + " " + ($PythonArgs -join " ")),
        ("PYTHONPATH: " + $env:PYTHONPATH),
        ""
    )
}

function Invoke-LoggedCommand {
    param(
        [string]$Label,
        [scriptblock]$Command,
        [switch]$AllowNonZero
    )

    Add-ReportLine ""
    Add-ReportLine "---- $Label ----"
    $Output = & $Command 2>&1
    $Code = $LASTEXITCODE
    if ($null -eq $Code) { $Code = 0 }

    foreach ($Item in @($Output)) {
        $Text = $Item.ToString()
        Write-Host $Text
        Add-ReportLine $Text
    }
    Add-ReportLine "ExitCode: $Code"

    if (($Code -ne 0) -and -not $AllowNonZero) {
        throw "$Label a echoue avec code $Code"
    }

    [pscustomobject]@{
        Code = $Code
        Output = @($Output)
    }
}

function Get-SelectionBounds {
    param([string]$Selection)

    if ([string]::IsNullOrWhiteSpace($Selection)) {
        return $null
    }

    if ($Selection -match '^(\d+)-(\d+)$') {
        [pscustomobject]@{
            Start = [int]$Matches[1]
            End = [int]$Matches[2]
        }
    } elseif ($Selection -match '^\d+$') {
        [pscustomobject]@{
            Start = [int]$Selection
            End = [int]$Selection
        }
    } else {
        $null
    }
}

function Capture-PayloadTcpLog {
    param([string]$Label)

    if (-not $DebugReport) { return }

    Add-ReportLine ""
    Add-ReportLine "---- payload tcp log $Label ----"
    Write-Host "[payload-log] capture PC ${PS5}:${PayloadLogPort} pendant ${PayloadLogSeconds}s"
    Add-ReportLine "[payload-log] capture PC ${PS5}:${PayloadLogPort} pendant ${PayloadLogSeconds}s"
    $PayloadLines = New-Object "System.Collections.Generic.List[string]"

    $Client = $null
    try {
        $OpenDeadline = [DateTime]::UtcNow.AddSeconds($PayloadLogSeconds)
        Write-Host "[payload-log] attente ouverture port ${PayloadLogPort}..."
        Add-ReportLine "[payload-log] attente ouverture port ${PayloadLogPort}..."

        while ([DateTime]::UtcNow -lt $OpenDeadline -and $null -eq $Client) {
            $TryClient = [System.Net.Sockets.TcpClient]::new()
            try {
                $Async = $TryClient.BeginConnect($PS5, $PayloadLogPort, $null, $null)
                if ($Async.AsyncWaitHandle.WaitOne(500, $false)) {
                    $TryClient.EndConnect($Async)
                    $Client = $TryClient
                    break
                }
            } catch {
                # Port pas encore ouvert: le ELF debug peut etre encore en demarrage.
            }

            if ($null -eq $Client) {
                $TryClient.Close()
                Start-Sleep -Milliseconds 250
            }
        }

        if ($null -eq $Client) {
            Add-ReportLine "[payload-log] port ${PayloadLogPort} jamais ouvert pendant ${PayloadLogSeconds}s"
            Write-Host "[payload-log] port ${PayloadLogPort} jamais ouvert pendant ${PayloadLogSeconds}s"
            return
        }

        Write-Host "[payload-log] connecte sur ${PayloadLogPort}"
        Add-ReportLine "[payload-log] connecte sur ${PayloadLogPort}"
        $Stream = $Client.GetStream()
        $Stream.ReadTimeout = 1000
        $Buffer = New-Object byte[] 4096
        $Deadline = [DateTime]::UtcNow.AddSeconds($PayloadLogSeconds)
        $CapturedBytes = 0

        while ([DateTime]::UtcNow -lt $Deadline) {
            if ($Stream.DataAvailable) {
                $Read = $Stream.Read($Buffer, 0, $Buffer.Length)
                if ($Read -le 0) { break }
                $CapturedBytes += $Read
                $Text = [System.Text.Encoding]::UTF8.GetString($Buffer, 0, $Read)
                $Text = $Text -replace "`0", ""
                foreach ($Line in ($Text -split "`r?`n")) {
                    if ([string]::IsNullOrWhiteSpace($Line)) { continue }
                    Write-Host $Line
                    Add-ReportLine $Line
                    $PayloadLines.Add($Line) | Out-Null
                }
            } else {
                Start-Sleep -Milliseconds 100
            }
        }

        if ($CapturedBytes -eq 0) {
            Add-ReportLine "[payload-log] connecte mais aucun log recu sur ${PayloadLogPort} pendant la capture"
            Add-ReportLine "[payload-log] injection OK possible, mais le payload ne renvoie pas forcement de log TCP"
            Write-Host "[payload-log] connecte mais aucun log recu sur ${PayloadLogPort} pendant la capture"
            Write-Host "[payload-log] injection OK possible, mais le payload ne renvoie pas forcement de log TCP"
        } else {
            Add-ReportLine "[payload-log] bytes recus: $CapturedBytes"
        }
    } catch {
        Add-ReportLine ("[payload-log] indisponible: " + $_.Exception.Message)
        Write-Host ("[payload-log] indisponible: " + $_.Exception.Message)
    } finally {
        $Client.Close()
    }

    if (-not [string]::IsNullOrWhiteSpace($script:ExpectedPayloadSelection)) {
        $SeenSelection = ""
        $SeenTrophyCount = 0
        foreach ($Line in $PayloadLines) {
            if ($Line -match "V90 config file .* -> '([^']+)'") {
                $SeenSelection = $Matches[1]
            } elseif ($Line -match "trophy_unlocker: config \S+ -> (\S+)") {
                $SeenSelection = $Matches[1]
            }

            if ($Line -match "Trophy2 info .* trophies=(\d+)") {
                $SeenTrophyCount = [int]$Matches[1]
            } elseif ($Line -match "GetGameInfo .* num=(\d+)") {
                $CandidateCount = [int]$Matches[1]
                if ($CandidateCount -gt $SeenTrophyCount) {
                    $SeenTrophyCount = $CandidateCount
                }
            }
        }

        $Bounds = Get-SelectionBounds -Selection $script:ExpectedPayloadSelection
        if ($null -ne $Bounds -and $SeenTrophyCount -gt 0 -and $Bounds.End -ge $SeenTrophyCount) {
            $MaxId = $SeenTrophyCount - 1
            Add-ReportLine "[payload-log] ERROR: selection demandee=$($script:ExpectedPayloadSelection) hors plage, trophy_count=$SeenTrophyCount max_id=$MaxId"
            throw "Selection hors plage: demande=$($script:ExpectedPayloadSelection), max_id=$MaxId"
        }

        if ([string]::IsNullOrWhiteSpace($SeenSelection)) {
            Add-ReportLine "[payload-log] WARNING: selection payload non vue dans le log TCP"
        } elseif ($SeenSelection -ne $script:ExpectedPayloadSelection) {
            Add-ReportLine "[payload-log] ERROR: selection demandee=$($script:ExpectedPayloadSelection) selection payload=$SeenSelection"
            throw "Mismatch config payload: demande=$($script:ExpectedPayloadSelection) payload=$SeenSelection"
        } else {
            Add-ReportLine "[payload-log] selection OK: $SeenSelection"
        }
    }
}

function Save-ErrorReport {
    param([object]$ErrorRecord)

    Write-Host ("[error] " + $ErrorRecord.Exception.Message)
    if (-not $DebugReport) { return }

    New-Item -ItemType Directory -Force -Path $DebugDir | Out-Null
    $Path = Join-Path $DebugDir ("error_" + $RunId + ".txt")
    $Header = @(New-ReportHeader -Status "ERROR") + @(
        ("ERROR: " + $ErrorRecord.Exception.Message),
        ""
    )

    $Body = @($Header) + @($script:ReportLines)
    [System.IO.File]::WriteAllLines($Path, [string[]]$Body, [System.Text.Encoding]::ASCII)
    Write-Host "[rapport] Erreur enregistree cote PC: $Path"
}

function Save-DebugReport {
    if (-not $DebugReport) { return }

    New-Item -ItemType Directory -Force -Path $DebugDir | Out-Null
    $Path = Join-Path $DebugDir ("ok_" + $RunId + ".txt")
    $Header = @(New-ReportHeader -Status "OK")
    $Body = @($Header) + @($script:ReportLines)
    [System.IO.File]::WriteAllLines($Path, [string[]]$Body, [System.Text.Encoding]::ASCII)
    Write-Host "[rapport] Rapport detaille OK cote PC: $Path"
}

trap {
    Save-ErrorReport $_
    exit 1
}

if (-not (Test-Path -LiteralPath $Elf)) { throw "ELF introuvable: $Elf" }
if (-not (Test-Path -LiteralPath $Helper)) { throw "Helper introuvable: $Helper" }
if (-not (Test-Path -LiteralPath $Deps)) { throw "Deps introuvables: $Deps" }

function Set-UnlockerConfig {
    param(
        [string]$SelectedMode,
        [int]$SelectedId,
        [string]$SelectedRange,
        [int]$SelectedStart,
        [int]$SelectedWave
    )

    switch ($SelectedMode) {
        "all" {
            Set-Content -LiteralPath $Config -Encoding ASCII -NoNewline -Value "mode=all`n"
        }
        "id" {
            Set-Content -LiteralPath $Config -Encoding ASCII -NoNewline -Value "mode=id`nid=$SelectedId`n"
        }
        "range" {
            Set-Content -LiteralPath $Config -Encoding ASCII -NoNewline -Value "mode=range`nrange=$SelectedRange`n"
        }
        "wave" {
            Set-Content -LiteralPath $Config -Encoding ASCII -NoNewline -Value "mode=wave`nstart=$SelectedStart`nwave=$SelectedWave`n"
        }
    }

    switch ($SelectedMode) {
        "all" {
            $script:ExpectedPayloadSelection = ""
        }
        "id" {
            $script:ExpectedPayloadSelection = "$SelectedId"
        }
        "range" {
            $script:ExpectedPayloadSelection = $SelectedRange
        }
        "wave" {
            $script:ExpectedPayloadSelection = "$SelectedStart-$($SelectedStart + $SelectedWave - 1)"
        }
    }

    Add-ReportLine ""
    Add-ReportLine "---- local config prepared ----"
    Get-Content -LiteralPath $Config | ForEach-Object { Add-ReportLine $_ }
    if (-not [string]::IsNullOrWhiteSpace($script:ExpectedPayloadSelection)) {
        Add-ReportLine "expected_payload_selection=$($script:ExpectedPayloadSelection)"
    }
}

function Send-UnlockerConfig {
    $Uploaded = $false
    foreach ($Port in $FtpPorts) {
        Write-Status "[config] upload ftp://${PS5}:$Port/data/trophy_unlocker_config.txt"
        $Result = Invoke-LoggedCommand -Label "ftp upload config port $Port" -AllowNonZero -Command {
            & curl.exe --silent --show-error --connect-timeout 5 --max-time 15 --ftp-pasv --upload-file $Config "ftp://${PS5}:$Port/data/trophy_unlocker_config.txt"
        }
        if ($Result.Code -eq 0) {
            $Uploaded = $true
            if ($DebugReport) {
                Invoke-LoggedCommand -Label "ftp verify remote config port $Port" -AllowNonZero -Command {
                    & curl.exe --silent --show-error --connect-timeout 5 --max-time 15 --ftp-pasv "ftp://${PS5}:$Port/data/trophy_unlocker_config.txt"
                } | Out-Null
            }
            break
        }
    }
    if (-not $Uploaded) {
        throw "Config non envoyee par FTP."
    }
}

function Invoke-Unlocker {
    param([string]$Label)

    Write-Status "[inject] $Label"
    $InjectResult = Invoke-LoggedCommand -Label "inject $Label" -AllowNonZero -Command {
        & $Python @PythonArgs $Helper $PS5 --port $DebugPort --elf $Elf --ftp-ports ($FtpPorts -join ",") --npcomm-name trophy_unlocker_npcomm.txt --count-name trophy_unlocker_count.txt --npsig-name trophy_unlocker_npsig.bin --platform-name trophy_unlocker_platform.txt
    }
    Capture-PayloadTcpLog -Label $Label
    if ($InjectResult.Code -ne 0) {
        throw "Injection ELF echouee avec code $($InjectResult.Code)"
    }
}

$env:PYTHONPATH = $Deps

$DetectResult = Invoke-LoggedCommand -Label "detect running game" -Command {
    & $Python @PythonArgs $Helper $PS5 --port $DebugPort --elf $Elf --list
}
$DetectOutput = @($DetectResult.Output | ForEach-Object { $_.ToString() })

$TargetLine = $DetectOutput | Where-Object { $_ -match '^\s+pid=.*name=eboot\.bin' } | Select-Object -First 1
if (-not $TargetLine) {
    $TargetLine = $DetectOutput | Where-Object { $_ -match '(CUSA|PPSA)\d{5}' } | Select-Object -First 1
}

$AutoPlatform = "unknown"
if ($TargetLine -match 'CUSA\d{5}') {
    $AutoPlatform = "ps4"
} elseif ($TargetLine -match 'PPSA\d{5}') {
    $AutoPlatform = "ps5"
}

Write-Status "[auto] platform=$AutoPlatform target=$TargetLine"

if ($NoPatch) {
    Write-Status "[auto] patch FW602 skip: -NoPatch force"
} elseif ($AutoPlatform -eq "ps4") {
    Write-Status "[auto] patch FW602 skip: jeu PS4/CUSA detecte"
} elseif ($AutoPlatform -eq "ps5") {
    Write-Status "[fw602] PS5/PPSA detecte: patch RAM seulement si signature FW 6.02 valide"
    $PatchExtraArgs = @()
    if ($DebugReport) { $PatchExtraArgs += "--debug-diff" }
    $PatchResult = Invoke-LoggedCommand -Label "fw602 patch auto" -AllowNonZero -Command {
        & $Python @PythonArgs $PatchScript $PS5 --port $DebugPort --mode patch --force @PatchExtraArgs
    }
    if ($PatchResult.Code -ne 0) {
        Write-Status "[fw602] auto patch failed, retry pid=56 avec debug detaille"
        $RetryPatchResult = Invoke-LoggedCommand -Label "fw602 patch pid=56 debug-diff" -AllowNonZero -Command {
            & $Python @PythonArgs $PatchScript $PS5 --port $DebugPort --mode patch --force --pid 56 --debug-diff
        }
        if ($RetryPatchResult.Code -ne 0) {
            Write-Status "[fw602] WARN: patch non applique."
            Write-Status "[fw602] Cause probable: signature FW differente, offsets non supportes ou ShellCore introuvable."
            Write-Status "[fw602] Continue quand meme: config + ELF seront envoyes."
            Write-Status "[fw602] Si rien ne pop, relance avec Debug rapport PC pour lire le detail."

            Add-ReportLine ""
            Add-ReportLine "---- fw602 patch skipped, continue injection ----"
            Add-ReportLine ("AutoPatchExitCode: " + $PatchResult.Code)
            Add-ReportLine ("RetryPatchExitCode: " + $RetryPatchResult.Code)
            Add-ReportLine "PatchStatus: non applique"
            Add-ReportLine "Action: injection continue sans patch FW602"
        }
    }
} else {
    Write-Status "[auto] STOP: aucun jeu CUSA/PPSA detecte."
    Write-Status "[auto] Lance un jeu puis relance le script. Aucun patch au hasard."
    throw "Aucun jeu CUSA/PPSA detecte"
}

if ($Mode -eq "list") {
    if ([string]::IsNullOrWhiteSpace($Ids)) {
        throw "Mode list: ajoute -Ids `"5,8,21`""
    }

    $ParsedIds = @()
    foreach ($Part in ($Ids -split "[,; ]+")) {
        if ([string]::IsNullOrWhiteSpace($Part)) { continue }
        $Value = 0
        if (-not [int]::TryParse($Part.Trim(), [ref]$Value) -or $Value -lt 0) {
            throw "ID invalide dans -Ids: $Part"
        }
        $ParsedIds += $Value
    }

    if ($ParsedIds.Count -eq 0) {
        throw "Mode list: aucun ID valide dans -Ids."
    }

    $OptimizedIds = @($ParsedIds | Sort-Object -Unique)
    $Groups = @()
    $GroupStart = $OptimizedIds[0]
    $GroupEnd = $OptimizedIds[0]
    for ($Index = 1; $Index -lt $OptimizedIds.Count; $Index++) {
        $CurrentId = $OptimizedIds[$Index]
        if ($CurrentId -eq ($GroupEnd + 1)) {
            $GroupEnd = $CurrentId
        } else {
            $Groups += [pscustomobject]@{ Start = $GroupStart; End = $GroupEnd }
            $GroupStart = $CurrentId
            $GroupEnd = $CurrentId
        }
    }
    $Groups += [pscustomobject]@{ Start = $GroupStart; End = $GroupEnd }

    $GroupLabels = @($Groups | ForEach-Object {
        if ($_.Start -eq $_.End) { "id=$($_.Start)" } else { "range=$($_.Start)-$($_.End)" }
    })

    Write-Status "[list] ids=$($ParsedIds -join ',')"
    Write-Status "[list] optimise=$($GroupLabels -join ' ; ')"
    if ($ParsedIds.Count -ne $OptimizedIds.Count) {
        Write-Status "[list] doublons retires pour reduire les injections"
    }

    for ($GroupIndex = 0; $GroupIndex -lt $Groups.Count; $GroupIndex++) {
        $Group = $Groups[$GroupIndex]
        if ($Group.Start -eq $Group.End) {
            $SelectedMode = "id"
            $SelectedId = $Group.Start
            $SelectedRange = $Range
            $Label = "mode=list id=$SelectedId"
        } else {
            $SelectedMode = "range"
            $SelectedId = 0
            $SelectedRange = "$($Group.Start)-$($Group.End)"
            $Label = "mode=list $SelectedRange"
        }

        Set-UnlockerConfig -SelectedMode $SelectedMode -SelectedId $SelectedId -SelectedRange $SelectedRange -SelectedStart $Start -SelectedWave $Wave
        Send-UnlockerConfig
        Invoke-Unlocker -Label $Label
        if ($GroupIndex -lt ($Groups.Count - 1)) {
            Start-Sleep -Seconds $ListDelaySeconds
        }
    }
    Write-Status "[done] Liste envoyee. Aucun ancien log /data/trophy_unlocker_log.txt n'est recupere. Rapport PC dans debug_logs."
    Save-DebugReport
    exit 0
}

Set-UnlockerConfig -SelectedMode $Mode -SelectedId $Id -SelectedRange $Range -SelectedStart $Start -SelectedWave $Wave
Send-UnlockerConfig
Invoke-Unlocker -Label "mode=$Mode id=$Id range=$Range start=$Start wave=$Wave"

Start-Sleep -Seconds $DelaySeconds
Write-Status "[done] ELF envoye. Aucun ancien log /data/trophy_unlocker_log.txt n'est recupere. Rapport PC dans debug_logs."
Save-DebugReport
exit 0
