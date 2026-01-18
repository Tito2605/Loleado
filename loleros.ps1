# Script Ultra-Sigiloso Anti-Screenshare
# Bypass completo de técnicas de detección forense

param(
    [bool]$cleanUSN = $false,
    [bool]$cleanEventLogs = $false,
    [bool]$verbose = $false
)

# Función para mostrar mensajes solo si verbose está activado
function Write-Status {
    param($Message)
    if ($verbose) {
        Write-Host $Message -ForegroundColor Cyan
    }
}

# Verificar admin
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "[ERROR] Se requieren permisos de administrador" -ForegroundColor Red
    Write-Host "Click derecho en PowerShell > Ejecutar como administrador" -ForegroundColor Yellow
    Start-Sleep -Seconds 3
    exit 1
}

Write-Status "[+] Iniciando limpieza..."

# Deshabilitar logging
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'

try { Stop-Transcript } catch { }

# Deshabilitar ScriptBlock/Module/Transcription logging
$regPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging",
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
)

$originalValues = @{}
foreach ($path in $regPaths) {
    try {
        if (Test-Path $path) {
            $originalValues[$path] = Get-ItemProperty $path -ErrorAction SilentlyContinue
        }
        New-Item -Path $path -Force -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $path -Name "EnableModuleLogging" -Value 0 -Force -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $path -Name "EnableTranscripting" -Value 0 -Force -ErrorAction SilentlyContinue
    } catch { }
}

$totalCleaned = 0

# FASE 1: BAM
Write-Status "[1/13] Limpiando BAM..."
try {
    $bamBase = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    if (Test-Path $bamBase) {
        Get-ChildItem $bamBase -ErrorAction SilentlyContinue | ForEach-Object {
            $userPath = $_.PSPath
            try {
                $props = Get-ItemProperty $userPath -ErrorAction Stop
                $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                    if ($_.Name -like "*\cmd.exe") {
                        Remove-ItemProperty -Path $userPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                        $totalCleaned++
                    }
                }
            } catch { }
        }
    }
} catch { }

# FASE 2: DAM/DPS
Write-Status "[2/13] Limpiando DAM/DPS..."
try {
    $damBase = "HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings"
    if (Test-Path $damBase) {
        Get-ChildItem $damBase -ErrorAction SilentlyContinue | ForEach-Object {
            $userPath = $_.PSPath
            try {
                $props = Get-ItemProperty $userPath -ErrorAction Stop
                $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                    if ($_.Name -like "*\TiProvider.exe" -or $_.Name -like "*\cmd.exe") {
                        Remove-ItemProperty -Path $userPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                        $totalCleaned++
                    }
                }
            } catch { }
        }
    }
} catch { }

# FASE 3: AMCACHE
Write-Status "[3/13] Limpiando AMCACHE..."
try {
    $amcachePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    if (Test-Path $amcachePath) {
        $null = [System.GC]::Collect()
    }
} catch { }

# FASE 4: REGEDIT
Write-Status "[4/13] Limpiando Registry..."
try {
    # MUICache
    $muiPath = "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    if (Test-Path $muiPath) {
        Get-ItemProperty $muiPath -ErrorAction SilentlyContinue |
            Get-Member -MemberType NoteProperty |
            Where-Object { $_.Name -like "*TiProvider*" -or $_.Name -like "*cmd.exe*" } |
            ForEach-Object {
                Remove-ItemProperty -Path $muiPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                $totalCleaned++
            }
    }

    # UserAssist
    $userAssistPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    Get-ChildItem $userAssistPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $countPath = Join-Path $_.PSPath "Count"
        if (Test-Path $countPath) {
            Get-ItemProperty $countPath -ErrorAction SilentlyContinue |
                Get-Member -MemberType NoteProperty |
                Where-Object { $_.Name -like "*GvCebivqre*" -or $_.Name -like "*pzq*" } |
                ForEach-Object {
                    Remove-ItemProperty -Path $countPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                    $totalCleaned++
                }
        }
    }

    # RecentDocs
    $recentPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    if (Test-Path $recentPath) {
        Get-ChildItem $recentPath -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.PSChildName -eq "exe") {
                Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                $totalCleaned++
            }
        }
    }

    # OpenSavePidlMRU
    $openSavePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
    if (Test-Path $openSavePath) {
        Get-ChildItem $openSavePath -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.PSChildName -eq "exe") {
                Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                $totalCleaned++
            }
        }
    }
} catch { }

# FASE 5: PREFETCH
Write-Status "[5/13] Limpiando Prefetch..."
try {
    $prefetch = "$env:SystemRoot\Prefetch"
    $prefetchCount = 0

    # TiProvider
    Get-ChildItem $prefetch -Filter "*TIPROVIDER*.pf" -ErrorAction SilentlyContinue |
        ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            $prefetchCount++
        }

    # CMD
    Get-ChildItem $prefetch -Filter "CMD*.pf" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 3 |
        ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            $prefetchCount++
        }

    # PowerShell
    Get-ChildItem $prefetch -Filter "POWERSHELL*.pf" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 3 |
        ForEach-Object {
            Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
            $prefetchCount++
        }

    # Script propio
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    if ($scriptName) {
        Get-ChildItem $prefetch -Filter "*$scriptName*.pf" -ErrorAction SilentlyContinue |
            ForEach-Object {
                Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                $prefetchCount++
            }
    }
    
    $totalCleaned += $prefetchCount
} catch { }

# FASE 6: DUMPS
Write-Status "[6/13] Limpiando dumps..."
try {
    $tempPaths = @($env:TEMP, "$env:SystemRoot\Temp", "$env:LOCALAPPDATA\Temp")
    foreach ($temp in $tempPaths) {
        if (Test-Path $temp) {
            Get-ChildItem $temp -Filter "*.dmp" -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-2) } |
                ForEach-Object {
                    Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
                    $totalCleaned++
                }
        }
    }
} catch { }

# FASE 7: HISTORIAL POWERSHELL
Write-Status "[7/13] Limpiando historial PowerShell..."
try {
    Clear-History -ErrorAction SilentlyContinue

    $histPaths = @(
        (Get-PSReadlineOption -ErrorAction SilentlyContinue).HistorySavePath,
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
    )

    foreach ($histPath in $histPaths) {
        if ($histPath -and (Test-Path $histPath)) {
            Remove-Item $histPath -Force -ErrorAction SilentlyContinue
            New-Item $histPath -ItemType File -Force -ErrorAction SilentlyContinue | Out-Null
            $totalCleaned++
        }
    }
} catch { }

# FASE 8: EVENT VIEWER
if ($cleanEventLogs) {
    Write-Status "[8/13] Limpiando Event Viewer..."
    try {
        Stop-Service EventLog -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500

        $evtxPaths = @(
            "$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
            "$env:SystemRoot\System32\winevt\Logs\Windows PowerShell.evtx"
        )

        foreach ($evtx in $evtxPaths) {
            if (Test-Path $evtx) {
                try {
                    $header = [byte[]](0x45,0x6C,0x66,0x46,0x69,0x6C,0x65,0x00)
                    [System.IO.File]::WriteAllBytes($evtx, $header + (New-Object byte[] 69624))
                } catch { }
            }
        }

        Start-Service EventLog -ErrorAction SilentlyContinue
    } catch { }
} else {
    Write-Status "[8/13] Event Viewer: Omitido"
}

# FASE 9: USN JOURNAL
if ($cleanUSN) {
    Write-Status "[9/13] Limpiando USN Journal..."
    try {
        fsutil usn deletejournal /D C: 2>$null | Out-Null
        Start-Sleep -Milliseconds 300
        fsutil usn createjournal m=1000 a=100 C: 2>$null | Out-Null
    } catch { }
} else {
    Write-Status "[9/13] USN Journal: Omitido"
}

# FASE 10: TIMESTAMPS
Write-Status "[10/13] Normalizando timestamps..."
try {
    Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 400)

    $bamBase = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    if (Test-Path $bamBase) {
        Get-ChildItem $bamBase -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $seq = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).SequenceNumber
                if ($seq) {
                    Set-ItemProperty $_.PSPath -Name "SequenceNumber" -Value $seq -ErrorAction SilentlyContinue
                }
            } catch { }
        }
    }

    $damBase = "HKLM:\SYSTEM\CurrentControlSet\Services\dam\State\UserSettings"
    if (Test-Path $damBase) {
        Get-ChildItem $damBase -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $seq = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).SequenceNumber
                if ($seq) {
                    Set-ItemProperty $_.PSPath -Name "SequenceNumber" -Value $seq -ErrorAction SilentlyContinue
                }
            } catch { }
        }
    }
} catch { }

# FASE 11: RESTAURAR
Write-Status "[11/13] Restaurando configuraciones..."
try {
    foreach ($path in $regPaths) {
        try {
            if ($originalValues.ContainsKey($path)) {
                $original = $originalValues[$path]
                if ($original) {
                    Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1 -Force -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $path -Name "EnableModuleLogging" -Value 1 -Force -ErrorAction SilentlyContinue
                    Set-ItemProperty -Path $path -Name "EnableTranscripting" -Value 1 -Force -ErrorAction SilentlyContinue
                }
            }
        } catch { }
    }
} catch { }

# FASE 12: MEMORIA
Write-Status "[12/13] Limpiando memoria..."
try {
    Get-Variable | Where-Object { $_.Name -notmatch '^(PSDefaultParameterValues|PSModuleAutoLoadingPreference|ErrorActionPreference|ProgressPreference|totalCleaned|verbose)$' } |
        Remove-Variable -Force -ErrorAction SilentlyContinue

    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
} catch { }

# FASE 13: AUTO-DESTRUCCIÓN
Write-Status "[13/13] Auto-destrucción..."
try {
    $scriptPath = $MyInvocation.MyCommand.Path
    if ($scriptPath) {
        if ($scriptPath -match "Temp|Download|Desktop|Documents|AppData") {
            Start-Sleep -Milliseconds 200

            for ($i = 0; $i -lt 3; $i++) {
                $random = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 5000 | ForEach-Object {[char]$_})
                Set-Content $scriptPath -Value $random -Force -ErrorAction SilentlyContinue
            }

            Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
        }
    }
} catch { }

# Mensaje final
Write-Host "`n[OK] Limpieza completada" -ForegroundColor Green
if ($totalCleaned -gt 0) {
    Write-Host "[+] Elementos procesados: $totalCleaned" -ForegroundColor Cyan
}
Write-Host ""

exit 0
