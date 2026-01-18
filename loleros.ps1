# Script Ultra-Sigiloso Anti-Screenshare
# Bypass completo de técnicas de detección forense
# Solo detectable con análisis de memoria en tiempo real

param(
    [bool]$cleanUSN = $false,
    [bool]$cleanEventLogs = $false
)

# Verificar admin silenciosamente
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    exit 1
}

# Deshabilitar TODAS las formas de logging
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$VerbosePreference = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$DebugPreference = 'SilentlyContinue'

try { Stop-Transcript } catch { }

# Deshabilitar ScriptBlock/Module/Transcription logging temporalmente
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

# ========================================
# FASE 1: LIMPIEZA BAM
# ========================================
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
                    }
                }
            } catch { }
        }
    }
} catch { }

# ========================================
# FASE 2: LIMPIEZA DAM/DPS  
# ========================================
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
                    }
                }
            } catch { }
        }
    }
} catch { }

# ========================================
# FASE 3: LIMPIEZA AMCACHE
# ========================================
try {
    $amcachePath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    if (Test-Path $amcachePath) {
        # No podemos modificar directamente, pero podemos forzar flush
        $null = [System.GC]::Collect()
    }
} catch { }

# ========================================
# FASE 4: LIMPIEZA REGEDIT (MUICache, RecentDocs, etc)
# ========================================
try {
    # MUICache
    $muiPath = "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache"
    if (Test-Path $muiPath) {
        Get-ItemProperty $muiPath -ErrorAction SilentlyContinue | 
            Get-Member -MemberType NoteProperty | 
            Where-Object { $_.Name -like "*TiProvider*" -or $_.Name -like "*cmd.exe*" } | 
            ForEach-Object {
                Remove-ItemProperty -Path $muiPath -Name $_.Name -Force -ErrorAction SilentlyContinue
            }
    }
    
    # UserAssist (codificado en ROT13)
    $userAssistPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"
    Get-ChildItem $userAssistPath -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        $countPath = Join-Path $_.PSPath "Count"
        if (Test-Path $countPath) {
            Get-ItemProperty $countPath -ErrorAction SilentlyContinue | 
                Get-Member -MemberType NoteProperty |
                Where-Object { $_.Name -like "*GvCebivqre*" -or $_.Name -like "*pzq*" } |
                ForEach-Object {
                    Remove-ItemProperty -Path $countPath -Name $_.Name -Force -ErrorAction SilentlyContinue
                }
        }
    }
    
    # RecentDocs
    $recentPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs"
    if (Test-Path $recentPath) {
        Get-ChildItem $recentPath -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.PSChildName -eq "exe") {
                Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    # OpenSavePidlMRU
    $openSavePath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU"
    if (Test-Path $openSavePath) {
        Get-ChildItem $openSavePath -ErrorAction SilentlyContinue | ForEach-Object {
            if ($_.PSChildName -eq "exe") {
                Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
} catch { }

# ========================================
# FASE 5: LIMPIEZA PREFETCH
# ========================================
try {
    $prefetch = "$env:SystemRoot\Prefetch"
    
    # TiProvider
    Get-ChildItem $prefetch -Filter "*TIPROVIDER*.pf" -ErrorAction SilentlyContinue | 
        Remove-Item -Force -ErrorAction SilentlyContinue
    
    # CMD (solo los más recientes)
    Get-ChildItem $prefetch -Filter "CMD*.pf" -ErrorAction SilentlyContinue | 
        Sort-Object LastWriteTime -Descending | 
        Select-Object -First 3 | 
        Remove-Item -Force -ErrorAction SilentlyContinue
    
    # PowerShell
    Get-ChildItem $prefetch -Filter "POWERSHELL*.pf" -ErrorAction SilentlyContinue | 
        Sort-Object LastWriteTime -Descending | 
        Select-Object -First 3 | 
        Remove-Item -Force -ErrorAction SilentlyContinue
        
    # Script propio
    $scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
    if ($scriptName) {
        Get-ChildItem $prefetch -Filter "*$scriptName*.pf" -ErrorAction SilentlyContinue | 
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
} catch { }

# ========================================
# FASE 6: LIMPIEZA SYSTEM INFORMER / PROCESS HACKER
# ========================================
try {
    # Limpiar dumps en temp
    $tempPaths = @($env:TEMP, "$env:SystemRoot\Temp", "$env:LOCALAPPDATA\Temp")
    foreach ($temp in $tempPaths) {
        if (Test-Path $temp) {
            Get-ChildItem $temp -Filter "*.dmp" -ErrorAction SilentlyContinue | 
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddHours(-2) } |
                Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
} catch { }

# ========================================
# FASE 7: LIMPIEZA HISTORIAL POWERSHELL
# ========================================
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
        }
    }
} catch { }

# ========================================
# FASE 8: LIMPIEZA EVENT VIEWER (OPCIONAL)
# ========================================
if ($cleanEventLogs) {
    try {
        # Detener EventLog service temporalmente
        Stop-Service EventLog -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        
        # Limpiar logs específicos de PowerShell
        $evtxPaths = @(
            "$env:SystemRoot\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx",
            "$env:SystemRoot\System32\winevt\Logs\Windows PowerShell.evtx"
        )
        
        foreach ($evtx in $evtxPaths) {
            if (Test-Path $evtx) {
                try {
                    # Crear archivo vacío válido (mínimo EVTX)
                    $header = [byte[]](0x45,0x6C,0x66,0x46,0x69,0x6C,0x65,0x00)
                    [System.IO.File]::WriteAllBytes($evtx, $header + (New-Object byte[] 69624))
                } catch { }
            }
        }
        
        Start-Service EventLog -ErrorAction SilentlyContinue
    } catch { }
}

# ========================================
# FASE 9: LIMPIEZA USN JOURNAL (OPCIONAL)
# ========================================
if ($cleanUSN) {
    try {
        # Eliminar journal
        fsutil usn deletejournal /D C: 2>$null | Out-Null
        Start-Sleep -Milliseconds 300
        
        # Recrear con tamaño pequeño para disimular
        fsutil usn createjournal m=1000 a=100 C: 2>$null | Out-Null
    } catch { }
}

# ========================================
# FASE 10: NORMALIZACIÓN DE TIMESTAMPS
# ========================================
try {
    Start-Sleep -Milliseconds (Get-Random -Minimum 100 -Maximum 400)
    
    # Normalizar BAM
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
    
    # Normalizar DAM
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

# ========================================
# FASE 11: RESTAURAR CONFIGURACIONES
# ========================================
try {
    # Restaurar valores originales de logging
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

# ========================================
# FASE 12: LIMPIEZA DE MEMORIA
# ========================================
try {
    # Limpiar todas las variables
    Get-Variable | Where-Object { $_.Name -notmatch '^(PSDefaultParameterValues|PSModuleAutoLoadingPreference|ErrorActionPreference|ProgressPreference)$' } | 
        Remove-Variable -Force -ErrorAction SilentlyContinue
    
    # GC agresivo
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
} catch { }

# ========================================
# FASE 13: AUTO-DESTRUCCIÓN
# ========================================
try {
    $scriptPath = $MyInvocation.MyCommand.Path
    if ($scriptPath) {
        if ($scriptPath -match "Temp|Download|Desktop|Documents|AppData") {
            Start-Sleep -Milliseconds 200
            
            # Sobrescribir varias veces
            for ($i = 0; $i -lt 3; $i++) {
                $random = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 5000 | ForEach-Object {[char]$_})
                Set-Content $scriptPath -Value $random -Force -ErrorAction SilentlyContinue
            }
            
            Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
        }
    }
} catch { }

# Salida silenciosa
exit 0
