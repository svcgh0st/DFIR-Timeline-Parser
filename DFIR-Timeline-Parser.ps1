#requires -version 5.1
<#
    DFIR-Timeline-Parser.ps1

    Windows Forms front end for running Eric Zimmerman command-line tools
    against a mounted or extracted Windows forensic target. The script never
    writes to the target folder unless the analyst explicitly chooses an
    output path inside that target and confirms the risk.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

[System.Windows.Forms.Application]::EnableVisualStyles()

$ErrorActionPreference = 'Stop'

$script:EzToolsUpdaterUrl = 'https://download.ericzimmermanstools.com/Get-ZimmermanTools.zip'
$script:WorkspaceRoot = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
$script:DefaultToolsPath = Join-Path $script:WorkspaceRoot 'ez'
$script:DefaultOutputPath = [Environment]::GetFolderPath('Desktop')
if ([string]::IsNullOrWhiteSpace($script:DefaultOutputPath)) {
    $script:DefaultOutputPath = Join-Path $env:USERPROFILE 'Desktop'
}
$script:ConfigPath = if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) { Join-Path $PSScriptRoot 'DFIR-Timeline-Parser.config.json' } else { Join-Path $script:WorkspaceRoot 'DFIR-Timeline-Parser.config.json' }
$script:LogFile = $null
$script:CurrentOutputRoot = $null
$script:LastRunOutputRoot = $null
$script:ArtifactResults = New-Object System.Collections.Generic.List[object]
$script:CurrentTools = @{}

$script:Artifacts = [ordered]@{
    MFT                 = [pscustomobject]@{ Label = '$MFT'; Default = $true;  Tool = 'MFTECmd.exe';                Group = 'Default' }
    LogFile             = [pscustomobject]@{ Label = '$LogFile'; Default = $true;  Tool = 'MFTECmd.exe';                Group = 'Default' }
    UsnJournal          = [pscustomobject]@{ Label = '$Extend\$J / USN Journal'; Default = $true; Tool = 'MFTECmd.exe'; Group = 'Default' }
    EvtxSecurity        = [pscustomobject]@{ Label = 'EVTX - Security.evtx'; Default = $true; Tool = 'EvtxECmd.exe';    Group = 'Default' }
    EvtxSysmon          = [pscustomobject]@{ Label = 'EVTX - Sysmon Operational'; Default = $true; Tool = 'EvtxECmd.exe'; Group = 'Default' }
    EvtxDefender        = [pscustomobject]@{ Label = 'EVTX - Windows Defender Operational'; Default = $true; Tool = 'EvtxECmd.exe'; Group = 'Default' }
    EvtxRdp             = [pscustomobject]@{ Label = 'EVTX - RDP / Terminal Services logs'; Default = $true; Tool = 'EvtxECmd.exe'; Group = 'Default' }
    CustomEvtx          = [pscustomobject]@{ Label = 'EVTX - Custom file/folder'; Default = $false; Tool = 'EvtxECmd.exe'; Group = 'Optional' }
    Prefetch            = [pscustomobject]@{ Label = 'Prefetch'; Default = $true; Tool = 'PECmd.exe';                 Group = 'Default' }
    ShimCache           = [pscustomobject]@{ Label = 'ShimCache from SYSTEM hive'; Default = $true; Tool = 'AppCompatCacheParser.exe'; Group = 'Default' }
    Amcache             = [pscustomobject]@{ Label = 'Amcache.hve'; Default = $true; Tool = 'AmcacheParser.exe';       Group = 'Default' }
    LnkFiles            = [pscustomobject]@{ Label = 'LNK files'; Default = $false; Tool = 'LECmd.exe';                Group = 'Optional' }
    JumpLists           = [pscustomobject]@{ Label = 'Jump Lists'; Default = $false; Tool = 'JLECmd.exe';              Group = 'Optional' }
    Shellbags           = [pscustomobject]@{ Label = 'Shellbags'; Default = $false; Tool = 'RECmd.exe';                Group = 'Optional' }
    RecentDocs          = [pscustomobject]@{ Label = 'RecentDocs'; Default = $false; Tool = 'RECmd.exe';               Group = 'Optional' }
    UserAssist          = [pscustomobject]@{ Label = 'UserAssist'; Default = $false; Tool = 'RECmd.exe';               Group = 'Optional' }
    RunKeys             = [pscustomobject]@{ Label = 'Run keys'; Default = $false; Tool = 'RECmd.exe';                 Group = 'Optional' }
    Services            = [pscustomobject]@{ Label = 'Services'; Default = $false; Tool = 'RECmd.exe';                 Group = 'Optional' }
    ScheduledTasks      = [pscustomobject]@{ Label = 'Scheduled Tasks'; Default = $false; Tool = 'RECmd.exe';          Group = 'Optional' }
    Srum                = [pscustomobject]@{ Label = 'SRUM'; Default = $false; Tool = 'SrumECmd.exe';                  Group = 'Optional' }
    RecycleBin          = [pscustomobject]@{ Label = 'Recycle Bin'; Default = $false; Tool = 'RBCmd.exe';              Group = 'Optional' }
}

# Writes a timestamped line to the GUI and to the active run log.
function Write-Status {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')][string]$Level = 'INFO'
    )

    $line = '{0} [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message

    if ($script:txtLog) {
        $script:txtLog.AppendText($line + [Environment]::NewLine)
        $script:txtLog.SelectionStart = $script:txtLog.TextLength
        $script:txtLog.ScrollToCaret()
        [System.Windows.Forms.Application]::DoEvents()
    }

    if ($script:LogFile) {
        Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8
    }
}

# Converts a Windows command-line argument array into a safely quoted string for Start-Process logging/execution.
function Join-WindowsCommandLine {
    param([Parameter(Mandatory)][string[]]$Arguments)

    $quoted = foreach ($arg in $Arguments) {
        if ($null -eq $arg) {
            '""'
            continue
        }

        if ($arg -notmatch '[\s"]' -and $arg.Length -gt 0) {
            $arg
            continue
        }

        $builder = New-Object System.Text.StringBuilder
        [void]$builder.Append('"')
        $slashCount = 0

        foreach ($char in $arg.ToCharArray()) {
            if ($char -eq '\') {
                $slashCount++
                continue
            }

            if ($char -eq '"') {
                [void]$builder.Append('\', ($slashCount * 2) + 1)
                [void]$builder.Append('"')
                $slashCount = 0
                continue
            }

            if ($slashCount -gt 0) {
                [void]$builder.Append('\', $slashCount)
                $slashCount = 0
            }
            [void]$builder.Append($char)
        }

        if ($slashCount -gt 0) {
            [void]$builder.Append('\', $slashCount * 2)
        }
        [void]$builder.Append('"')
        $builder.ToString()
    }

    return ($quoted -join ' ')
}

# Resolves a path when possible and falls back to a full path for paths that do not exist yet.
function Get-NormalizedPath {
    param([Parameter(Mandatory)][string]$Path)

    try {
        return (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath.TrimEnd('\')
    }
    catch {
        return ([System.IO.Path]::GetFullPath($Path)).TrimEnd('\')
    }
}

# Locates a portable .NET 9 runtime beside this workspace when available.
function Get-PortableDotNetRoot {
    $candidates = New-Object System.Collections.Generic.List[string]

    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $candidates.Add((Join-Path (Split-Path -Parent $PSScriptRoot) 'work\dotnet9')) | Out-Null
        $candidates.Add((Join-Path $PSScriptRoot 'work\dotnet9')) | Out-Null
    }

    $candidates.Add((Join-Path (Get-Location).Path 'work\dotnet9')) | Out-Null

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        $dotnetExe = Join-Path $candidate 'dotnet.exe'
        $runtimeRoot = Join-Path $candidate 'shared\Microsoft.NETCore.App'
        if ((Test-Path -LiteralPath $dotnetExe -PathType Leaf) -and
            (Test-Path -LiteralPath $runtimeRoot -PathType Container) -and
            (Get-ChildItem -LiteralPath $runtimeRoot -Directory -Filter '9.*' -ErrorAction SilentlyContinue | Select-Object -First 1)) {
            return $candidate
        }
    }

    return $null
}

# Tests whether a candidate path is equal to or nested below a parent path.
function Test-IsSameOrChildPath {
    param(
        [Parameter(Mandatory)][string]$Parent,
        [Parameter(Mandatory)][string]$Candidate
    )

    $parentPath = Get-NormalizedPath -Path $Parent
    $candidatePath = Get-NormalizedPath -Path $Candidate

    return ($candidatePath.Equals($parentPath, [System.StringComparison]::OrdinalIgnoreCase) -or
        $candidatePath.StartsWith($parentPath + '\', [System.StringComparison]::OrdinalIgnoreCase))
}

# Creates a filesystem-safe folder or file stem from an artifact or source name.
function ConvertTo-SafeName {
    param([Parameter(Mandatory)][string]$Name)

    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $safe = $Name
    foreach ($char in $invalid) {
        $safe = $safe.Replace($char, '_')
    }
    return ($safe -replace '\s+', '_').Trim('_')
}

# Creates a timestamped run folder inside the selected output destination.
function New-RunOutputRoot {
    param([Parameter(Mandatory)][string]$OutputDestination)

    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $baseName = 'DFIR-Timeline-Parser_{0}' -f $stamp
    $runRoot = Join-Path $OutputDestination $baseName
    $suffix = 1

    while (Test-Path -LiteralPath $runRoot) {
        $runRoot = Join-Path $OutputDestination ('{0}_{1:D2}' -f $baseName, $suffix)
        $suffix++
    }

    New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
    return $runRoot
}

# Returns a short stable hash for path-derived output folder names.
function Get-ShortHash {
    param([Parameter(Mandatory)][string]$Text)

    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return ([System.BitConverter]::ToString($sha1.ComputeHash($bytes))).Replace('-', '').Substring(0, 8)
    }
    finally {
        $sha1.Dispose()
    }
}

# Loads remembered GUI settings from the script-side config file.
function Get-ParserConfig {
    if (-not (Test-Path -LiteralPath $script:ConfigPath -PathType Leaf)) {
        return [pscustomobject]@{}
    }

    try {
        return (Get-Content -LiteralPath $script:ConfigPath -Raw -ErrorAction Stop | ConvertFrom-Json)
    }
    catch {
        Write-Status -Level 'WARN' -Message "Unable to read config file ${script:ConfigPath}: $($_.Exception.Message)"
        return [pscustomobject]@{}
    }
}

# Saves the persistent GUI settings that are safe to remember between runs.
function Save-ParserConfig {
    param([Parameter(Mandatory)][string]$ToolsPath)

    try {
        [pscustomobject]@{
            ToolsPath   = $ToolsPath
            LastUpdated = (Get-Date -Format 'o')
        } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $script:ConfigPath -Encoding UTF8
    }
    catch {
        Write-Status -Level 'WARN' -Message "Unable to save config file ${script:ConfigPath}: $($_.Exception.Message)"
    }
}

# Recursively discovers executable paths for the EZ tools required by this script.
function Get-EzToolMap {
    param([Parameter(Mandatory)][string]$ToolsRoot)

    $toolNames = $script:Artifacts.Values |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_.Tool) } |
        Select-Object -ExpandProperty Tool -Unique

    $map = @{}
    foreach ($toolName in $toolNames) {
        $match = Get-ChildItem -LiteralPath $ToolsRoot -Recurse -Force -File -Filter $toolName -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTimeUtc -Descending |
            Select-Object -First 1

        if ($match) {
            $map[$toolName] = $match.FullName
        }
    }

    return $map
}

# Runs one EZ tool process, logs the full command, captures stdout/stderr, and returns its exit code.
function Invoke-ExternalTool {
    param(
        [Parameter(Mandatory)][string]$ToolPath,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [Parameter(Mandatory)][string]$LogPrefix
    )

    New-Item -ItemType Directory -Path $WorkingDirectory -Force | Out-Null
    $processLogBase = if (-not [string]::IsNullOrWhiteSpace($script:CurrentOutputRoot)) { $script:CurrentOutputRoot } else { $WorkingDirectory }
    $processLogDir = Join-Path $processLogBase '_process_logs'
    New-Item -ItemType Directory -Path $processLogDir -Force | Out-Null

    $safePrefix = ConvertTo-SafeName -Name $LogPrefix
    if ($safePrefix.Length -gt 24) {
        $hashBytes = [System.Text.Encoding]::UTF8.GetBytes($safePrefix)
        $sha1 = [System.Security.Cryptography.SHA1]::Create()
        $hash = ([System.BitConverter]::ToString($sha1.ComputeHash($hashBytes))).Replace('-', '').Substring(0, 8)
        $sha1.Dispose()
        $safePrefix = '{0}_{1}' -f $safePrefix.Substring(0, 15), $hash
    }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss_fff'
    $stdoutPath = Join-Path $processLogDir "$safePrefix.$stamp.stdout.txt"
    $stderrPath = Join-Path $processLogDir "$safePrefix.$stamp.stderr.txt"
    $argumentString = Join-WindowsCommandLine -Arguments $Arguments

    Write-Status -Message ("Command: {0} {1}" -f (Join-WindowsCommandLine -Arguments @($ToolPath)), $argumentString)

    try {
        $startInfo = New-Object System.Diagnostics.ProcessStartInfo
        $startInfo.FileName = $ToolPath
        $startInfo.Arguments = $argumentString
        $startInfo.WorkingDirectory = $WorkingDirectory
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true

        # Some shells expose both Path and PATH. Normalize before process start
        # to avoid .NET duplicate-key failures on affected workstations.
        $processPath = [Environment]::GetEnvironmentVariable('Path', 'Process')
        foreach ($key in @($startInfo.EnvironmentVariables.Keys)) {
            if ($key -ieq 'PATH' -and $key -cne 'Path') {
                $startInfo.EnvironmentVariables.Remove($key)
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($processPath)) {
            $startInfo.EnvironmentVariables['Path'] = $processPath
        }

        $portableDotNetRoot = Get-PortableDotNetRoot
        if ($portableDotNetRoot) {
            $startInfo.EnvironmentVariables['DOTNET_ROOT'] = $portableDotNetRoot
            $startInfo.EnvironmentVariables['Path'] = '{0};{1}' -f $portableDotNetRoot, $startInfo.EnvironmentVariables['Path']
            Write-Status -Message "Using portable .NET runtime: $portableDotNetRoot"
        }

        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $startInfo
        [void]$process.Start()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()

        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        Set-Content -LiteralPath $stdoutPath -Value $stdout -Encoding UTF8
        Set-Content -LiteralPath $stderrPath -Value $stderr -Encoding UTF8

        if ($script:LogFile -and -not [string]::IsNullOrWhiteSpace($stdout)) {
            Add-Content -LiteralPath $script:LogFile -Value "`n--- STDOUT: $LogPrefix ---`n$stdout" -Encoding UTF8
        }
        if ($script:LogFile -and -not [string]::IsNullOrWhiteSpace($stderr)) {
            Add-Content -LiteralPath $script:LogFile -Value "`n--- STDERR: $LogPrefix ---`n$stderr" -Encoding UTF8
        }

        $exitCode = [int]$process.ExitCode
        $process.Dispose()
        return $exitCode
    }
    catch {
        Write-Status -Level 'ERROR' -Message ("Process failed to start: {0}" -f $_.Exception.Message)
        return 9999
    }
}

# Records one artifact result for the final analyst summary.
function Add-ArtifactResult {
    param(
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter(Mandatory)][string]$Status,
        [int]$Found = 0,
        [int]$Parsed = 0,
        [string]$Detail = ''
    )

    $script:ArtifactResults.Add([pscustomobject]@{
        Artifact = $Artifact
        Status   = $Status
        Found    = $Found
        Parsed   = $Parsed
        Detail   = $Detail
    }) | Out-Null
}

# Logs all discovered artifact paths so the run can be audited later.
function Write-FoundPaths {
    param(
        [Parameter(Mandatory)][string]$Artifact,
        [Parameter()][AllowNull()][string[]]$Paths
    )

    if (-not $Paths -or $Paths.Count -eq 0) {
        Write-Status -Level 'WARN' -Message "${Artifact}: no matching artifacts found."
        return
    }

    Write-Status -Message ("{0}: found {1} artifact path(s)." -f $Artifact, $Paths.Count)
    foreach ($path in $Paths) {
        Write-Status -Message ("{0}: {1}" -f $Artifact, $path)
    }
}

# Finds exact relative paths first, then falls back to a recursive file-name search.
function Find-ArtifactFiles {
    param(
        [Parameter(Mandatory)][string]$TargetRoot,
        [Parameter()][string[]]$RelativeCandidates = @(),
        [Parameter()][string[]]$FileNames = @(),
        [Parameter()][string[]]$NamePatterns = @()
    )

    $found = New-Object System.Collections.Generic.List[string]

    foreach ($relative in $RelativeCandidates) {
        $candidate = Join-Path $TargetRoot $relative
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $found.Add((Get-NormalizedPath -Path $candidate)) | Out-Null
        }
    }

    foreach ($name in $FileNames) {
        Get-ChildItem -LiteralPath $TargetRoot -Recurse -Force -File -Filter $name -ErrorAction SilentlyContinue |
            ForEach-Object { $found.Add($_.FullName) | Out-Null }
    }

    foreach ($pattern in $NamePatterns) {
        Get-ChildItem -LiteralPath $TargetRoot -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like $pattern } |
            ForEach-Object { $found.Add($_.FullName) | Out-Null }
    }

    return $found.ToArray() | Sort-Object -Unique
}

# Finds exact relative directories first, then falls back to a recursive directory-name search.
function Find-ArtifactDirectories {
    param(
        [Parameter(Mandatory)][string]$TargetRoot,
        [Parameter()][string[]]$RelativeCandidates = @(),
        [Parameter()][string[]]$DirectoryNames = @()
    )

    $found = New-Object System.Collections.Generic.List[string]

    foreach ($relative in $RelativeCandidates) {
        $candidate = Join-Path $TargetRoot $relative
        if (Test-Path -LiteralPath $candidate -PathType Container) {
            $found.Add((Get-NormalizedPath -Path $candidate)) | Out-Null
        }
    }

    foreach ($name in $DirectoryNames) {
        Get-ChildItem -LiteralPath $TargetRoot -Recurse -Force -Directory -Filter $name -ErrorAction SilentlyContinue |
            ForEach-Object { $found.Add($_.FullName) | Out-Null }
    }

    return $found.ToArray() | Sort-Object -Unique
}

# Returns a dedicated output directory for one artifact type.
function Get-ArtifactOutputDirectory {
    param([Parameter(Mandatory)][string]$ArtifactKey)

    $folder = Join-Path $script:CurrentOutputRoot (ConvertTo-SafeName -Name $ArtifactKey)
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    return $folder
}

# Starts an EZ parser for each discovered file, using one subfolder per source when needed.
function Invoke-FileParser {
    param(
        [Parameter(Mandatory)][string]$ArtifactKey,
        [Parameter(Mandatory)][string]$ToolName,
        [Parameter()][AllowNull()][string[]]$Paths,
        [Parameter(Mandatory)][scriptblock]$ArgumentBuilder
    )

    $label = $script:Artifacts[$ArtifactKey].Label
    Write-FoundPaths -Artifact $label -Paths $Paths

    if (-not $Paths -or $Paths.Count -eq 0) {
        Add-ArtifactResult -Artifact $label -Status 'Missing artifact' -Found 0 -Parsed 0
        return
    }

    if (-not $script:CurrentTools.ContainsKey($ToolName)) {
        Write-Status -Level 'ERROR' -Message "${label}: missing required tool $ToolName."
        Add-ArtifactResult -Artifact $label -Status 'Missing tool' -Found $Paths.Count -Parsed 0 -Detail $ToolName
        return
    }

    $parsed = 0
    $failures = 0
    $artifactOutput = Get-ArtifactOutputDirectory -ArtifactKey $ArtifactKey

    foreach ($path in $Paths) {
        $sourceOutput = $artifactOutput
        if ($Paths.Count -gt 1) {
            $sourceOutput = Join-Path $artifactOutput (ConvertTo-SafeName -Name ([System.IO.Path]::GetFileName($path)))
            New-Item -ItemType Directory -Path $sourceOutput -Force | Out-Null
        }

        $arguments = & $ArgumentBuilder $path $sourceOutput
        $exitCode = Invoke-ExternalTool -ToolPath $script:CurrentTools[$ToolName] -Arguments $arguments -WorkingDirectory $sourceOutput -LogPrefix "$ArtifactKey-$([System.IO.Path]::GetFileName($path))"
        $csvOutputCount = @(Get-ChildItem -LiteralPath $sourceOutput -Recurse -File -Filter '*.csv' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\_process_logs\\' }).Count
        if ($exitCode -eq 0) {
            if ($csvOutputCount -gt 0) {
                $parsed++
                Write-Status -Level 'SUCCESS' -Message "$label parsed successfully: $path"
            }
            else {
                $failures++
                Write-Status -Level 'ERROR' -Message "$label parser returned exit code 0 but did not create CSV output for $path"
            }
        }
        else {
            $failures++
            Write-Status -Level 'ERROR' -Message "$label parser returned exit code $exitCode for $path"
        }
    }

    $status = if ($failures -eq 0) { 'Parsed' } elseif ($parsed -gt 0) { 'Partial failure' } else { 'Parser failed' }
    Add-ArtifactResult -Artifact $label -Status $status -Found $Paths.Count -Parsed $parsed -Detail "$failures failure(s)"
}

# Runs EvtxECmd against analyst-selected EVTX files and folders.
function Invoke-CustomEvtxParser {
    param([Parameter()][AllowNull()][string[]]$CustomEvtxPaths)

    $label = $script:Artifacts['CustomEvtx'].Label

    if (-not $CustomEvtxPaths -or $CustomEvtxPaths.Count -eq 0) {
        Write-Status -Level 'WARN' -Message "$label selected but no custom EVTX paths were provided."
        Add-ArtifactResult -Artifact $label -Status 'Missing artifact' -Found 0 -Parsed 0 -Detail 'No custom EVTX path provided'
        return
    }

    if (-not $script:CurrentTools.ContainsKey('EvtxECmd.exe')) {
        Write-Status -Level 'ERROR' -Message "${label}: missing required tool EvtxECmd.exe."
        Add-ArtifactResult -Artifact $label -Status 'Missing tool' -Found $CustomEvtxPaths.Count -Parsed 0 -Detail 'EvtxECmd.exe'
        return
    }

    $requestedPaths = New-Object System.Collections.Generic.List[string]
    $evtxFiles = New-Object System.Collections.Generic.List[string]

    foreach ($customPath in $CustomEvtxPaths) {
        if ([string]::IsNullOrWhiteSpace($customPath)) {
            continue
        }

        if (-not (Test-Path -LiteralPath $customPath)) {
            Write-Status -Level 'WARN' -Message "$label path does not exist: $customPath"
            continue
        }

        $resolvedPath = Get-NormalizedPath -Path $customPath
        $requestedPaths.Add($resolvedPath) | Out-Null

        if (Test-Path -LiteralPath $resolvedPath -PathType Container) {
            Get-ChildItem -LiteralPath $resolvedPath -Recurse -Force -File -Filter '*.evtx' -ErrorAction SilentlyContinue |
                ForEach-Object { $evtxFiles.Add($_.FullName) | Out-Null }
        }
        elseif ([System.IO.Path]::GetExtension($resolvedPath) -ieq '.evtx') {
            $evtxFiles.Add($resolvedPath) | Out-Null
        }
        else {
            Write-Status -Level 'WARN' -Message "$label path is not an .evtx file: $resolvedPath"
        }
    }

    Write-FoundPaths -Artifact "$label input" -Paths ($requestedPaths.ToArray())
    $files = @($evtxFiles.ToArray() | Sort-Object -Unique)
    Write-FoundPaths -Artifact "$label files" -Paths $files

    if ($files.Count -eq 0) {
        Add-ArtifactResult -Artifact $label -Status 'Missing artifact' -Found 0 -Parsed 0 -Detail 'No .evtx files found in selected custom paths'
        return
    }

    $artifactOutput = Get-ArtifactOutputDirectory -ArtifactKey 'CustomEvtx'
    $parsed = 0
    $failures = 0
    $fileIndex = 0

    foreach ($file in $files) {
        $fileIndex++
        $fileName = [System.IO.Path]::GetFileNameWithoutExtension($file)
        $sourceOutput = Join-Path $artifactOutput ('EVTX_{0:D4}_{1}' -f $fileIndex, (Get-ShortHash -Text $file))
        New-Item -ItemType Directory -Path $sourceOutput -Force | Out-Null

        $exitCode = Invoke-ExternalTool -ToolPath $script:CurrentTools['EvtxECmd.exe'] -Arguments @('-f', $file, '--csv', $sourceOutput) -WorkingDirectory $sourceOutput -LogPrefix "CustomEvtx-$fileName"
        $csvOutputCount = @(Get-ChildItem -LiteralPath $sourceOutput -Recurse -File -Filter '*.csv' -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '\\_process_logs\\' }).Count

        if ($exitCode -eq 0 -and $csvOutputCount -gt 0) {
            $parsed++
            Write-Status -Level 'SUCCESS' -Message "$label parsed successfully: $file"
        }
        elseif ($exitCode -eq 0) {
            $failures++
            Write-Status -Level 'ERROR' -Message "$label parser returned exit code 0 but did not create CSV output for $file"
        }
        else {
            $failures++
            Write-Status -Level 'ERROR' -Message "$label parser returned exit code $exitCode for $file"
        }
    }

    $status = if ($failures -eq 0) { 'Parsed' } elseif ($parsed -gt 0) { 'Partial failure' } else { 'Parser failed' }
    Add-ArtifactResult -Artifact $label -Status $status -Found $files.Count -Parsed $parsed -Detail "$failures failure(s)"
}

# Runs RECmd against registry hives and key paths without decoding the hive manually.
function Invoke-RegistryKeysWithRECmd {
    param(
        [Parameter(Mandatory)][string]$ArtifactKey,
        [Parameter()][AllowNull()][string[]]$HivePaths,
        [Parameter(Mandatory)][string[]]$RegistryKeys
    )

    $label = $script:Artifacts[$ArtifactKey].Label
    Write-FoundPaths -Artifact $label -Paths $HivePaths

    if (-not $HivePaths -or $HivePaths.Count -eq 0) {
        Add-ArtifactResult -Artifact $label -Status 'Missing artifact' -Found 0 -Parsed 0
        return
    }

    if (-not $script:CurrentTools.ContainsKey('RECmd.exe')) {
        Write-Status -Level 'ERROR' -Message "${label}: missing required tool RECmd.exe."
        Add-ArtifactResult -Artifact $label -Status 'Missing tool' -Found $HivePaths.Count -Parsed 0 -Detail 'RECmd.exe'
        return
    }

    $parsed = 0
    $failures = 0
    $artifactOutput = Get-ArtifactOutputDirectory -ArtifactKey $ArtifactKey

    foreach ($hive in $HivePaths) {
        foreach ($key in $RegistryKeys) {
            $sourceName = '{0}-{1}' -f ([System.IO.Path]::GetFileName($hive)), (ConvertTo-SafeName -Name $key)
            $sourceOutput = Join-Path $artifactOutput $sourceName
            New-Item -ItemType Directory -Path $sourceOutput -Force | Out-Null
            $arguments = @('-f', $hive, '--kn', $key, '--csv', $sourceOutput)
            $exitCode = Invoke-ExternalTool -ToolPath $script:CurrentTools['RECmd.exe'] -Arguments $arguments -WorkingDirectory $sourceOutput -LogPrefix "$ArtifactKey-$sourceName"
            $csvOutputCount = @(Get-ChildItem -LiteralPath $sourceOutput -Recurse -File -Filter '*.csv' -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -notmatch '\\_process_logs\\' }).Count
            if ($exitCode -eq 0) {
                if ($csvOutputCount -gt 0) {
                    $parsed++
                }
                else {
                    $failures++
                    Write-Status -Level 'ERROR' -Message "$label RECmd returned exit code 0 but did not create CSV output for hive $hive key $key"
                }
            }
            else {
                $failures++
                Write-Status -Level 'ERROR' -Message "$label RECmd returned exit code $exitCode for hive $hive key $key"
            }
        }
    }

    $status = if ($failures -eq 0) { 'Parsed' } elseif ($parsed -gt 0) { 'Partial failure' } else { 'Parser failed' }
    Add-ArtifactResult -Artifact $label -Status $status -Found $HivePaths.Count -Parsed $parsed -Detail "$failures failure(s)"
}

# Locates common offline Windows registry hives in extracted targets.
function Get-RegistryHivePaths {
    param(
        [Parameter(Mandatory)][string]$TargetRoot,
        [Parameter(Mandatory)][ValidateSet('SYSTEM', 'SOFTWARE', 'NTUSER', 'USRCLASS')][string]$HiveType
    )

    switch ($HiveType) {
        'SYSTEM' {
            return Find-ArtifactFiles -TargetRoot $TargetRoot -RelativeCandidates @('Windows\System32\config\SYSTEM') -FileNames @('SYSTEM')
        }
        'SOFTWARE' {
            return Find-ArtifactFiles -TargetRoot $TargetRoot -RelativeCandidates @('Windows\System32\config\SOFTWARE') -FileNames @('SOFTWARE')
        }
        'NTUSER' {
            return Find-ArtifactFiles -TargetRoot $TargetRoot -FileNames @('NTUSER.DAT')
        }
        'USRCLASS' {
            return Find-ArtifactFiles -TargetRoot $TargetRoot -FileNames @('UsrClass.dat')
        }
    }
}

# Downloads and runs Eric Zimmerman's official updater into the selected tools folder only.
function Invoke-EzToolsDownload {
    param(
        [Parameter(Mandatory)][string]$ToolsFolder,
        [Parameter()][string]$TargetRoot
    )

    if (-not [string]::IsNullOrWhiteSpace($TargetRoot) -and (Test-Path -LiteralPath $TargetRoot)) {
        if (Test-IsSameOrChildPath -Parent $TargetRoot -Candidate $ToolsFolder) {
            [System.Windows.Forms.MessageBox]::Show(
                'The EZ Tools folder is inside the evidence/target folder. Choose a tools folder outside the target before downloading.',
                'Unsafe Tools Folder',
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning
            ) | Out-Null
            return
        }
    }

    New-Item -ItemType Directory -Path $ToolsFolder -Force | Out-Null
    $updaterRoot = Join-Path $ToolsFolder '_Get-ZimmermanTools'
    New-Item -ItemType Directory -Path $updaterRoot -Force | Out-Null
    $zipPath = Join-Path $updaterRoot 'Get-ZimmermanTools.zip'

    Write-Status -Message "Downloading EZ Tools updater to $zipPath"
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $script:EzToolsUpdaterUrl -OutFile $zipPath -UseBasicParsing -UserAgent 'Mozilla/5.0 Windows PowerShell forensic parser setup'

    Write-Status -Message "Expanding EZ Tools updater under $updaterRoot"
    Expand-Archive -LiteralPath $zipPath -DestinationPath $updaterRoot -Force

    $updaterScript = Get-ChildItem -LiteralPath $updaterRoot -Recurse -File -Filter 'Get-ZimmermanTools.ps1' -ErrorAction SilentlyContinue |
        Select-Object -First 1

    if (-not $updaterScript) {
        throw 'Get-ZimmermanTools.ps1 was not found after expanding the updater archive.'
    }

    $powershellExe = (Get-Command powershell.exe -ErrorAction Stop).Source
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $updaterScript.FullName, '-Dest', $ToolsFolder)
    $exitCode = Invoke-ExternalTool -ToolPath $powershellExe -Arguments $arguments -WorkingDirectory $updaterRoot -LogPrefix 'Get-ZimmermanTools'

    if ($exitCode -eq 0) {
        Write-Status -Level 'SUCCESS' -Message "EZ Tools download/update completed in $ToolsFolder"
    }
    else {
        Write-Status -Level 'ERROR' -Message "EZ Tools updater returned exit code $exitCode"
    }
}

# Executes the selected artifact parsers and keeps going if any single parser fails.
function Invoke-SelectedParsing {
    param(
        [Parameter(Mandatory)][string]$TargetRoot,
        [Parameter(Mandatory)][string]$OutputRoot,
        [Parameter(Mandatory)][string]$ToolsRoot,
        [Parameter(Mandatory)][string[]]$SelectedArtifactKeys,
        [Parameter()][AllowNull()][string[]]$CustomEvtxPaths
    )

    New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null
    $runOutputRoot = New-RunOutputRoot -OutputDestination $OutputRoot
    $script:ArtifactResults.Clear()
    $script:CurrentOutputRoot = $runOutputRoot
    $script:LastRunOutputRoot = $runOutputRoot

    $script:LogFile = Join-Path $runOutputRoot ('DFIR-Timeline-Parser_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    New-Item -ItemType File -Path $script:LogFile -Force | Out-Null

    Write-Status -Message "Start time: $(Get-Date -Format 'o')"
    Write-Status -Message "Target root: $TargetRoot"
    Write-Status -Message "Output destination: $OutputRoot"
    Write-Status -Message "Run output folder: $runOutputRoot"
    Write-Status -Message "EZ Tools root: $ToolsRoot"
    Write-Status -Message ("Selected artifacts: {0}" -f (($SelectedArtifactKeys | ForEach-Object { $script:Artifacts[$_].Label }) -join ', '))
    if ($SelectedArtifactKeys -contains 'CustomEvtx') {
        Write-Status -Message ("Custom EVTX paths: {0}" -f (($CustomEvtxPaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '; '))
    }

    $script:CurrentTools = Get-EzToolMap -ToolsRoot $ToolsRoot
    foreach ($toolName in ($script:Artifacts.Values | Where-Object Tool | Select-Object -ExpandProperty Tool -Unique)) {
        if ($script:CurrentTools.ContainsKey($toolName)) {
            Write-Status -Message "Tool path: $toolName => $($script:CurrentTools[$toolName])"
        }
        else {
            Write-Status -Level 'WARN' -Message "Missing tool: $toolName"
        }
    }

    foreach ($key in $SelectedArtifactKeys) {
        try {
            switch ($key) {
                'MFT' {
                    $paths = Find-ArtifactFiles -TargetRoot $TargetRoot -RelativeCandidates @('$MFT') -FileNames @('$MFT')
                    Invoke-FileParser -ArtifactKey $key -ToolName 'MFTECmd.exe' -Paths $paths -ArgumentBuilder { param($path, $out) @('-f', $path, '--csv', $out) }
                }
                'LogFile' {
                    $paths = Find-ArtifactFiles -TargetRoot $TargetRoot -RelativeCandidates @('$LogFile') -FileNames @('$LogFile')
                    Invoke-FileParser -ArtifactKey $key -ToolName 'MFTECmd.exe' -Paths $paths -ArgumentBuilder { param($path, $out) @('-f', $path, '--csv', $out) }
                }
                'UsnJournal' {
                    $paths = Find-ArtifactFiles -TargetRoot $TargetRoot -RelativeCandidates @('$Extend\$J') -FileNames @('$J')
                    Invoke-FileParser -ArtifactKey $key -ToolName 'MFTECmd.exe' -Paths $paths -ArgumentBuilder { param($path, $out) @('-f', $path, '--csv', $out) }
                }
                'EvtxSecurity' {
                    $paths = Find-ArtifactFiles -TargetRoot $TargetRoot -RelativeCandidates @('Windows\System32\winevt\Logs\Security.evtx') -FileNames @('Security.evtx')
                    Invoke-FileParser -ArtifactKey $key -ToolName 'EvtxECmd.exe' -Paths $paths -ArgumentBuilder { param($path, $out) @('-f', $path, '--csv', $out) }
                }
                'EvtxSysmon' {
                    $paths = Find-ArtifactFiles -TargetRoot $TargetRoot -RelativeCandidates @('Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx') -FileNames @('Microsoft-Windows-Sysmon%4Operational.evtx')
                    Invoke-FileParser -ArtifactKey $key -ToolName 'EvtxECmd.exe' -Paths $paths -ArgumentBuilder { param($path, $out) @('-f', $path, '--csv', $out) }
                }
                'EvtxDefender' {
                    $paths = Find-ArtifactFiles -TargetRoot $TargetRoot -RelativeCandidates @('Windows\System32\winevt\Logs\Microsoft-Windows-Windows Defender%4Operational.evtx') -FileNames @('Microsoft-Windows-Windows Defender%4Operational.evtx')
                    Invoke-FileParser -ArtifactKey $key -ToolName 'EvtxECmd.exe' -Paths $paths -ArgumentBuilder { param($path, $out) @('-f', $path, '--csv', $out) }
                }
                'EvtxRdp' {
                    $paths = Find-ArtifactFiles -TargetRoot $TargetRoot -RelativeCandidates @(
                        'Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx',
                        'Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx',
                        'Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RDPClient%4Operational.evtx',
                        'Windows\System32\winevt\Logs\Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx',
                        'Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-Gateway%4Operational.evtx'
                    ) -NamePatterns @(
                        'Microsoft-Windows-TerminalServices-*%4*.evtx',
                        'Microsoft-Windows-RemoteDesktopServices-*%4*.evtx',
                        'Microsoft-Windows-RemoteConnectionManager*.evtx'
                    )
                    Invoke-FileParser -ArtifactKey $key -ToolName 'EvtxECmd.exe' -Paths $paths -ArgumentBuilder { param($path, $out) @('-f', $path, '--csv', $out) }
                }
                'CustomEvtx' {
                    Invoke-CustomEvtxParser -CustomEvtxPaths $CustomEvtxPaths
                }
                'Prefetch' {
                    $paths = Find-ArtifactDirectories -TargetRoot $TargetRoot -RelativeCandidates @('Windows\Prefetch') -DirectoryNames @('Prefetch')
                    Invoke-FileParser -ArtifactKey $key -ToolName 'PECmd.exe' -Paths $paths -ArgumentBuilder { param($path, $out) @('-d', $path, '--csv', $out) }
                }
                'ShimCache' {
                    $paths = Get-RegistryHivePaths -TargetRoot $TargetRoot -HiveType SYSTEM
                    Invoke-FileParser -ArtifactKey $key -ToolName 'AppCompatCacheParser.exe' -Paths $paths -ArgumentBuilder { param($path, $out) @('-f', $path, '--csv', $out) }
                }
                'Amcache' {
                    $paths = Find-ArtifactFiles -TargetRoot $TargetRoot -RelativeCandidates @('Windows\AppCompat\Programs\Amcache.hve') -FileNames @('Amcache.hve')
                    Invoke-FileParser -ArtifactKey $key -ToolName 'AmcacheParser.exe' -Paths $paths -ArgumentBuilder { param($path, $out) @('-f', $path, '--csv', $out) }
                }
                'LnkFiles' {
                    $paths = Find-ArtifactFiles -TargetRoot $TargetRoot -NamePatterns @('*.lnk')
                    $label = $script:Artifacts[$key].Label
                    Write-FoundPaths -Artifact $label -Paths $paths
                    if (-not $paths -or $paths.Count -eq 0) {
                        Add-ArtifactResult -Artifact $label -Status 'Missing artifact' -Found 0 -Parsed 0
                        break
                    }
                    if (-not $script:CurrentTools.ContainsKey('LECmd.exe')) {
                        Write-Status -Level 'ERROR' -Message "${label}: missing required tool LECmd.exe."
                        Add-ArtifactResult -Artifact $label -Status 'Missing tool' -Found $paths.Count -Parsed 0 -Detail 'LECmd.exe'
                        break
                    }

                    $artifactOutput = Get-ArtifactOutputDirectory -ArtifactKey $key
                    $exitCode = Invoke-ExternalTool -ToolPath $script:CurrentTools['LECmd.exe'] -Arguments @('-d', $TargetRoot, '--csv', $artifactOutput) -WorkingDirectory $artifactOutput -LogPrefix 'LnkFiles'
                    $csvOutputCount = @(Get-ChildItem -LiteralPath $artifactOutput -Recurse -File -Filter '*.csv' -ErrorAction SilentlyContinue |
                        Where-Object { $_.FullName -notmatch '\\_process_logs\\' }).Count
                    if ($exitCode -eq 0 -and $csvOutputCount -gt 0) {
                        Add-ArtifactResult -Artifact $label -Status 'Parsed' -Found $paths.Count -Parsed $paths.Count
                    }
                    elseif ($exitCode -eq 0) {
                        Add-ArtifactResult -Artifact $label -Status 'Parser failed' -Found $paths.Count -Parsed 0 -Detail 'Exit code 0 but no CSV output'
                    }
                    else {
                        Add-ArtifactResult -Artifact $label -Status 'Parser failed' -Found $paths.Count -Parsed 0 -Detail "Exit code $exitCode"
                    }
                }
                'JumpLists' {
                    $paths = Find-ArtifactDirectories -TargetRoot $TargetRoot -RelativeCandidates @(
                        'Users\Default\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations',
                        'Users\Default\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations'
                    ) -DirectoryNames @('AutomaticDestinations', 'CustomDestinations')
                    Invoke-FileParser -ArtifactKey $key -ToolName 'JLECmd.exe' -Paths $paths -ArgumentBuilder { param($path, $out) @('-d', $path, '--csv', $out) }
                }
                'Shellbags' {
                    $hives = @(
                        Get-RegistryHivePaths -TargetRoot $TargetRoot -HiveType NTUSER
                        Get-RegistryHivePaths -TargetRoot $TargetRoot -HiveType USRCLASS
                    ) | Sort-Object -Unique
                    Invoke-RegistryKeysWithRECmd -ArtifactKey $key -HivePaths $hives -RegistryKeys @(
                        'Software\Microsoft\Windows\Shell\BagMRU',
                        'Software\Microsoft\Windows\Shell\Bags',
                        'Software\Microsoft\Windows\ShellNoRoam\BagMRU',
                        'Software\Microsoft\Windows\ShellNoRoam\Bags',
                        'Local Settings\Software\Microsoft\Windows\Shell\BagMRU',
                        'Local Settings\Software\Microsoft\Windows\Shell\Bags'
                    )
                }
                'RecentDocs' {
                    $hives = Get-RegistryHivePaths -TargetRoot $TargetRoot -HiveType NTUSER
                    Invoke-RegistryKeysWithRECmd -ArtifactKey $key -HivePaths $hives -RegistryKeys @('Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs')
                }
                'UserAssist' {
                    $hives = Get-RegistryHivePaths -TargetRoot $TargetRoot -HiveType NTUSER
                    Invoke-RegistryKeysWithRECmd -ArtifactKey $key -HivePaths $hives -RegistryKeys @('Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist')
                }
                'RunKeys' {
                    $hives = @(
                        Get-RegistryHivePaths -TargetRoot $TargetRoot -HiveType NTUSER
                        Get-RegistryHivePaths -TargetRoot $TargetRoot -HiveType SOFTWARE
                    ) | Sort-Object -Unique
                    Invoke-RegistryKeysWithRECmd -ArtifactKey $key -HivePaths $hives -RegistryKeys @(
                        'Software\Microsoft\Windows\CurrentVersion\Run',
                        'Software\Microsoft\Windows\CurrentVersion\RunOnce',
                        'Microsoft\Windows\CurrentVersion\Run',
                        'Microsoft\Windows\CurrentVersion\RunOnce'
                    )
                }
                'Services' {
                    $hives = Get-RegistryHivePaths -TargetRoot $TargetRoot -HiveType SYSTEM
                    Invoke-RegistryKeysWithRECmd -ArtifactKey $key -HivePaths $hives -RegistryKeys @(
                        'ControlSet001\Services',
                        'ControlSet002\Services',
                        'ControlSet003\Services'
                    )
                }
                'ScheduledTasks' {
                    $hives = Get-RegistryHivePaths -TargetRoot $TargetRoot -HiveType SOFTWARE
                    Invoke-RegistryKeysWithRECmd -ArtifactKey $key -HivePaths $hives -RegistryKeys @(
                        'Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks',
                        'Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree'
                    )
                    $taskXml = Find-ArtifactFiles -TargetRoot $TargetRoot -NamePatterns @('*.job', '*.xml') |
                        Where-Object { $_ -match '\\Windows\\System32\\Tasks(\\|$)' }
                    if ($taskXml.Count -gt 0) {
                        Write-Status -Level 'WARN' -Message "Scheduled task XML/job files were found but not manually parsed. Registry TaskCache was parsed with RECmd."
                        foreach ($path in $taskXml) { Write-Status -Message "Scheduled task file located: $path" }
                    }
                }
                'Srum' {
                    $paths = Find-ArtifactFiles -TargetRoot $TargetRoot -RelativeCandidates @('Windows\System32\sru\SRUDB.dat') -FileNames @('SRUDB.dat')
                    $softwareHive = (Get-RegistryHivePaths -TargetRoot $TargetRoot -HiveType SOFTWARE | Select-Object -First 1)
                    Invoke-FileParser -ArtifactKey $key -ToolName 'SrumECmd.exe' -Paths $paths -ArgumentBuilder {
                        param($path, $out)
                        if ($softwareHive) { @('-f', $path, '-r', $softwareHive, '--csv', $out) } else { @('-f', $path, '--csv', $out) }
                    }
                }
                'RecycleBin' {
                    $paths = Find-ArtifactDirectories -TargetRoot $TargetRoot -RelativeCandidates @('$Recycle.Bin') -DirectoryNames @('$Recycle.Bin')
                    Invoke-FileParser -ArtifactKey $key -ToolName 'RBCmd.exe' -Paths $paths -ArgumentBuilder { param($path, $out) @('-d', $path, '--csv', $out) }
                }
            }
        }
        catch {
            $label = $script:Artifacts[$key].Label
            Write-Status -Level 'ERROR' -Message "$label failed unexpectedly: $($_.Exception.Message)"
            Add-ArtifactResult -Artifact $label -Status 'Unexpected error' -Found 0 -Parsed 0 -Detail $_.Exception.Message
        }
    }

    Write-Status -Message "Completion time: $(Get-Date -Format 'o')"
    $summaryPath = Join-Path $runOutputRoot 'DFIR-Timeline-Parser_Summary.csv'
    $script:ArtifactResults | Export-Csv -LiteralPath $summaryPath -NoTypeInformation -Encoding UTF8
    Write-Status -Level 'SUCCESS' -Message "Summary written to $summaryPath"
}

# Opens a folder picker and writes the selected path to the supplied text box.
function Select-FolderForTextBox {
    param(
        [Parameter(Mandatory)][System.Windows.Forms.TextBox]$TextBox,
        [Parameter(Mandatory)][string]$Description
    )

    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = $Description
    $dialog.ShowNewFolderButton = $true
    if (-not [string]::IsNullOrWhiteSpace($TextBox.Text) -and (Test-Path -LiteralPath $TextBox.Text)) {
        $dialog.SelectedPath = $TextBox.Text
    }

    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $TextBox.Text = $dialog.SelectedPath
    }
}

# Opens an EVTX file picker and writes the selected file path to the supplied text box.
function Select-EvtxFileForTextBox {
    param([Parameter(Mandatory)][System.Windows.Forms.TextBox]$TextBox)

    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = 'Select an EVTX file'
    $dialog.Filter = 'Windows Event Logs (*.evtx)|*.evtx|All files (*.*)|*.*'
    $dialog.Multiselect = $false
    if (-not [string]::IsNullOrWhiteSpace($TextBox.Text)) {
        $candidate = $TextBox.Text
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $dialog.InitialDirectory = Split-Path -Parent $candidate
            $dialog.FileName = Split-Path -Leaf $candidate
        }
        elseif (Test-Path -LiteralPath $candidate -PathType Container) {
            $dialog.InitialDirectory = $candidate
        }
    }

    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $TextBox.Text = $dialog.FileName
    }
}

# Adds one custom EVTX file/folder path to the list, ignoring duplicates.
function Add-CustomEvtxPath {
    param([Parameter(Mandatory)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }

    $resolvedPath = if (Test-Path -LiteralPath $Path) { Get-NormalizedPath -Path $Path } else { $Path }
    foreach ($item in $script:lstCustomEvtx.Items) {
        if ([string]::Equals([string]$item, $resolvedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            return
        }
    }

    [void]$script:lstCustomEvtx.Items.Add($resolvedPath)
    $script:ArtifactCheckboxes['CustomEvtx'].Checked = $true
}

# Returns all custom EVTX paths currently listed in the GUI.
function Get-CustomEvtxPathsFromList {
    $paths = foreach ($item in $script:lstCustomEvtx.Items) {
        [string]$item
    }

    return @($paths)
}

# Opens a multi-select EVTX file picker and adds selected files to the custom EVTX list.
function Select-EvtxFilesForListBox {
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Title = 'Select EVTX file(s)'
    $dialog.Filter = 'Windows Event Logs (*.evtx)|*.evtx|All files (*.*)|*.*'
    $dialog.Multiselect = $true

    if ($script:lstCustomEvtx.Items.Count -gt 0) {
        $firstPath = [string]$script:lstCustomEvtx.Items[0]
        if (Test-Path -LiteralPath $firstPath -PathType Leaf) {
            $dialog.InitialDirectory = Split-Path -Parent $firstPath
        }
        elseif (Test-Path -LiteralPath $firstPath -PathType Container) {
            $dialog.InitialDirectory = $firstPath
        }
    }

    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        foreach ($fileName in $dialog.FileNames) {
            Add-CustomEvtxPath -Path $fileName
        }
    }
}

# Builds and wires the Windows Forms interface.
function New-ParserForm {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'DFIR-Timeline-Parser'
    $form.StartPosition = 'CenterScreen'
    $form.Size = New-Object System.Drawing.Size(1120, 940)
    $form.MinimumSize = New-Object System.Drawing.Size(1020, 800)

    $mainPanel = New-Object System.Windows.Forms.TableLayoutPanel
    $mainPanel.Dock = 'Fill'
    $mainPanel.ColumnCount = 1
    $mainPanel.RowCount = 6
    $mainPanel.Padding = New-Object System.Windows.Forms.Padding(10)
    $mainPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 120))) | Out-Null
    $mainPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 270))) | Out-Null
    $mainPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 128))) | Out-Null
    $mainPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 48))) | Out-Null
    $mainPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $mainPanel.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 32))) | Out-Null
    $form.Controls.Add($mainPanel)

    $pathGrid = New-Object System.Windows.Forms.TableLayoutPanel
    $pathGrid.Dock = 'Fill'
    $pathGrid.ColumnCount = 3
    $pathGrid.RowCount = 3
    $pathGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 170))) | Out-Null
    $pathGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $pathGrid.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 150))) | Out-Null
    $mainPanel.Controls.Add($pathGrid, 0, 0)

    $labels = @('Target root folder', 'Output destination folder', 'EZ Tools folder')
    $buttons = @('Browse Target', 'Browse Output', 'Browse Tools')
    $textBoxes = @()
    for ($i = 0; $i -lt 3; $i++) {
        $label = New-Object System.Windows.Forms.Label
        $label.Text = $labels[$i]
        $label.Dock = 'Fill'
        $label.TextAlign = 'MiddleLeft'
        $pathGrid.Controls.Add($label, 0, $i)

        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Dock = 'Fill'
        $textBox.Anchor = 'Left,Right'
        $pathGrid.Controls.Add($textBox, 1, $i)
        $textBoxes += $textBox

        $button = New-Object System.Windows.Forms.Button
        $button.Text = $buttons[$i]
        $button.Dock = 'Fill'
        $pathGrid.Controls.Add($button, 2, $i)

        switch ($i) {
            0 { $button.Add_Click({ Select-FolderForTextBox -TextBox $script:txtTarget -Description 'Select the mounted or extracted Windows forensic target root.' }) }
            1 { $button.Add_Click({ Select-FolderForTextBox -TextBox $script:txtOutput -Description 'Select or create the output folder for CSVs and logs.' }) }
            2 { $button.Add_Click({
                    Select-FolderForTextBox -TextBox $script:txtTools -Description 'Select the Eric Zimmerman tools folder.'
                    if (-not [string]::IsNullOrWhiteSpace($script:txtTools.Text)) {
                        Save-ParserConfig -ToolsPath $script:txtTools.Text
                    }
                })
            }
        }
    }

    $script:txtTarget = $textBoxes[0]
    $script:txtOutput = $textBoxes[1]
    $script:txtTools = $textBoxes[2]
    $config = Get-ParserConfig
    $script:txtOutput.Text = $script:DefaultOutputPath
    if ($config.ToolsPath -and (Test-Path -LiteralPath $config.ToolsPath -PathType Container)) {
        $script:txtTools.Text = $config.ToolsPath
    }
    else {
        $script:txtTools.Text = $script:DefaultToolsPath
    }

    $artifactGroup = New-Object System.Windows.Forms.GroupBox
    $artifactGroup.Text = 'Artifact selection'
    $artifactGroup.Dock = 'Fill'
    $mainPanel.Controls.Add($artifactGroup, 0, 1)

    $artifactLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $artifactLayout.Dock = 'Fill'
    $artifactLayout.ColumnCount = 3
    $artifactLayout.RowCount = 9
    $artifactLayout.Padding = New-Object System.Windows.Forms.Padding(8)
    foreach ($unused in 1..3) {
        $artifactLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 33.33))) | Out-Null
    }
    $artifactGroup.Controls.Add($artifactLayout)

    $script:ArtifactCheckboxes = @{}
    $index = 0
    foreach ($key in $script:Artifacts.Keys) {
        $checkBox = New-Object System.Windows.Forms.CheckBox
        $checkBox.Text = $script:Artifacts[$key].Label
        $checkBox.Checked = [bool]$script:Artifacts[$key].Default
        $checkBox.AutoSize = $true
        $checkBox.Tag = $key
        $checkBox.Margin = New-Object System.Windows.Forms.Padding(6)
        $script:ArtifactCheckboxes[$key] = $checkBox
        $artifactLayout.Controls.Add($checkBox, ($index % 3), [Math]::Floor($index / 3))
        $index++
    }

    $customEvtxGroup = New-Object System.Windows.Forms.GroupBox
    $customEvtxGroup.Text = 'Custom EVTX input'
    $customEvtxGroup.Dock = 'Fill'
    $mainPanel.Controls.Add($customEvtxGroup, 0, 2)

    $customEvtxLayout = New-Object System.Windows.Forms.TableLayoutPanel
    $customEvtxLayout.Dock = 'Fill'
    $customEvtxLayout.ColumnCount = 5
    $customEvtxLayout.RowCount = 2
    $customEvtxLayout.Padding = New-Object System.Windows.Forms.Padding(8)
    $customEvtxLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $customEvtxLayout.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Absolute, 34))) | Out-Null
    $customEvtxLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 130))) | Out-Null
    $customEvtxLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $customEvtxLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 118))) | Out-Null
    $customEvtxLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 128))) | Out-Null
    $customEvtxLayout.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 118))) | Out-Null
    $customEvtxGroup.Controls.Add($customEvtxLayout)

    $customEvtxLabel = New-Object System.Windows.Forms.Label
    $customEvtxLabel.Text = 'EVTX paths'
    $customEvtxLabel.Dock = 'Fill'
    $customEvtxLabel.TextAlign = 'MiddleLeft'
    $customEvtxLayout.Controls.Add($customEvtxLabel, 0, 0)

    $script:lstCustomEvtx = New-Object System.Windows.Forms.ListBox
    $script:lstCustomEvtx.Dock = 'Fill'
    $script:lstCustomEvtx.HorizontalScrollbar = $true
    $customEvtxLayout.Controls.Add($script:lstCustomEvtx, 1, 0)
    $customEvtxLayout.SetColumnSpan($script:lstCustomEvtx, 4)

    $script:btnBrowseEvtxFile = New-Object System.Windows.Forms.Button
    $script:btnBrowseEvtxFile.Text = 'Add EVTX File'
    $script:btnBrowseEvtxFile.Dock = 'Fill'
    $customEvtxLayout.Controls.Add($script:btnBrowseEvtxFile, 1, 1)

    $script:btnBrowseEvtxFolder = New-Object System.Windows.Forms.Button
    $script:btnBrowseEvtxFolder.Text = 'Add EVTX Folder'
    $script:btnBrowseEvtxFolder.Dock = 'Fill'
    $customEvtxLayout.Controls.Add($script:btnBrowseEvtxFolder, 2, 1)

    $script:btnRemoveEvtxPath = New-Object System.Windows.Forms.Button
    $script:btnRemoveEvtxPath.Text = 'Remove Selected'
    $script:btnRemoveEvtxPath.Dock = 'Fill'
    $customEvtxLayout.Controls.Add($script:btnRemoveEvtxPath, 3, 1)

    $script:btnClearEvtxPaths = New-Object System.Windows.Forms.Button
    $script:btnClearEvtxPaths.Text = 'Clear'
    $script:btnClearEvtxPaths.Dock = 'Fill'
    $customEvtxLayout.Controls.Add($script:btnClearEvtxPaths, 4, 1)

    $buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttonPanel.Dock = 'Fill'
    $buttonPanel.FlowDirection = 'LeftToRight'
    $mainPanel.Controls.Add($buttonPanel, 0, 3)

    $script:btnStart = New-Object System.Windows.Forms.Button
    $script:btnStart.Text = 'Start Parsing'
    $script:btnStart.Width = 150
    $script:btnStart.Height = 34
    $script:btnStart.BackColor = [System.Drawing.Color]::FromArgb(192, 0, 0)
    $script:btnStart.ForeColor = [System.Drawing.Color]::White
    $script:btnStart.FlatStyle = 'Standard'
    $script:btnStart.Font = New-Object System.Drawing.Font($script:btnStart.Font, [System.Drawing.FontStyle]::Bold)
    $buttonPanel.Controls.Add($script:btnStart)

    $script:btnDownload = New-Object System.Windows.Forms.Button
    $script:btnDownload.Text = 'Download/Update EZ Tools'
    $script:btnDownload.Width = 180
    $script:btnDownload.Height = 34
    $buttonPanel.Controls.Add($script:btnDownload)

    $script:btnOpenOutput = New-Object System.Windows.Forms.Button
    $script:btnOpenOutput.Text = 'Open Output Folder'
    $script:btnOpenOutput.Width = 150
    $script:btnOpenOutput.Height = 34
    $buttonPanel.Controls.Add($script:btnOpenOutput)

    $script:txtLog = New-Object System.Windows.Forms.TextBox
    $script:txtLog.Dock = 'Fill'
    $script:txtLog.Multiline = $true
    $script:txtLog.ScrollBars = 'Vertical'
    $script:txtLog.ReadOnly = $true
    $script:txtLog.Font = New-Object System.Drawing.Font('Consolas', 9)
    $mainPanel.Controls.Add($script:txtLog, 0, 4)

    $script:lblStatus = New-Object System.Windows.Forms.Label
    $script:lblStatus.Dock = 'Fill'
    $script:lblStatus.TextAlign = 'MiddleLeft'
    $script:lblStatus.Text = 'Ready.'
    $mainPanel.Controls.Add($script:lblStatus, 0, 5)

    $script:btnBrowseEvtxFile.Add_Click({
        Select-EvtxFilesForListBox
    })

    $script:btnBrowseEvtxFolder.Add_Click({
        $tempTextBox = New-Object System.Windows.Forms.TextBox
        Select-FolderForTextBox -TextBox $tempTextBox -Description 'Select a folder containing Windows event log .evtx files.'
        if (-not [string]::IsNullOrWhiteSpace($tempTextBox.Text)) {
            Add-CustomEvtxPath -Path $tempTextBox.Text
        }
    })

    $script:btnRemoveEvtxPath.Add_Click({
        $selectedItems = @($script:lstCustomEvtx.SelectedItems)
        foreach ($item in $selectedItems) {
            $script:lstCustomEvtx.Items.Remove($item)
        }
        if ($script:lstCustomEvtx.Items.Count -eq 0) {
            $script:ArtifactCheckboxes['CustomEvtx'].Checked = $false
        }
    })

    $script:btnClearEvtxPaths.Add_Click({
        $script:lstCustomEvtx.Items.Clear()
        $script:ArtifactCheckboxes['CustomEvtx'].Checked = $false
    })

    $script:btnOpenOutput.Add_Click({
        $folderToOpen = if (-not [string]::IsNullOrWhiteSpace($script:LastRunOutputRoot) -and (Test-Path -LiteralPath $script:LastRunOutputRoot)) {
            $script:LastRunOutputRoot
        }
        else {
            $script:txtOutput.Text
        }

        if ([string]::IsNullOrWhiteSpace($folderToOpen) -or -not (Test-Path -LiteralPath $folderToOpen)) {
            [System.Windows.Forms.MessageBox]::Show('Choose an existing output folder first.', 'Output Folder', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            return
        }
        Start-Process -FilePath explorer.exe -ArgumentList (Join-WindowsCommandLine -Arguments @($folderToOpen))
    })

    $script:btnDownload.Add_Click({
        try {
            $script:btnDownload.Enabled = $false
            $script:lblStatus.Text = 'Downloading/updating EZ Tools...'

            if ([string]::IsNullOrWhiteSpace($script:txtTools.Text)) {
                throw 'Choose an EZ Tools folder first.'
            }

            Save-ParserConfig -ToolsPath $script:txtTools.Text
            Invoke-EzToolsDownload -ToolsFolder $script:txtTools.Text -TargetRoot $script:txtTarget.Text
            $script:lblStatus.Text = 'EZ Tools update finished.'
        }
        catch {
            Write-Status -Level 'ERROR' -Message $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'EZ Tools Download Failed', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            $script:lblStatus.Text = 'EZ Tools update failed.'
        }
        finally {
            $script:btnDownload.Enabled = $true
        }
    })

    $script:btnStart.Add_Click({
        try {
            $targetRoot = $script:txtTarget.Text.Trim()
            $outputRoot = $script:txtOutput.Text.Trim()
            $toolsRoot = $script:txtTools.Text.Trim()
            $customEvtxPaths = @(Get-CustomEvtxPathsFromList)

            if ([string]::IsNullOrWhiteSpace($targetRoot) -or -not (Test-Path -LiteralPath $targetRoot -PathType Container)) {
                throw 'Choose an existing target root folder.'
            }
            if ([string]::IsNullOrWhiteSpace($outputRoot)) {
                throw 'Choose an output destination folder.'
            }
            if ([string]::IsNullOrWhiteSpace($toolsRoot) -or -not (Test-Path -LiteralPath $toolsRoot -PathType Container)) {
                throw 'Choose an existing EZ Tools folder or use Download/Update EZ Tools first.'
            }

            if (Test-IsSameOrChildPath -Parent $targetRoot -Candidate $outputRoot) {
                $choice = [System.Windows.Forms.MessageBox]::Show(
                    'The output folder is inside the target/evidence folder. This will write parser output into the selected target path. Continue only if this was intentional.',
                    'Confirm Output Inside Target',
                    [System.Windows.Forms.MessageBoxButtons]::YesNo,
                    [System.Windows.Forms.MessageBoxIcon]::Warning
                )
                if ($choice -ne [System.Windows.Forms.DialogResult]::Yes) {
                    return
                }
            }

            if (Test-IsSameOrChildPath -Parent $targetRoot -Candidate $toolsRoot) {
                throw 'The EZ Tools folder cannot be inside the target/evidence folder.'
            }

            $selected = @(
                foreach ($pair in $script:ArtifactCheckboxes.GetEnumerator()) {
                    if ($pair.Value.Checked) { [string]$pair.Key }
                }
            )

            if ($customEvtxPaths.Count -gt 0 -and ($selected -notcontains 'CustomEvtx')) {
                $script:ArtifactCheckboxes['CustomEvtx'].Checked = $true
                $selected += 'CustomEvtx'
            }

            if ($selected.Count -eq 0) {
                throw 'Select at least one artifact type.'
            }

            if ($selected -contains 'CustomEvtx') {
                if ($customEvtxPaths.Count -eq 0) {
                    throw 'Custom EVTX is selected. Add at least one EVTX file or folder, or clear the Custom EVTX checkbox.'
                }
                foreach ($customEvtxPath in $customEvtxPaths) {
                    if (-not (Test-Path -LiteralPath $customEvtxPath)) {
                        throw "The custom EVTX path does not exist: $customEvtxPath"
                    }
                }
            }

            $preflightTools = Get-EzToolMap -ToolsRoot $toolsRoot
            $missing = $selected |
                ForEach-Object { $script:Artifacts[$_].Tool } |
                Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
                Select-Object -Unique |
                Where-Object { -not $preflightTools.ContainsKey($_) }

            if ($missing.Count -gt 0) {
                $message = "Missing required EZ tool(s):`r`n`r`n{0}`r`n`r`nUse Download/Update EZ Tools, or continue and let unavailable artifact parsers be skipped?" -f ($missing -join "`r`n")
                $choice = [System.Windows.Forms.MessageBox]::Show($message, 'Missing EZ Tools', [System.Windows.Forms.MessageBoxButtons]::YesNo, [System.Windows.Forms.MessageBoxIcon]::Warning)
                if ($choice -ne [System.Windows.Forms.DialogResult]::Yes) {
                    return
                }
            }

            $script:btnStart.Enabled = $false
            $script:btnDownload.Enabled = $false
            $script:lblStatus.Text = 'Parsing selected artifacts...'
            Save-ParserConfig -ToolsPath $toolsRoot

            Invoke-SelectedParsing -TargetRoot $targetRoot -OutputRoot $outputRoot -ToolsRoot $toolsRoot -SelectedArtifactKeys $selected -CustomEvtxPaths $customEvtxPaths

            $success = ($script:ArtifactResults | Where-Object { $_.Status -eq 'Parsed' }).Count
            $problem = ($script:ArtifactResults | Where-Object { $_.Status -ne 'Parsed' }).Count
            $summary = "Parsing complete.`r`n`r`nParsed: $success`r`nWarnings/failures/not parsed: $problem`r`n`r`nOutput folder:`r`n$script:CurrentOutputRoot`r`n`r`nLog file:`r`n$script:LogFile"
            [System.Windows.Forms.MessageBox]::Show($summary, 'Parsing Complete', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            $script:lblStatus.Text = 'Parsing complete.'
        }
        catch {
            Write-Status -Level 'ERROR' -Message $_.Exception.Message
            [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, 'Parsing Failed', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            $script:lblStatus.Text = 'Parsing failed.'
        }
        finally {
            $script:btnStart.Enabled = $true
            $script:btnDownload.Enabled = $true
        }
    })

    return $form
}

$form = New-ParserForm
[void][System.Windows.Forms.Application]::Run($form)
