# DFIR-Timeline-Parser

Windows Forms PowerShell GUI for parsing an extracted or mounted Windows target with Eric Zimmerman tools and writing CSV output for Timeline Explorer.

## Run The GUI

Open 64-bit Windows PowerShell and run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
& "C:\Path\To\DFIR-Timeline-Parser\DFIR-Timeline-Parser.ps1"
```

If you are running it from the folder that contains the script:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
& ".\DFIR-Timeline-Parser.ps1"
```

## Recommended Paths

Target root:

```text
C:\Path\To\Mounted-Or-Extracted-Target
```

EZ Tools folder:

```text
C:\Path\To\DFIR-Timeline-Parser\ez
```

Output folder example:

```text
%USERPROFILE%\Desktop
```

Avoid choosing the evidence/source folder as the output folder.

The selected output folder is treated as a destination parent. Each parse creates a new timestamped run folder inside it:

```text
DFIR-Timeline-Parser_YYYYMMDD_HHMMSS
```

All artifact folders, parser logs, and summary files for that run are written inside the timestamped folder so the Desktop or parent output folder stays tidy.

The GUI defaults the output path to the current logged-in user's Desktop. The EZ Tools path is remembered in:

```text
DFIR-Timeline-Parser.config.json
```

When you use **Browse Tools** or start a parse, the selected EZ Tools path is saved for the next launch. This file is generated locally and may contain workstation-specific paths. Use `DFIR-Timeline-Parser.config.sample.json` as the publish-safe example.

## Parsing Custom Event Logs

Use the **EVTX - Custom file/folder** checkbox.

Then use the custom EVTX buttons underneath the artifact checklist:

- **Add EVTX File** to add one or more `.evtx` files.
- **Add EVTX Folder** to add a folder.
- **Remove Selected** to remove highlighted entries.
- **Clear** to empty the custom EVTX list.

There is no fixed limit on custom EVTX entries. If you add a folder, the script recursively finds every `.evtx` file underneath that folder and parses each one with EvtxECmd.

Custom EVTX output is written under:

```text
CustomEvtx
```

inside the selected output folder.

## Artifact Tool Coverage

Every GUI checkbox maps to a configured Eric Zimmerman command-line tool. Options without a configured parser are not exposed as artifact checkboxes.

Optional checkbox mappings:

- LNK files: `LECmd.exe`
- Jump Lists: `JLECmd.exe`
- Shellbags, RecentDocs, UserAssist, Run keys, Services, and Scheduled Tasks registry data: `RECmd.exe`
- SRUM: `SrumECmd.exe`
- Recycle Bin: `RBCmd.exe`

## MFT Note

For large `$MFT` files, use the `ez` tools folder, not `ez8`.

The workspace includes a portable .NET 9 runtime under:

```text
work\dotnet9
```

The GUI script auto-detects that runtime so the .NET 9 MFTECmd build can parse large MFTs without requiring a system-wide .NET install.

## Outputs

Each run creates a timestamped output folder. Inside that folder, each artifact type gets its own output folder. Every run also writes:

```text
DFIR-Timeline-Parser_YYYYMMDD_HHMMSS.log
DFIR-Timeline-Parser_Summary.csv
```

The log records selected artifacts, paths found, tools used, commands executed, missing artifacts, missing tools, parser errors, and completion time.

## Output Folder Map

| Output folder | Artifact | Tool |
| --- | --- | --- |
| `MFT` | `$MFT` | `MFTECmd.exe` |
| `LogFile` | `$LogFile` | `MFTECmd.exe` |
| `UsnJournal` | `$Extend\$J` / USN Journal | `MFTECmd.exe` |
| `EvtxSecurity` | `Security.evtx` | `EvtxECmd.exe` |
| `EvtxSysmon` | Sysmon Operational EVTX | `EvtxECmd.exe` |
| `EvtxDefender` | Windows Defender Operational EVTX | `EvtxECmd.exe` |
| `EvtxRdp` | RDP / Terminal Services EVTX logs | `EvtxECmd.exe` |
| `CustomEvtx` | Analyst-selected EVTX files or folders | `EvtxECmd.exe` |
| `Prefetch` | Windows Prefetch | `PECmd.exe` |
| `ShimCache` | ShimCache from `SYSTEM` hive | `AppCompatCacheParser.exe` |
| `Amcache` | `Amcache.hve` | `AmcacheParser.exe` |
| `LnkFiles` | `.lnk` shortcut files | `LECmd.exe` |
| `JumpLists` | Automatic and Custom Destinations | `JLECmd.exe` |
| `Shellbags` | Shellbag registry keys | `RECmd.exe` |
| `RecentDocs` | RecentDocs registry keys | `RECmd.exe` |
| `UserAssist` | UserAssist registry keys | `RECmd.exe` |
| `RunKeys` | Run and RunOnce registry keys | `RECmd.exe` |
| `Services` | Services registry keys | `RECmd.exe` |
| `ScheduledTasks` | TaskCache registry keys | `RECmd.exe` |
| `Srum` | `SRUDB.dat` | `SrumECmd.exe` |
| `RecycleBin` | `$Recycle.Bin` | `RBCmd.exe` |
| `_process_logs` | Captured parser stdout/stderr | Created by this wrapper |

## Credits

This project is a PowerShell GUI wrapper around Eric Zimmerman's forensic tools. The parsing work is performed by the EZ Tools executables selected in the GUI. Credit and thanks to Eric Zimmerman for creating and maintaining those tools.
