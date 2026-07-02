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

To parse the entire standard Windows event log folder from the selected target, tick:

```text
EVTX - All logs folder
```

This automatically parses every `.evtx` file under:

```text
Windows\System32\winevt\Logs
```

When **EVTX - All logs folder** is selected, the focused EVTX checkboxes for Security, Sysmon, Windows Defender, and RDP/Terminal Services are disabled to avoid parsing the same logs twice. The Custom EVTX input is also disabled because All Logs and Custom EVTX are mutually exclusive modes.

Use the **EVTX - Custom file/folder** checkbox inside the **Custom EVTX input** section.

The custom EVTX path list and buttons stay disabled until that checkbox is selected. Then use:

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

Most GUI checkboxes map to a configured Eric Zimmerman command-line tool. Options without a configured parser are not exposed as artifact checkboxes.

Browser history is selected by default and is the exception: it uses the integrated SQLite exporter because browser history databases are not parsed by the configured EZ Tools command set. The exporter copies Chrome, Edge, Brave, Chromium, Vivaldi, Opera, Opera GX, and Firefox browser databases into the run output folder first, parses those copies, and does not modify the evidence/source folder. Python 3 is required for this artifact.

Optional checkbox mappings:

- LNK files: `LECmd.exe`
- Jump Lists: `JLECmd.exe`
- Shellbags, RecentDocs, UserAssist, Run keys, Services, and Scheduled Tasks registry data: `RECmd.exe`
- SRUM: `SrumECmd.exe`
- Recycle Bin: `RBCmd.exe`
- Browser history: integrated SQLite exporter with Python 3

## MFT Note

For large `$MFT` files, use the `ez` tools folder, not `ez8`.

The workspace includes a portable .NET 9 runtime under:

```text
work\dotnet9
```

The GUI script auto-detects that runtime so the .NET 9 MFTECmd build can parse large MFTs without requiring a system-wide .NET install.

## USN Journal Note

The USN Journal parser targets:

```text
$Extend\$J
```

`$J` contains the USN change records that MFTECmd exports to timeline-friendly CSV. When `$MFT` is available, the GUI passes it to MFTECmd with `-m` so USN output can include better parent path resolution.

The companion `$Extend\$Max` stream contains USN journal metadata/settings. The GUI logs when `$Max` is present, but it is not exported as event records because it does not contain the `$J` change journal timeline data.

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
| `EvtxAll` | All `.evtx` files under `Windows\System32\winevt\Logs` | `EvtxECmd.exe` |
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
| `BrowserHistory` | Browser history and downloads | Integrated SQLite exporter |
| `Troubleshooting_Logs` | Captured parser stdout/stderr troubleshooting logs | Created by this wrapper |

## Browser History Outputs

When selected, browser history output is written under:

```text
BrowserHistory
```

Files created:

- `BrowserHistory.csv`
- `BrowserDownloads.csv`
- `BrowserHistoryAndDownloads_All.csv`
- `BrowserHistoryExport_Errors.csv`
- `browser_manifest.json`

`BrowserDownloads.csv` columns:

```text
User,Browser,Time,DownloadUrl,TabUrl,ReferrerUrl,TargetPath,CurrentPath
```

Browser times are exported in UTC with a trailing `Z`.

## Credits

This project is primarily a PowerShell GUI wrapper around Eric Zimmerman's forensic tools. Credit and thanks to Eric Zimmerman for creating and maintaining EZ Tools. The optional browser-history workflow uses an integrated SQLite exporter because that artifact family is outside the configured EZ Tools parser set.


