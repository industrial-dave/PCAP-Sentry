# PCAP Sentry Update System - Quick Reference

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    PCAP Sentry Application                   │
│                   (Installed on User's PC)                   │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │
                    User clicks button
                    "Check for Updates"
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│           Update Checker (update_checker.py)                │
│  ► BackgroundUpdateChecker - Runs in thread                │
│  ► Connects to GitHub API (HTTPS)                         │
│  ► Compares versions                                       │
└─────────────────────────────────────────────────────────────┘
                              │
                    HTTPS Secure Connection
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│         GitHub API Endpoint (GitHub Public)                │
│  https://api.github.com/repos/industrial-dave/             │
│                     PCAP-Sentry/releases/latest            │
│                                                             │
│  Returns JSON:                                             │
│  ► tag_name: "v2.1.0"                                      │
│  ► body: "Release notes..."                                │
│  ► assets: [{ name: "PCAP_Sentry.exe",                     │
│              browser_download_url: "..." }]               │
└─────────────────────────────────────────────────────────────┘
                              │
                    Version Comparison
                   Is new > current?
                              │
                ┌─────────────┴──────────────┐
                ▼                            ▼
            YES (Update)              NO (Latest)
                │                            │
                ▼                            ▼
    ┌──────────────────┐        ┌─────────────────────┐
    │ Show dialog:     │        │ Show confirmation:  │
    │ "Update ready"   │        │ "Already latest"    │
    │ • New version    │        └─────────────────────┘
    │ • Release notes  │
    │ • Download btn   │
    └──────────────────┘
            │
    User clicks "Download"
            │
            ▼
    ┌──────────────────────────────┐
    │ Download installer from URL  │
    │ Show progress bar            │
    │ Save to:                     │
    │ %APPDATA%\PCAP Sentry\       │
    │  updates\PCAP_Sentry_        │
    │ 2.1.0_20260211_120000.exe   │
    └──────────────────────────────┘
            │
            ▼
    ┌──────────────────────────────┐
    │ Launch installer             │
    │ (Standard Windows installer) │
    │                              │
    │ User completes installation  │
    │ • Chooses install location   │
    │ • Completes wizard           │
    │ • New version installed      │
    └──────────────────────────────┘
            │
            ▼
    ┌──────────────────────────────┐
    │ App offers to close:         │
    │ "Close app now?" Yes/No      │
    │                              │
    │ User restarts app → Gets     │
    │ new version!                 │
    └──────────────────────────────┘
```

## Component Interaction Diagram

```
PCAPSentryApp (GUI)
    │
    ├─ Toolbar
    │   └─ "Check for Updates" Button (NEW)
    │       └─ calls: _check_for_updates_ui()
    │           │
    │           ├─► BackgroundUpdateChecker(thread)
    │           │       └─► UpdateChecker.fetch_latest_release()
    │           │               └─► HTTPS to GitHub
    │           │                   └─► Returns version info
    │           │
    │           ├─► Display dialog if update found
    │           │
    │           └─► _download_and_install_update()
    │               ├─► UpdateChecker.download_update()
    │               │   └─► Show progress dialog
    │               └─► UpdateChecker.launch_installer()
    │                   └─► User runs installer
    │
    └─ Settings saved to: %APPDATA%\PCAP Sentry\settings.json
```

## Data Flow Diagram

```
CURRENT STATE:
┌─────────────────────────────────┐
│ PCAP Sentry v2.1.0 (Installed)  │
│                                 │
│ APP_VERSION = "2.1.0"          │
│                                 │
│ User clicks "Check for Updates" │
├─────────────────────────────────┤
│ Update check initiated          │
│ Background thread started       │
│ GitHub API called               │
│ Latest release fetched          │
│ → Version: 2.1.1               │
│ → Notes: "Bug fixes..."         │
│ → File: PCAP_Sentry.exe         │
├─────────────────────────────────┤
│ Version comparison:             │
│ 2.1.1 > 2.1.0 = UPDATE FOUND   │
├─────────────────────────────────┤
│ Dialog shown to user:           │
│ "Update Available"              │
│ Current: 2.1.0                  │
│ Available: 2.1.1                │
│ Release Notes: [displayed]      │
│                                 │
│ [Download & Update] [Later]     │
└─────────────────────────────────┘
                │
        User clicks button
                │
                ▼
        ┌──────────────────────┐
        │ Download starts      │
        │ Target: %APPDATA%\   │
        │ PCAP Sentry\updates\ │
        │ PCAP_Sentry_2.1.1_   │
        │ 20260211_120000.exe  │
        │                      │
        │ [████████░░░] 75%    │
        └──────────────────────┘
                │
        Download completes
                │
                ▼
        ┌──────────────────────┐
        │ Installer launches   │
        │                      │
        │ (Windows Installer)  │
        │ ► Select location    │
        │ ► Install files      │
        │ ► Complete setup     │
        └──────────────────────┘
                │
        Installation complete
                │
                ▼
        ┌──────────────────────┐
        │ PCAP Sentry v2.1.1   │
        │ INSTALLED & READY    │
        │                      │
        │ User restarts app    │
        │ Updated version runs │
        │ Fully updated!       │
        └──────────────────────┘

FINAL STATE:
✓ PCAP Sentry v2.1.1 (Installed)
  APP_VERSION = "2.1.1"
  All new features available
  Bug fixes applied
```

## File Locations

### Application Location (after install):
```
C:\Program Files\PCAP Sentry\
    ├── PCAP_Sentry.exe           ← Main application
    ├── library.zip               ← Python runtime
    ├── *.pyd                     ← Libraries
    └── ...
```

### User Data Location:
```
%APPDATA%\PCAP Sentry\
    ├── settings.json             ← App preferences
    ├── startup_errors.log        ← Startup log
    ├── app_errors.log            ← Error log
    │
    └── updates/
        ├── PCAP_Sentry_2.1.0_20260211_120000.exe  ← Downloaded updates
        ├── PCAP_Sentry_2.1.1_20260212_140000.exe
        └── ...                                    ← (max 3 kept)
```

## Process Timeline

```
TIME    ACTION
────    ──────────────────────────────────────────────────────
T0:00   User launches PCAP Sentry
        │
T0:05   → App fully loaded, toolbar visible
        │
        User clicks "Check for Updates"
        │
T0:07   ► Dialog: "Checking for updates..."
        │ (background thread starts)
        │
T0:08   ► HTTPS connection to GitHub initiated
        │
T0:10   ► GitHub responds with latest release info
        │ - Latest version: 2.1.1
        │ - Current version: 2.1.0
        │ - Update available: YES
        │
T0:12   ► Update dialog appears with:
        │   - Version comparison
        │   - Release notes
        │   - Download button
        │
        User clicks "Download & Update"
        │
T0:13   ► Download progress dialog appears
        │
T0:35   ► Download completes (22 MB)
        │
        ► Installer launches automatically
        │
T1:00   User completes Windows installer
        │
        ► App offers to close
        │
        User clicks "Yes"
        │
T1:05   App closes
        │ 
        Installer finishes
        │
        UPDATED! ✓ PCAP Sentry 2.1.1 installed
        │
        User relaunches app
        │
T1:10   → PCAP Sentry v2.1.1 starts with all new features!
```

## Error Handling Paths

```
Check for Updates
    │
    ├─► Network Error
    │   └─► "Failed to check for updates: Connection timeout"
    │
    ├─► GitHub API Error
    │   └─► "Failed to check for updates: API error"
    │
    ├─► No Release Found
    │   └─► "Failed to check for updates: No releases available"
    │
    ├─► No Executable in Release
    │   └─► "Failed to check for updates: No executable found"
    │
    ├─► Download Error
    │   └─► "Failed to download the update"
    │
    ├─► Installer Launch Error
    │   └─► "Update downloaded to: [path] - Please run manually"
    │
    └─► Success!
        └─► Update dialog shown or latest confirmation
```

## Version Comparison Logic

```
Current: 2.1.0    Latest: 2.1.1
Parse:   [2,1,0]  Parse:  [2,1,1]
Compare: [2,1,0] < [2,1,1] ? YES → UPDATE AVAILABLE ✓

Current: 2.1.0    Latest: 2026.02.11-1
Parse:   [2,1,0]  Parse:  [2026,2,11,1]
Compare: [2,1,0] < [2026,2,11,1] ? YES → UPDATE AVAILABLE ✓

Current: 2.1.0    Latest: 2.0.9
Parse:   [2,1,0]  Parse:  [2,0,9]
Compare: [2,1,0] < [2,0,9] ? NO → ALREADY LATEST ✓
```

---

**Use this diagram set to understand the architecture and flow of the update system!**
