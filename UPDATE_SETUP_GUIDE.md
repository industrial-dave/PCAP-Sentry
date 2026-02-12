# Quick Start: Enable Updates for PCAP Sentry

To make PCAP Sentry updateable when installed, I've added an integrated update system. Here's what was added:

## Files Added

1. **`Python/update_checker.py`** - The update checking and downloading logic
   - Checks GitHub for new releases
   - Downloads and installs updates
   - Handles version comparison and cleanup

## Files Modified

1. **`Python/pcap_sentry_gui.py`** - Integrated update UI
   - Added "Check for Updates" button in toolbar
   - Added update checking and downloading methods
   - Graceful fallback if update checker unavailable

## How It Works

### User Experience
1. Click "Check for Updates" button in the toolbar
2. App checks GitHub for newer versions
3. If available, shows update dialog with release notes
4. User can download and launch installer with one click
5. App can auto-close to allow installation

### Technical Flow
- **Version Checking**: Compares `APP_VERSION` from current app with latest GitHub release
- **Download Location**: `%APPDATA%\PCAP Sentry\updates\`
- **Network**: Uses HTTPS to GitHub API (api.github.com)
- **Background**: Update checks run in background threads (non-blocking UI)

## Features

✅ **One-Click Updates** - "Check for Updates" button in main toolbar
✅ **GitHub Integration** - Automatically fetches from industrial-dave/PCAP-Sentry releases
✅ **Smart Version Comparison** - Handles various version formats (2.1.0, 2026.02.11-1, etc.)
✅ **Download & Install** - Downloads installer and launches it automatically
✅ **Release Notes Display** - Shows changelog before downloading
✅ **Non-Blocking** - Background checking doesn't freeze the UI
✅ **Error Handling** - Gracefully handles network issues and failures
✅ **Auto-Cleanup** - Removes old update files automatically

## Prerequisites

The system requires:
- Python 3.6+ (for SSL context support - already installed with PyInstaller builds)
- Internet connectivity for update checks
- GitHub Releases published with executable named `PCAP_Sentry.exe`

## No Additional Dependencies!

The update system uses only Python standard library:
- `urllib` - HTTPS downloads
- `json` - GitHub API response parsing
- `ssl` - Secure connections
- `threading` - Background operations
- `os` - File management

**No new pip packages required!**

## Building for Distribution

When building releases for installation:

1. Update version in `pcap_sentry_gui.py`:
   ```python
   APP_VERSION = "2.1.0"  # Update this
   ```

2. Build EXE:
   ```bash
   build_exe.bat
   ```

3. Create GitHub Release:
   - Tag: Same as version (e.g., `v2.1.0`)
   - Attach the built `PCAP_Sentry.exe` from `dist/` folder
   - Add release notes in description

4. Build installer:
   ```bash
   build_installer.bat
   ```

Now when users have PCAP Sentry installed, they can click "Check for Updates" and get the new version!

## Testing Updates

To test locally without publishing:

1. Create a test release on GitHub with a higher version number
2. Attach a test `PCAP_Sentry.exe`
3. Run current version and click "Check for Updates"
4. Watch for update prompt

## Troubleshooting

**Update button doesn't appear?**
- Ensure `update_checker.py` is in `Python/` directory
- Check console for import errors

**"Failed to check for updates"?**
- Check internet connection
- Verify firewall allows access to api.github.com
- Check GitHub API status at status.github.com

**Update downloads but won't install?**
- Make sure installer has proper permissions
- Check Windows antivirus isn't blocking execution
- Verify you have rights to modify Program Files

## What Users See

### When checking for updates:
- "Checking for updates..." message appears
- Background check happens (non-blocking)
- Update dialog shows if newer version available
- Displays current vs. new version
- Shows release notes

### If update available:
- Two options: "Download & Update" or "Later"
- Download shows progress bar
- Installer launches automatically
- Can choose to close app immediately or later

### If already latest:
- Simple confirmation: "You are running the latest version (X.X.X)"

## Next Steps

1. ✅ Commit these changes to git
2. ✅ Test the update checker locally
3. ✅ Make sure `update_checker.py` is included in version control
4. ✅ When ready to release, create a GitHub release with the new EXE
5. ✅ Users can then update from that version forward

That's it! Your app is now updateable! 🎉
