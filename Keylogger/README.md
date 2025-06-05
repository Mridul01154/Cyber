# Windows Keylogger (Educational Purpose Only)

> ⚠️ **Disclaimer**: This software is intended **solely for educational and ethical penetration testing** purposes. Unauthorized use to spy on individuals or systems without consent may be **illegal**. The author is not responsible for any misuse of this code.

## Overview

This is a simple Windows-based keylogger written in C that:
- Hides its console window upon execution
- Copies itself to the system's temporary directory as `sysupdate.exe`
- Runs in the background, logging keystrokes to `system.log`
- Terminates if the `ESC` key is pressed

## Features

- Logs both alphanumeric and special keys
- Records keystrokes with timestamps
- Runs silently in the background
- Supports uppercase/lowercase detection using Shift and Caps Lock
- Saves logs to a file named `system.log`

## How It Works

1. **Console Hiding**: The `hideConsole()` function uses WinAPI to hide the running console.
2. **Self-Copying**: The `moveToTempDir()` function copies the binary to the system temp directory and re-runs itself under the new name.
3. **Key Logging**: A new thread is created to capture keystrokes using `GetAsyncKeyState`.
4. **Log Format**: Each keystroke is logged with a timestamp and saved to `system.log`.

## File Structure

