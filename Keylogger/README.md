Disclaimer: This project is strictly for educational and ethical purposes. Do not use this code to invade privacy, violate laws, or breach terms of service.

This is a basic Windows-based keylogger implemented in C, demonstrating how low-level keyboard input can be captured using the WinAPI. The program logs keystrokes, formats them with timestamps, and writes them to a disguised log file. It also hides its console window and attempts to persist by copying itself to the system's temp directory.

⚙️ Features
Captures printable characters, control keys (e.g., Enter, Shift, Backspace)

Timestamps each logged keystroke

Detects and logs key combinations (e.g., Shift + letter, Caps Lock behavior)

Hides the console window on startup

Moves and relaunches itself from the %TEMP% directory as sysupdate.exe

Stores logs in a local file named system.log

Gracefully exits when the ESC key is pressed

📁 How It Works
The program hides the console using ShowWindow(hwnd, SW_HIDE).

It copies itself to the Windows Temp directory with a disguised name (sysupdate.exe).

It spawns a new thread to continuously listen for keypresses using GetAsyncKeyState.

Keystrokes are logged to a file named system.log with time-based formatting.

⚠️ Warning
This software can be misused. Running this without proper consent is illegal and unethical. Please ensure:

You have explicit permission to run this on any machine.

It is used only in controlled, authorized, or educational environments (e.g., labs, security research).

You understand and respect applicable local laws and terms of use.
