Thread Pool Timer Process Injection

⚠️ Educational Research Only
This repository contains security research for educational purposes and authorized activity. Use responsibly and in accordance with applicable laws and regulations.

Overview
Thread Pool Timer Process Injection is a novel process injection technique that leverages Windows thread pool infrastructure for code execution. By combining traditional DLL injection with CreateThreadpoolTimer API calls, this method executes code through legitimate Windows mechanisms while potentially evading common detection patterns.

🔬 Research Contribution
This technique represents the first documented use of CreateThreadpoolTimer for process injection purposes. Our comprehensive analysis revealed no existing public documentation of this specific API combination for code execution.

Novel Execution Vector: Uses Windows thread pool timer callbacks
Legitimate Infrastructure: Executes within Windows-managed thread pool workers
Evasion Potential: Different telemetry signature than known injection methods
API Combination: Unique pairing of CreateThreadpoolTimer with injection techniques

🛠️ Technical Implementation
Architecture
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  DLL Injection  │───▶│  Timer Creation  │───▶│ Code Execution  │
│   (Traditional) │    │     (Novel)      │    │  (via Callback) │
└─────────────────┘    └──────────────────┘    └─────────────────┘
Execution Flow

Injection Phase: Traditional DLL injection into target process
Timer Setup: Thread pool timer created with configurable delay
Callback Execution: Timer callback fires in target process context
Code Execution: Shellcode executed through timer callback mechanism

Core Components
1. Main Injector (Injector.cpp)

Process enumeration and targeting
DLL injection using CreateRemoteThread + LoadLibraryW
Error handling and status reporting

2. Timer DLL (TimerDLL.cpp)

Timer-based execution implementation
TP_CALLBACK_ENVIRON configuration
Shellcode execution via timer callback

📋 API Sequence
Traditional Injection APIs
cppOpenProcess()           // Target process access
VirtualAllocEx()        // Remote memory allocation  
WriteProcessMemory()    // DLL path writing
CreateRemoteThread()    // Remote thread creation
LoadLibraryW()          // DLL loading

Timer APIs
cppInitializeThreadpoolEnvironment()  // Callback environment setup
CreateThreadpoolTimer()            // Timer object creation
SetThreadpoolTimer()               // Timer scheduling
TimerCallback()                    // Execution vector

![Recording 2025-07-16 1317152323](https://github.com/user-attachments/assets/fe7d0f6f-a1e0-4198-8e06-dec994e42bd6)
