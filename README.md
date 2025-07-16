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

<img width="732" height="172" alt="image" src="https://github.com/user-attachments/assets/60df6f0d-b2e9-4d88-88c1-da88a3d1217a" />



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

## 📋 API Sequence

### 🧪 Traditional Injection APIs
```cpp
OpenProcess()           // Access the target process
VirtualAllocEx()        // Allocate memory in remote process  
WriteProcessMemory()    // Write shellcode or DLL path
CreateRemoteThread()    // Create a remote thread to execute payload
LoadLibraryW()          // Load a DLL via thread execution


⏱️ Thread Pool Timer-Based APIs

InitializeThreadpoolEnvironment()  // Configure threadpool callback environment
CreateThreadpoolTimer()            // Create a timer object
SetThreadpoolTimer()               // Schedule the timer for execution
TimerCallback()                    // Callback function that executes shellcode

![Recording 2025-07-16 1317152323](https://github.com/user-attachments/assets/fe7d0f6f-a1e0-4198-8e06-dec994e42bd6)
