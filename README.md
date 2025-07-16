# 🧬 Thread Pool Timer Process Injection

> ⚠️ **Educational Research Only**  
> This repository contains security research for **educational purposes** and **authorized use only**.  
> Use responsibly and in accordance with all applicable laws and regulations.

---

## 📖 Overview

**Thread Pool Timer Process Injection** is a novel technique that leverages the Windows thread pool infrastructure to execute shellcode. By combining traditional DLL injection with the `CreateThreadpoolTimer` API, this method enables in-memory code execution through legitimate system-managed threads—potentially bypassing many modern detection mechanisms.

This approach introduces a stealthy execution vector that avoids classic API hooks such as `CreateRemoteThread`, `NtCreateThreadEx`, and APCs, making it highly attractive for red team operations and malware research.

---

## 🔬 Research Contribution

This project presents the **first publicly documented use of `CreateThreadpoolTimer` for shellcode execution in a process injection scenario**. Extensive searches across research portals, GitHub, and offensive security communities confirmed the uniqueness of this implementation.

---

### 💡 Key Highlights

- **Novel Execution Vector:** Utilizes Windows thread pool timer callbacks to run shellcode.
- **Legitimate Infrastructure:** Executes code within native Windows-managed worker threads.
- **Evasion Potential:** Generates telemetry that differs from well-known injection behaviors.
- **API Innovation:** Unique pairing of `CreateThreadpoolTimer` with a custom injection strategy.

---

Want help generating sections for:
- 🛠 Build Instructions  
- 🚀 Usage & Testing  
- 🔒 Mitigations or Detection Ideas  


🛠️ Technical Implementation

<img width="732" height="172" alt="image" src="https://github.com/user-attachments/assets/60df6f0d-b2e9-4d88-88c1-da88a3d1217a" />

## 🔄 Execution Flow

**Injection Phase:**  
Traditional DLL injection into the target process using `CreateRemoteThread` and `LoadLibraryW`.

**Timer Setup:**  
Thread pool timer is created using `CreateThreadpoolTimer()` and armed via `SetThreadpoolTimer()`.

**Callback Execution:**  
The configured timer fires inside the target process's context and triggers the callback function.

**Code Execution:**  
Shellcode or malicious logic is executed directly via the timer callback mechanism.

---

## 🧩 Core Components

### 🛠 Main Injector (`Injector.cpp`)
- Process enumeration and targeting logic  
- DLL injection using `CreateRemoteThread` and `LoadLibraryW`  
- Error handling and execution status reporting  

### ⏲ Timer DLL (`TimerDLL.cpp`)
- Timer-based shellcode execution implementation  
- `TP_CALLBACK_ENVIRON` structure setup for thread pool configuration  
- Execution of shellcode via the timer callback  


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
