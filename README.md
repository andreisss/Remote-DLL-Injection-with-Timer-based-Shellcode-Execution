# Remote DLL Injection with Timer-based Shellcode Execution
 

> ⚠ **Educational Research Only**  
> This repository contains security research for **educational purposes** and **authorized use only**.  
> Use responsibly and in accordance with all applicable laws and regulations.

---

## Overview

**Thread Pool Timer Process Injection** is a technique that leverages the Windows thread pool to execute shellcode. Using the classic DLL injection with CreateThreadpoolTimer to run shellcode in-memory using legit system threads, stealthy, and likely to slip past modern defenses

This approach introduces a stealthy execution vector that avoids classic API hooks such as `CreateRemoteThread`, `NtCreateThreadEx`, and APCs, making it highly attractive for red team operations and malware research.

---

![Recording 2025-07-16 1317152323](https://github.com/user-attachments/assets/fe7d0f6f-a1e0-4198-8e06-dec994e42bd6)

---

---

🛠️ Technical Implementation

<img width="732" height="172" alt="image" src="https://github.com/user-attachments/assets/60df6f0d-b2e9-4d88-88c1-da88a3d1217a" />

---

## 🧩 Core Components

### 🛠 Main Injector (`ConsoleApplication5.cpp`)
- Process enumeration and targeting logic  
- DLL injection using `CreateRemoteThread` and `LoadLibraryW`  
- Error handling and execution status reporting  

### ⏲ Timer DLL (`Dll1.cpp`)
- Timer-based shellcode execution implementation  
- `TP_CALLBACK_ENVIRON` structure setup for thread pool configuration  
- Execution of shellcode via the timer callback  
