/*
 * checks.c -- Windows sandbox/VM/debugger detection probes.
 *
 * Educational proof-of-concept: every function only inspects the environment and
 * reports a boolean. No payload, no evasion, no tampering.
 *
 * By ARXHR007 ;)
 */
#define _WIN32_WINNT 0x0600
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <iphlpapi.h>
#include <time.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <winreg.h>
#include <cpuid.h>
#include <ctype.h>

#include "detector.h"
#include "checks.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

/* ------------------------------------------------------------------ helpers */

static char* getRegValue(HKEY hKey, const char* subKey, const char* valueName) {
    HKEY hSubKey;
    LONG result = RegOpenKeyExA(hKey, subKey, 0, KEY_READ, &hSubKey);
    if (result != ERROR_SUCCESS) {
        return NULL;
    }
    DWORD bufferSize = 1024;
    /* +1 so we can always NUL-terminate: RegQueryValueExA does not promise a
       terminator for REG_SZ, and the value is later handed to strstr(). */
    char* buffer = (char*)malloc(bufferSize + 1);
    if (buffer == NULL) {
        RegCloseKey(hSubKey);
        return NULL;
    }
    DWORD valueType;
    DWORD returnedSize = bufferSize;
    result = RegQueryValueExA(hSubKey, valueName, NULL, &valueType, (LPBYTE)buffer, &returnedSize);
    RegCloseKey(hSubKey);
    if (result != ERROR_SUCCESS) {
        free(buffer);
        return NULL;
    }
    if (returnedSize > bufferSize) {
        returnedSize = bufferSize;
    }
    buffer[returnedSize] = '\0';
    return buffer;
}

static bool regKeyExists(HKEY hKey, const char* subKey) {
    HKEY hSubKey;
    if (RegOpenKeyExA(hKey, subKey, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
        RegCloseKey(hSubKey);
        return true;
    }
    return false;
}

static bool isProcessRunningByName(const char* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false;
    }
    do {
        if (_stricmp(entry.szExeFile, processName) == 0) {
            CloseHandle(snapshot);
            return true;
        }
    } while (Process32Next(snapshot, &entry));
    CloseHandle(snapshot);
    return false;
}

/* ------------------------------------------------------------ system checks */

static bool hasVirtualMacAddress(void) {
    const char* vmPrefixes[] = {
        "00-05-69", "00-0C-29", "00-1C-14", "00-50-56", "00-1C-42",
        "00-03-FF", "00-0F-4B", "00-16-3E", "08-00-27"
    };
    int prefixCount = (int)(sizeof(vmPrefixes) / sizeof(vmPrefixes[0]));
    ULONG bufferSize = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &bufferSize);
    if (bufferSize == 0) {
        return false;
    }
    IP_ADAPTER_ADDRESSES* addresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
    if (addresses == NULL) {
        return false;
    }
    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addresses, &bufferSize) != ERROR_SUCCESS) {
        free(addresses);
        return false;
    }
    IP_ADAPTER_ADDRESSES* current = addresses;
    while (current) {
        if (current->PhysicalAddressLength == 6) {
            char macAddr[18];
            snprintf(macAddr, sizeof(macAddr), "%02X-%02X-%02X-%02X-%02X-%02X",
                current->PhysicalAddress[0], current->PhysicalAddress[1],
                current->PhysicalAddress[2], current->PhysicalAddress[3],
                current->PhysicalAddress[4], current->PhysicalAddress[5]);
            for (int i = 0; i < prefixCount; i++) {
                if (strncmp(macAddr, vmPrefixes[i], 8) == 0) {
                    free(addresses);
                    return true;
                }
            }
        }
        current = current->Next;
    }
    free(addresses);
    return false;
}

static bool detectVMwareRegistryKeys(void) {
    const char* vmwareKeys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"
    };
    int keyCount = (int)(sizeof(vmwareKeys) / sizeof(vmwareKeys[0]));
    for (int i = 0; i < keyCount; i++) {
        char* value = getRegValue(HKEY_LOCAL_MACHINE, vmwareKeys[i], "Identifier");
        if (value != NULL) {
            bool detected = (strstr(value, "VMware") != NULL || strstr(value, "VBOX") != NULL);
            free(value);
            if (detected) {
                return true;
            }
        }
    }
    return false;
}

static bool detectVirtualFiles(void) {
    const char* vmFiles[] = {
        "C:\\Windows\\System32\\Drivers\\Vmmouse.sys",
        "C:\\Windows\\System32\\Drivers\\vm3dgl.dll",
        "C:\\Windows\\System32\\Drivers\\vmdum.dll",
        "C:\\Windows\\System32\\Drivers\\VBoxMouse.sys",
        "C:\\Windows\\System32\\Drivers\\VBoxGuest.sys",
        "C:\\Windows\\System32\\Drivers\\VBoxSF.sys",
        "C:\\Windows\\System32\\Drivers\\VBoxVideo.sys",
        "C:\\Windows\\System32\\vboxdisp.dll",
        "C:\\Windows\\System32\\vboxhook.dll",
        "C:\\Windows\\System32\\vboxogl.dll"
    };
    int fileCount = (int)(sizeof(vmFiles) / sizeof(vmFiles[0]));
    for (int i = 0; i < fileCount; i++) {
        if (GetFileAttributesA(vmFiles[i]) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }
    return false;
}

static bool detectVMProcesses(void) {
    const char* vmProcesses[] = {
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        "VBoxService.exe", "VBoxTray.exe"
    };
    int processCount = (int)(sizeof(vmProcesses) / sizeof(vmProcesses[0]));
    for (int i = 0; i < processCount; i++) {
        if (isProcessRunningByName(vmProcesses[i])) {
            return true;
        }
    }
    return false;
}

static bool detectVirtualServices(void) {
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scManager == NULL) {
        return false;
    }
    const char* vmServices[] = { "VMTools", "VBoxService" };
    int serviceCount = (int)(sizeof(vmServices) / sizeof(vmServices[0]));
    bool result = false;
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
    EnumServicesStatusExA(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                         NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);
    if (bytesNeeded > 0) {
        ENUM_SERVICE_STATUS_PROCESS* services = (ENUM_SERVICE_STATUS_PROCESS*)malloc(bytesNeeded);
        if (services == NULL) {
            CloseServiceHandle(scManager);
            return false;
        }
        if (EnumServicesStatusExA(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                (LPBYTE)services, bytesNeeded, &bytesNeeded, &servicesReturned,
                                &resumeHandle, NULL)) {
            for (DWORD i = 0; i < servicesReturned; i++) {
                for (int j = 0; j < serviceCount; j++) {
                    if (strstr(services[i].lpServiceName, vmServices[j]) != NULL) {
                        result = true;
                        break;
                    }
                }
                if (result) break;
            }
        }
        free(services);
    }
    CloseServiceHandle(scManager);
    return result;
}

static bool detectDeviceBios(void) {
    char buffer[4096] = {0};
    DWORD size = sizeof(buffer);
    const char* vmIndicators[] = { "VMware", "VBOX", "Virtual", "Xen", "innotek", "QEMU" };
    int indicatorCount = (int)(sizeof(vmIndicators) / sizeof(vmIndicators[0]));
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "SystemManufacturer", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            for (int i = 0; i < indicatorCount; i++) {
                if (strstr(buffer, vmIndicators[i]) != NULL) {
                    RegCloseKey(hKey);
                    return true;
                }
            }
        }
        size = sizeof(buffer);
        if (RegQueryValueExA(hKey, "SystemProductName", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS) {
            for (int i = 0; i < indicatorCount; i++) {
                if (strstr(buffer, vmIndicators[i]) != NULL) {
                    RegCloseKey(hKey);
                    return true;
                }
            }
        }
        RegCloseKey(hKey);
    }
    return false;
}

static bool checkRegistry(void) {
    struct {
        HKEY hKey;
        const char* subKey;
        const char* value;
    } keys[] = {
        {HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier"},
        {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S", ""},
        {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\CriticalDeviceDatabase\\root#vmwvmcihostdev", ""},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", ""},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", ""},
        {HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", "SystemBiosVersion"}
    };
    int keyCount = (int)(sizeof(keys) / sizeof(keys[0]));
    for (int i = 0; i < keyCount; i++) {
        /* Empty value name = flag if the key merely exists: these keys often
           carry no default value, so a value query would miss them. */
        if (keys[i].value[0] == '\0') {
            if (regKeyExists(keys[i].hKey, keys[i].subKey)) {
                return true;
            }
            continue;
        }
        char* regValue = getRegValue(keys[i].hKey, keys[i].subKey, keys[i].value);
        if (regValue != NULL) {
            bool detected = (strstr(regValue, "VMware") != NULL ||
                           strstr(regValue, "VBOX") != NULL ||
                           strstr(regValue, "Virtual") != NULL ||
                           strstr(regValue, "Xen") != NULL);
            free(regValue);
            if (detected) {
                return true;
            }
        }
    }
    return false;
}

static bool checkSandboxArtifacts(void) {
    const char* sandboxArtifacts[] = {
        "C:\\agent\\agent.pyw", "C:\\analysis", "C:\\sandbox", "C:\\Tools\\Wireshark",
        "C:\\iDEFENSE", "C:\\analysis_logs", "C:\\sandbox logs",
        "C:\\program files\\wireshark", "C:\\program files\\fiddler"
    };
    int artifactCount = (int)(sizeof(sandboxArtifacts) / sizeof(sandboxArtifacts[0]));
    for (int i = 0; i < artifactCount; i++) {
        if (GetFileAttributesA(sandboxArtifacts[i]) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }
    return false;
}

static bool checkSandboxHostnames(void) {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        return false;
    }
    const char* sandboxNames[] = {
        "sandbox", "virus", "malware", "cuckoo", "analysis", "lab",
        "maltest", "test", "artifacts", "vm-", "pc-", "john-pc"
    };
    int nameCount = (int)(sizeof(sandboxNames) / sizeof(sandboxNames[0]));
    for (int i = 0; hostname[i]; i++) {
        hostname[i] = (char)tolower((unsigned char)hostname[i]);
    }
    for (int i = 0; i < nameCount; i++) {
        if (strstr(hostname, sandboxNames[i]) != NULL) {
            return true;
        }
    }
    return false;
}

/* NEW: injected analysis/monitoring DLLs loaded into this process. */
static bool detectSandboxDLLs(void) {
    const char* sandboxDlls[] = {
        "sbiedll.dll",   /* Sandboxie */
        "api_log.dll",   /* iDefense SysAnalyzer */
        "dir_watch.dll", /* iDefense SysAnalyzer */
        "pstorec.dll",   /* SunBelt / CWSandbox */
        "vmcheck.dll",   /* Virtual PC */
        "wpespy.dll",    /* WPE Pro */
        "cmdvrt32.dll"   /* Comodo container */
    };
    int count = (int)(sizeof(sandboxDlls) / sizeof(sandboxDlls[0]));
    for (int i = 0; i < count; i++) {
        if (GetModuleHandleA(sandboxDlls[i]) != NULL) {
            return true;
        }
    }
    return false;
}

/* ---------------------------------------------------------- hardware checks */

static bool detectHardwareConfigurations(void) {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);
    if (sysInfo.dwNumberOfProcessors <= 2 && memStatus.ullTotalPhys < 4000000000LL) {
        return true;
    }
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
        if (totalNumberOfBytes.QuadPart < 100000000000LL) {
            return true;
        }
    }
    return false;
}

static bool checkScreenResolution(void) {
    int desktopWidth = GetSystemMetrics(SM_CXSCREEN);
    int desktopHeight = GetSystemMetrics(SM_CYSCREEN);
    return (desktopWidth < 1024 || desktopHeight < 768);
}

static bool checkDriveSize(void) {
    UINT driveType = GetDriveTypeA("C:\\");
    if (driveType == DRIVE_FIXED) {
        ULARGE_INTEGER freeBytes, totalBytes, totalFreeBytes;
        if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, &totalFreeBytes)) {
            return (totalBytes.QuadPart < 60000000000LL);
        }
    }
    return false;
}

/* -------------------------------------------------------------- user checks */

static bool checkMouseMovement(void) {
    POINT pt1, pt2;
    if (!GetCursorPos(&pt1)) {
        return false;
    }
    Sleep(500);
    if (!GetCursorPos(&pt2)) {
        return false;
    }
    return (pt1.x == pt2.x && pt1.y == pt2.y);
}

static bool checkSystemUptime(void) {
    return (GetTickCount64() / 1000 < 60 * 10);
}

static bool checkUserActivity(void) {
    LASTINPUTINFO lastInput;
    lastInput.cbSize = sizeof(LASTINPUTINFO);
    if (GetLastInputInfo(&lastInput)) {
        DWORD idleTime = GetTickCount() - lastInput.dwTime;
        return (idleTime >= 600000);
    }
    return false;
}

static bool checkRecentFiles(void) {
    char recentPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_RECENT, NULL, 0, recentPath);
    WIN32_FIND_DATAA findData;
    char searchPath[MAX_PATH];
    snprintf(searchPath, sizeof(searchPath), "%s\\*.lnk", recentPath);
    HANDLE hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return true;
    }
    int fileCount = 0;
    do {
        fileCount++;
        if (fileCount >= 5) {
            FindClose(hFind);
            return false;
        }
    } while (FindNextFileA(hFind, &findData));
    FindClose(hFind);
    return true;
}

/* Detected == no keyboard activity during the polling window (the inverse is a
   human, not a sandbox). */
static bool checkNoKeyboardActivity(void) {
    for (int i = 0; i < 300; i++) {
        for (int key = 0; key < 256; key++) {
            if (GetAsyncKeyState(key) & 0x8000) {
                return false;
            }
        }
        Sleep(10);
    }
    return true;
}

static bool detectAdditionalProcesses(void) {
    const char* additionalProcesses[] = {
        "procmon.exe", "wireshark.exe", "ollydbg.exe", "x64dbg.exe"
    };
    int count = (int)(sizeof(additionalProcesses) / sizeof(additionalProcesses[0]));
    for (int i = 0; i < count; i++) {
        if (isProcessRunningByName(additionalProcesses[i])) {
            return true;
        }
    }
    return false;
}

/* ----------------------------------------------------------- network checks */

static bool detectDebuggingPorts(void) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(1016);
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock != INVALID_SOCKET) {
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            closesocket(sock);
            WSACleanup();
            return true;
        }
        closesocket(sock);
    }
    addr.sin_port = htons(5002);
    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock != INVALID_SOCKET) {
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            closesocket(sock);
            WSACleanup();
            return true;
        }
        closesocket(sock);
    }
    WSACleanup();
    return false;
}

/* ----------------------------------------------------------- runtime checks */

static bool isRunningInHypervisor(void) {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx >> 31) & 1;
    }
    return false;
}

/* NEW: CPUID hypervisor vendor leaf (0x40000000) -- more specific than bit 31. */
static bool detectHypervisorVendor(void) {
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(0x40000000, &eax, &ebx, &ecx, &edx)) {
        return false;
    }
    char vendor[13];
    memcpy(vendor + 0, &ebx, 4);
    memcpy(vendor + 4, &ecx, 4);
    memcpy(vendor + 8, &edx, 4);
    vendor[12] = '\0';
    const char* known[] = {
        "VMwareVMware", "VBoxVBoxVBox", "KVMKVMKVM\0\0\0", "Microsoft Hv",
        "XenVMMXenVMM", "prl hyperv  ", "TCGTCGTCGTCG", "bhyve bhyve "
    };
    int count = (int)(sizeof(known) / sizeof(known[0]));
    for (int i = 0; i < count; i++) {
        if (memcmp(vendor, known[i], 12) == 0) {
            return true;
        }
    }
    return false;
}

/* NEW: debugger attached to this process. */
static bool detectDebuggerPresent(void) {
    if (IsDebuggerPresent()) {
        return true;
    }
    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) {
        return true;
    }
    return false;
}

/* NEW: hardware breakpoints set in the debug registers of the current thread. */
static bool detectHardwareBreakpoints(void) {
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return true;
        }
    }
    return false;
}

/* NEW: inline hooks on ntdll syscall stubs -- a JMP as the first opcode instead
   of the normal "mov r10, rcx" (0x4C) prologue indicates interception. */
static bool detectApiHooks(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) {
        return false;
    }
    const char* funcs[] = { "NtCreateFile", "NtProtectVirtualMemory", "NtWriteVirtualMemory" };
    int count = (int)(sizeof(funcs) / sizeof(funcs[0]));
    for (int i = 0; i < count; i++) {
        unsigned char* fn = (unsigned char*)GetProcAddress(ntdll, funcs[i]);
        if (fn != NULL) {
            if (fn[0] == 0xE9 || fn[0] == 0xEB) { /* jmp rel32 / jmp rel8 */
                return true;
            }
        }
    }
    return false;
}

/* NEW: classic "Red Pill" -- read the IDT base with SIDT. Kept for teaching
   value; unreliable on modern multi-core x64 so it is weighted WEAK and only
   applies the historical 32-bit heuristic. */
static bool detectRedPillIDT(void) {
#if defined(__GNUC__) && defined(__i386__)
    unsigned char idtr[6];
    __asm__ __volatile__("sidt %0" : "=m"(idtr));
    unsigned long base;
    memcpy(&base, &idtr[2], sizeof(base));
    /* VMware historically placed the IDT high (0xFFxxxxxx). */
    return ((base >> 24) == 0xFF);
#else
    /* On x86_64 the IDT base is not a reliable single-value discriminator. */
    return false;
#endif
}

static bool checkTimeAcceleration(void) {
    time_t start = time(NULL);
    Sleep(3000);
    time_t end = time(NULL);
    time_t elapsed = end - start;
    return (elapsed < 2 || elapsed > 4);
}

/* --------------------------------------------------------------- test table */

void runTests(SandboxDetector* detector) {
    /* Runtime */
    addResult(detector, "Runtime", "Time Acceleration", WEIGHT_MEDIUM, checkTimeAcceleration());
    addResult(detector, "Runtime", "Hypervisor Bit (CPUID)", WEIGHT_MEDIUM, isRunningInHypervisor());
    addResult(detector, "Runtime", "Hypervisor Vendor (CPUID)", WEIGHT_STRONG, detectHypervisorVendor());
    addResult(detector, "Runtime", "Debugger Present", WEIGHT_MEDIUM, detectDebuggerPresent());
    addResult(detector, "Runtime", "Hardware Breakpoints", WEIGHT_MEDIUM, detectHardwareBreakpoints());
    addResult(detector, "Runtime", "ntdll API Hooks", WEIGHT_MEDIUM, detectApiHooks());
    addResult(detector, "Runtime", "Red Pill (IDT)", WEIGHT_WEAK, detectRedPillIDT());
    /* System */
    addResult(detector, "System", "VM Registry Keys", WEIGHT_STRONG, detectVMwareRegistryKeys());
    addResult(detector, "System", "Virtual Files", WEIGHT_STRONG, detectVirtualFiles());
    addResult(detector, "System", "Virtual Processes", WEIGHT_STRONG, detectVMProcesses());
    addResult(detector, "System", "Virtual Services", WEIGHT_STRONG, detectVirtualServices());
    addResult(detector, "System", "BIOS/Device Information", WEIGHT_STRONG, detectDeviceBios());
    addResult(detector, "System", "Registry Indicators", WEIGHT_STRONG, checkRegistry());
    addResult(detector, "System", "Sandbox Artifacts", WEIGHT_MEDIUM, checkSandboxArtifacts());
    addResult(detector, "System", "Sandbox Hostnames", WEIGHT_MEDIUM, checkSandboxHostnames());
    addResult(detector, "System", "Injected Sandbox DLLs", WEIGHT_MEDIUM, detectSandboxDLLs());
    /* Hardware */
    addResult(detector, "Hardware", "Virtual MAC Address", WEIGHT_STRONG, hasVirtualMacAddress());
    addResult(detector, "Hardware", "Limited Hardware Configuration", WEIGHT_WEAK, detectHardwareConfigurations());
    addResult(detector, "Hardware", "Low Screen Resolution", WEIGHT_WEAK, checkScreenResolution());
    addResult(detector, "Hardware", "Small Disk Drive", WEIGHT_WEAK, checkDriveSize());
    /* User */
    addResult(detector, "User", "No Mouse Movement", WEIGHT_WEAK, checkMouseMovement());
    addResult(detector, "User", "Short System Uptime", WEIGHT_WEAK, checkSystemUptime());
    addResult(detector, "User", "No User Activity", WEIGHT_WEAK, checkUserActivity());
    addResult(detector, "User", "Few Recent Files", WEIGHT_WEAK, checkRecentFiles());
    addResult(detector, "User", "Additional Security Processes", WEIGHT_MEDIUM, detectAdditionalProcesses());
    addResult(detector, "User", "No Keyboard Activity", WEIGHT_WEAK, checkNoKeyboardActivity());
    /* Network */
    addResult(detector, "Network", "Debugging Ports", WEIGHT_MEDIUM, detectDebuggingPorts());
}
