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
#include <stdarg.h>

#include "detector.h"
#include "checks.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

/* ------------------------------------------------------------------ helpers */

/* Evidence for the check that fired: runTests clears this before each check
   and stores it on the result row when the check returns true. Every check
   reports *what* matched, not just that something did. */
static char g_lastHit[200];

static bool hitf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(g_lastHit, sizeof(g_lastHit), fmt, ap);
    va_end(ap);
    return true;
}

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

typedef struct { const char* prefix; const char* vendor; } OuiEntry;

/* Scans every adapter's MAC against a OUI table; on a match reports which
   adapter and which vendor it belongs to. */
static bool matchMacOui(const OuiEntry* ouis, int count) {
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
    bool fired = false;
    IP_ADAPTER_ADDRESSES* current = addresses;
    while (current && !fired) {
        if (current->PhysicalAddressLength == 6) {
            char macAddr[18];
            snprintf(macAddr, sizeof(macAddr), "%02X-%02X-%02X-%02X-%02X-%02X",
                current->PhysicalAddress[0], current->PhysicalAddress[1],
                current->PhysicalAddress[2], current->PhysicalAddress[3],
                current->PhysicalAddress[4], current->PhysicalAddress[5]);
            for (int i = 0; i < count; i++) {
                if (strncmp(macAddr, ouis[i].prefix, 8) == 0) {
                    fired = hitf("adapter MAC %s is a %s prefix",
                                 macAddr, ouis[i].vendor);
                    break;
                }
            }
        }
        current = current->Next;
    }
    free(addresses);
    return fired;
}

static bool hasVirtualMacAddress(void) {
    /* Strong indicators: adapters owned by a hosted hypervisor. */
    static const OuiEntry vmOuis[] = {
        {"00-05-69", "VMware"}, {"00-0C-29", "VMware"},
        {"00-1C-14", "VMware"}, {"00-50-56", "VMware"},
        {"00-1C-42", "Parallels"}, {"00-0F-4B", "Virtual Iron"},
        {"00-16-3E", "Xen"}, {"08-00-27", "VirtualBox"},
        {"52-54-00", "QEMU/KVM"}
    };
    return matchMacOui(vmOuis, (int)(sizeof(vmOuis) / sizeof(vmOuis[0])));
}

/* Hyper-V gets its own weak check: a 00-15-5D adapter only means this host
   *runs* Hyper-V, which every VBS/WSL2/Docker-enabled Windows 10/11 box does.
   It says nothing about being inside a VM -- unlike the OUIs above. */
static bool hasHyperVMacAddress(void) {
    static const OuiEntry hvOuis[] = {
        {"00-03-FF", "Hyper-V"}, {"00-15-5D", "Hyper-V"}
    };
    return matchMacOui(hvOuis, (int)(sizeof(hvOuis) / sizeof(hvOuis[0])));
}

/* NEW: disk Identifier strings are also reported under DEVICEMAP for every
   SCSI port; scanning only port 0 misses secondary/virtual disks. */
static bool detectScsiIdentifiers(void) {
    for (int port = 0; port < 4; port++) {
        char key[192];
        snprintf(key, sizeof(key),
                 "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port %d\\Scsi Bus 0\\"
                 "Target Id 0\\Logical Unit Id 0", port);
        char* value = getRegValue(HKEY_LOCAL_MACHINE, key, "Identifier");
        if (value != NULL) {
            bool detected = (strstr(value, "VMware") != NULL ||
                             strstr(value, "VBOX") != NULL ||
                             strstr(value, "QEMU") != NULL ||
                             strstr(value, "Msft") != NULL ||
                             strstr(value, "Virtual") != NULL);
            if (detected) {
                bool fired = hitf("port %d Identifier is \"%s\"", port, value);
                free(value);
                return fired;
            }
            free(value);
        }
    }
    return false;
}

/* NEW: VM guest-service keys persist under CurrentControlSet even when the
   service itself is stopped or disabled, unlike SCM enumeration. */
static bool detectVirtualServiceKeys(void) {
    const char* services[] = {
        "VBoxGuest", "VBoxMouse", "VBoxSF", "VBoxVideo",
        "VMTools", "vmhgfs", "vmmouse", "vmrawdsk", "vmci",
        "xen", "xenbus", "xenvif", "xennet", "xensvc",
        "qemu-ga", "vpc-s3", "vpcubus", "prl_tools", "prl_tg"
    };
    int count = (int)(sizeof(services) / sizeof(services[0]));
    for (int i = 0; i < count; i++) {
        char key[160];
        snprintf(key, sizeof(key),
                 "SYSTEM\\CurrentControlSet\\Services\\%s", services[i]);
        if (regKeyExists(HKEY_LOCAL_MACHINE, key)) {
            return hitf("service key %s exists", services[i]);
        }
    }
    return false;
}

/* NEW: named pipes owned by sandbox agents and VM IPC endpoints. A pipe that
   exists but stays busy still fails WaitNamedPipe with ERROR_SEM_TIMEOUT --
   which is exactly what distinguishes "exists" from "absent" here. */
static bool detectNamedPipes(void) {
    const char* pipes[] = {
        "\\\\.\\pipe\\cuckoo",
        "\\\\.\\pipe\\VBoxTrayIPC",
        "\\\\.\\pipe\\VBoxMiniRdDN",
        "\\\\.\\pipe\\vmware-authdpipe",
        "\\\\.\\pipe\\vmware-usbarbpipe"
    };
    int count = (int)(sizeof(pipes) / sizeof(pipes[0]));
    for (int i = 0; i < count; i++) {
        if (WaitNamedPipeA(pipes[i], 0) ||
            GetLastError() == ERROR_SEM_TIMEOUT) {
            return hitf("pipe %s exists", pipes[i]);
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
        "C:\\Windows\\System32\\Drivers\\xenvbd.sys",
        "C:\\Windows\\System32\\Drivers\\xennet.sys",
        "C:\\Windows\\System32\\vboxdisp.dll",
        "C:\\Windows\\System32\\vboxhook.dll",
        "C:\\Windows\\System32\\vboxogl.dll"
    };
    int fileCount = (int)(sizeof(vmFiles) / sizeof(vmFiles[0]));
    for (int i = 0; i < fileCount; i++) {
        if (GetFileAttributesA(vmFiles[i]) != INVALID_FILE_ATTRIBUTES) {
            return hitf("found %s", vmFiles[i]);
        }
    }
    return false;
}

static bool detectVMProcesses(void) {
    const char* vmProcesses[] = {
        "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
        "VBoxService.exe", "VBoxTray.exe", "qemu-ga.exe",
        "xenservice.exe", "vmsrvc.exe", "vmusrvc.exe",
        "prl_tools.exe", "prl_cc.exe"
    };
    int processCount = (int)(sizeof(vmProcesses) / sizeof(vmProcesses[0]));
    for (int i = 0; i < processCount; i++) {
        if (isProcessRunningByName(vmProcesses[i])) {
            return hitf("%s is running", vmProcesses[i]);
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
                        result = hitf("service %s is registered",
                                      services[i].lpServiceName);
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
    /* {subkey, value} pairs that carry the DMI vendor/product strings. The
       SystemInformation key is what msinfo32 reports on Win10+, so it catches
       VMs whose legacy BIOS key is inconclusive. */
    static const struct { const char* subKey; const char* value; } sources[] = {
        {"HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemManufacturer"},
        {"HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemProductName"},
        {"HARDWARE\\DESCRIPTION\\System\\BIOS", "BIOSVendor"},
        {"SYSTEM\\ControlSet001\\Control\\SystemInformation", "SystemManufacturer"},
        {"SYSTEM\\ControlSet001\\Control\\SystemInformation", "SystemProductName"}
    };
    const char* vmIndicators[] = {
        "VMware", "VBOX", "VirtualBox", "Virtual", "Xen",
        "innotek", "QEMU", "Bochs", "KVM", "BHYVE", "Parallels"
    };
    int sourceCount = (int)(sizeof(sources) / sizeof(sources[0]));
    int indicatorCount = (int)(sizeof(vmIndicators) / sizeof(vmIndicators[0]));
    for (int s = 0; s < sourceCount; s++) {
        char* value = getRegValue(HKEY_LOCAL_MACHINE, sources[s].subKey, sources[s].value);
        if (value == NULL) {
            continue;
        }
        for (int i = 0; i < indicatorCount; i++) {
            if (strstr(value, vmIndicators[i]) != NULL) {
                bool fired = hitf("%s is \"%s\"", sources[s].value, value);
                free(value);
                return fired;
            }
        }
        free(value);
    }
    return false;
}

/* NEW: raw SMBIOS table scan -- the same strings as the registry keys above,
   but read from the firmware blob itself, so it works even where the registry
   keys have been cleaned. No admin rights needed for GetSystemFirmwareTable
   on 'RSMB'. */
static bool detectSmbiosTables(void) {
    static const DWORD rsmb = 'R' | ('S' << 8) | ((DWORD)'M' << 16) | ((DWORD)'B' << 24);
    const char* vmIndicators[] = {
        "VMware", "VirtualBox", "VBOX", "QEMU", "Bochs",
        "Xen", "Hyper-V", "KVM", "Parallels", "BHYVE"
    };
    int indicatorCount = (int)(sizeof(vmIndicators) / sizeof(vmIndicators[0]));
    UINT need = GetSystemFirmwareTable(rsmb, 0, NULL, 0);
    if (need == 0 || need > 1024 * 1024) {
        return false;
    }
    BYTE* blob = (BYTE*)malloc(need);
    if (blob == NULL) {
        return false;
    }
    if (GetSystemFirmwareTable(rsmb, 0, blob, need) == 0) {
        free(blob);
        return false;
    }
    bool fired = false;
    for (UINT off = 0; off < need && !fired; off++) {
        for (int i = 0; i < indicatorCount; i++) {
            size_t len = strlen(vmIndicators[i]);
            if (off + len <= need &&
                memcmp(blob + off, vmIndicators[i], len) == 0) {
                fired = hitf("SMBIOS table contains \"%s\"", vmIndicators[i]);
                break;
            }
        }
    }
    free(blob);
    return fired;
}

static bool checkRegistry(void) {
    struct {
        HKEY hKey;
        const char* subKey;
        const char* value;
    } keys[] = {
        {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VMware_&Prod_VMware_Virtual_S", ""},
        {HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\SCSI\\Disk&Ven_VBOX&Prod_HARDDISK", ""},
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
                return hitf("key %s exists", keys[i].subKey);
            }
            continue;
        }
        char* regValue = getRegValue(keys[i].hKey, keys[i].subKey, keys[i].value);
        if (regValue != NULL) {
            bool detected = (strstr(regValue, "VMware") != NULL ||
                           strstr(regValue, "VBOX") != NULL ||
                           strstr(regValue, "Virtual") != NULL ||
                           strstr(regValue, "Xen") != NULL);
            if (detected) {
                bool fired = hitf("%s %s is \"%s\"", keys[i].subKey,
                                  keys[i].value, regValue);
                free(regValue);
                return fired;
            }
            free(regValue);
        }
    }
    return false;
}

static bool checkSandboxArtifacts(void) {
    const char* sandboxArtifacts[] = {
        "C:\\agent\\agent.pyw", "C:\\analysis", "C:\\sandbox", "C:\\Tools\\Wireshark",
        "C:\\iDEFENSE", "C:\\analysis_logs", "C:\\sandbox logs",
        "C:\\program files\\wireshark", "C:\\program files\\fiddler",
        "C:\\program files\\fakenet", "C:\\Tools\\FakeNet",
        "C:\\Users\\Public\\Downloads\\malware", "C:\\Cape"
    };
    int artifactCount = (int)(sizeof(sandboxArtifacts) / sizeof(sandboxArtifacts[0]));
    for (int i = 0; i < artifactCount; i++) {
        if (GetFileAttributesA(sandboxArtifacts[i]) != INVALID_FILE_ATTRIBUTES) {
            return hitf("found %s", sandboxArtifacts[i]);
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
            return hitf("hostname \"%s\" matches \"%s\"", hostname, sandboxNames[i]);
        }
    }
    return false;
}

/* NEW: usernames are as telling as hostnames -- sandboxes ship with canned
   accounts (cuckoo, analyst), and WDAGUtilityAccount only exists inside
   Windows Defender Application Guard. */
static bool checkSuspiciousUsername(void) {
    char username[256];
    DWORD size = sizeof(username);
    if (!GetUserNameA(username, &size)) {
        return false;
    }
    const char* badNames[] = {
        "cuckoo", "sandbox", "malware", "virus", "analyst", "wdag",
        "honey", "snort", "john"
    };
    int nameCount = (int)(sizeof(badNames) / sizeof(badNames[0]));
    for (int i = 0; username[i]; i++) {
        username[i] = (char)tolower((unsigned char)username[i]);
    }
    for (int i = 0; i < nameCount; i++) {
        if (strstr(username, badNames[i]) != NULL) {
            return hitf("username \"%s\" matches \"%s\"", username, badNames[i]);
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
            return hitf("%s is loaded in this process", sandboxDlls[i]);
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
        return hitf("%u processors, %.1f GB RAM", sysInfo.dwNumberOfProcessors,
                    (double)memStatus.ullTotalPhys / 1073741824.0);
    }
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
    if (GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
        if (totalNumberOfBytes.QuadPart < 100000000000LL) {
            return hitf("C: total %.1f GB",
                        (double)totalNumberOfBytes.QuadPart / 1073741824.0);
        }
    }
    return false;
}

static bool checkScreenResolution(void) {
    int desktopWidth = GetSystemMetrics(SM_CXSCREEN);
    int desktopHeight = GetSystemMetrics(SM_CYSCREEN);
    if (desktopWidth < 1024 || desktopHeight < 768) {
        return hitf("desktop is %dx%d", desktopWidth, desktopHeight);
    }
    return false;
}

static bool checkDriveSize(void) {
    UINT driveType = GetDriveTypeA("C:\\");
    if (driveType == DRIVE_FIXED) {
        ULARGE_INTEGER freeBytes, totalBytes, totalFreeBytes;
        if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, &totalFreeBytes)) {
            if (totalBytes.QuadPart < 60000000000LL) {
                return hitf("C: total %.1f GB",
                            (double)totalBytes.QuadPart / 1073741824.0);
            }
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
    if (pt1.x == pt2.x && pt1.y == pt2.y) {
        return hitf("cursor unmoved over 500 ms");
    }
    return false;
}

static bool checkSystemUptime(void) {
    ULONGLONG upSecs = GetTickCount64() / 1000;
    if (upSecs < 60 * 10) {
        return hitf("uptime %llu s", upSecs);
    }
    return false;
}

static bool checkUserActivity(void) {
    LASTINPUTINFO lastInput;
    lastInput.cbSize = sizeof(LASTINPUTINFO);
    if (GetLastInputInfo(&lastInput)) {
        DWORD idleTime = GetTickCount() - lastInput.dwTime;
        if (idleTime >= 600000) {
            return hitf("idle for %lu s", (unsigned long)(idleTime / 1000));
        }
    }
    return false;
}

static bool checkRecentFiles(void) {
    char recentPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_RECENT, NULL, 0, recentPath);
    WIN32_FIND_DATAA findData;
    char searchPath[MAX_PATH + 16];
    snprintf(searchPath, sizeof(searchPath), "%s\\*.lnk", recentPath);
    HANDLE hFind = FindFirstFileA(searchPath, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return hitf("no .lnk files in Recent");
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
    return hitf("only %d recent .lnk files", fileCount);
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
    return hitf("no key held during 3 s poll");
}

static bool detectAdditionalProcesses(void) {
    const char* additionalProcesses[] = {
        "procmon.exe", "procmon64.exe", "procxp.exe", "procxp64.exe",
        "wireshark.exe", "dumpcap.exe", "tshark.exe",
        "ollydbg.exe", "x32dbg.exe", "x64dbg.exe", "windbg.exe",
        "idaq.exe", "idaq64.exe", "ida64.exe", "idag.exe",
        "processhacker.exe", "tcpview.exe", "autoruns.exe",
        "pestudio.exe", "regshot.exe", "fakenet.exe", "apatedns.exe",
        "sysanalyzer.exe", "sniff_hit.exe", "joeboxcontrol.exe",
        "joeboxserver.exe"
    };
    int count = (int)(sizeof(additionalProcesses) / sizeof(additionalProcesses[0]));
    for (int i = 0; i < count; i++) {
        if (isProcessRunningByName(additionalProcesses[i])) {
            return hitf("%s is running", additionalProcesses[i]);
        }
    }
    return false;
}

/* ----------------------------------------------------------- network checks */

static bool detectDebuggingPorts(void) {
    /* Ports historically held open by debugger/agent stubs on loopback. */
    const USHORT ports[] = { 1016, 5002 };
    int portCount = (int)(sizeof(ports) / sizeof(ports[0]));
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
    bool fired = false;
    for (int i = 0; i < portCount && !fired; i++) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(ports[i]);
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock != INVALID_SOCKET) {
            if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                fired = hitf("loopback port %u accepts connections", ports[i]);
            }
            closesocket(sock);
        }
    }
    WSACleanup();
    return fired;
}

/* ----------------------------------------------------------- runtime checks */

static bool isRunningInHypervisor(void) {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if ((ecx >> 31) & 1) {
            return hitf("CPUID.1:ECX bit 31 is set");
        }
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
            return hitf("vendor leaf reports \"%s\"", vendor);
        }
    }
    return false;
}

/* NEW: debugger attached to this process. */
static bool detectDebuggerPresent(void) {
    if (IsDebuggerPresent()) {
        return hitf("IsDebuggerPresent is true");
    }
    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote) {
        return hitf("a remote debugger is attached");
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
            return hitf("Dr0-Dr3 = %p %p %p %p", (void*)ctx.Dr0,
                        (void*)ctx.Dr1, (void*)ctx.Dr2, (void*)ctx.Dr3);
        }
    }
    return false;
}

/* Inline hooks on ntdll syscall stubs -- a JMP as the first opcode instead
   of the normal "mov r10, rcx" (0x4C) prologue indicates interception, and a
   breakpoint byte (0xCC) is a planted int3. */
static bool detectApiHooks(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == NULL) {
        return false;
    }
    const char* funcs[] = {
        "NtCreateFile", "NtProtectVirtualMemory", "NtWriteVirtualMemory",
        "NtAllocateVirtualMemory", "NtCreateThreadEx"
    };
    int count = (int)(sizeof(funcs) / sizeof(funcs[0]));
    for (int i = 0; i < count; i++) {
        unsigned char* fn = (unsigned char*)GetProcAddress(ntdll, funcs[i]);
        if (fn != NULL) {
            if (fn[0] == 0xE9 || fn[0] == 0xEB || fn[0] == 0xCC) {
                return hitf("%s starts with byte 0x%02X", funcs[i], fn[0]);
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
    if ((base >> 24) == 0xFF) {
        return hitf("IDT base is 0x%08lx", base);
    }
    return false;
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
    if (elapsed < 2 || elapsed > 4) {
        return hitf("3 s sleep measured %ld s of wall time", (long)elapsed);
    }
    return false;
}

/* --------------------------------------------------------------- test table */

/* Records one check result with its evidence: g_lastHit is cleared, the check
   runs, and if it fired the detail string is stored on the row. */
#define ADD_CHECK(category, test, weight, fn)                              \
    do {                                                                   \
        g_lastHit[0] = '\0';                                               \
        bool _fired = (fn)();                                              \
        addResultDetail(detector, category, test, weight, _fired,          \
                        _fired ? g_lastHit : "");                          \
    } while (0)

void runTests(SandboxDetector* detector) {
    /* Runtime */
    ADD_CHECK("Runtime", "Time Acceleration", WEIGHT_MEDIUM, checkTimeAcceleration);
    ADD_CHECK("Runtime", "Hypervisor Bit (CPUID)", WEIGHT_MEDIUM, isRunningInHypervisor);
    ADD_CHECK("Runtime", "Hypervisor Vendor (CPUID)", WEIGHT_STRONG, detectHypervisorVendor);
    ADD_CHECK("Runtime", "Debugger Present", WEIGHT_MEDIUM, detectDebuggerPresent);
    ADD_CHECK("Runtime", "Hardware Breakpoints", WEIGHT_MEDIUM, detectHardwareBreakpoints);
    ADD_CHECK("Runtime", "ntdll API Hooks", WEIGHT_MEDIUM, detectApiHooks);
    ADD_CHECK("Runtime", "Red Pill (IDT)", WEIGHT_WEAK, detectRedPillIDT);
    /* System */
    ADD_CHECK("System", "Virtual Files", WEIGHT_STRONG, detectVirtualFiles);
    ADD_CHECK("System", "Virtual Processes", WEIGHT_STRONG, detectVMProcesses);
    ADD_CHECK("System", "Virtual Services", WEIGHT_STRONG, detectVirtualServices);
    ADD_CHECK("System", "VM Service Registry Keys", WEIGHT_STRONG, detectVirtualServiceKeys);
    ADD_CHECK("System", "BIOS/Device Information", WEIGHT_STRONG, detectDeviceBios);
    ADD_CHECK("System", "SMBIOS Firmware Strings", WEIGHT_STRONG, detectSmbiosTables);
    ADD_CHECK("System", "SCSI Disk Identifiers", WEIGHT_STRONG, detectScsiIdentifiers);
    ADD_CHECK("System", "Registry Indicators", WEIGHT_STRONG, checkRegistry);
    ADD_CHECK("System", "Sandbox Artifacts", WEIGHT_MEDIUM, checkSandboxArtifacts);
    ADD_CHECK("System", "Named Pipe Artifacts", WEIGHT_MEDIUM, detectNamedPipes);
    ADD_CHECK("System", "Sandbox Hostnames", WEIGHT_MEDIUM, checkSandboxHostnames);
    ADD_CHECK("System", "Suspicious Username", WEIGHT_WEAK, checkSuspiciousUsername);
    ADD_CHECK("System", "Injected Sandbox DLLs", WEIGHT_MEDIUM, detectSandboxDLLs);
    /* Hardware */
    ADD_CHECK("Hardware", "Virtual MAC Address", WEIGHT_STRONG, hasVirtualMacAddress);
    ADD_CHECK("Hardware", "Hyper-V Network Adapter", WEIGHT_WEAK, hasHyperVMacAddress);
    ADD_CHECK("Hardware", "Limited Hardware Configuration", WEIGHT_WEAK, detectHardwareConfigurations);
    ADD_CHECK("Hardware", "Low Screen Resolution", WEIGHT_WEAK, checkScreenResolution);
    ADD_CHECK("Hardware", "Small Disk Drive", WEIGHT_WEAK, checkDriveSize);
    /* User */
    ADD_CHECK("User", "No Mouse Movement", WEIGHT_WEAK, checkMouseMovement);
    ADD_CHECK("User", "Short System Uptime", WEIGHT_WEAK, checkSystemUptime);
    ADD_CHECK("User", "No User Activity", WEIGHT_WEAK, checkUserActivity);
    ADD_CHECK("User", "Few Recent Files", WEIGHT_WEAK, checkRecentFiles);
    ADD_CHECK("User", "Additional Security Processes", WEIGHT_MEDIUM, detectAdditionalProcesses);
    ADD_CHECK("User", "No Keyboard Activity", WEIGHT_WEAK, checkNoKeyboardActivity);
    /* Network */
    ADD_CHECK("Network", "Debugging Ports", WEIGHT_MEDIUM, detectDebuggingPorts);
}
