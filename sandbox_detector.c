/*
################################################################################################
NOTE:

This is just a proof-of-concept code that demonstrates some methods APT level malware uses to detect a sandbox environment.  
ex: mouse movments , process analysis like x64dbg , memory and hardware size etc
When applying it in the real world, all of this code needs to be obfuscated and requires extensive AV/EDR evasion techniques.

kindly read the README.md inorder to understand the code

also this code contain only some techniques I mentioned about in the notes also some i didn't mentioned

################################################################################################

By ARXHR007 ;)
################################################################################################

*/

#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <time.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <winreg.h>
#include <cpuid.h>
#include <wininet.h>
#include <ctype.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#ifndef GetTickCount64
ULONGLONG GetTickCount64(void) {
    return (ULONGLONG)GetTickCount();
}
#endif
typedef struct {
    char category[32];
    char test[64];
    bool detected;
} DetectionResult;
typedef struct {
    DetectionResult* results;
    int resultCount;
    int capacity;
    bool isInSandbox;
} SandboxDetector;
SandboxDetector* newSandboxDetector() {
    SandboxDetector* detector = (SandboxDetector*)malloc(sizeof(SandboxDetector));
    detector->capacity = 20;
    detector->resultCount = 0;
    detector->results = (DetectionResult*)malloc(sizeof(DetectionResult) * detector->capacity);
    detector->isInSandbox = false;
    return detector;
}
void addResult(SandboxDetector* detector, const char* category, const char* test, bool detected) {
    if (detector->resultCount >= detector->capacity) {
        detector->capacity *= 2;
        detector->results = (DetectionResult*)realloc(detector->results, sizeof(DetectionResult) * detector->capacity);
    }
    strcpy(detector->results[detector->resultCount].category, category);
    strcpy(detector->results[detector->resultCount].test, test);
    detector->results[detector->resultCount].detected = detected;
    detector->resultCount++;
    if (detected) {
        detector->isInSandbox = true;
    }
}
char* getRegValue(HKEY hKey, const char* subKey, const char* valueName) {
    HKEY hSubKey;
    LONG result = RegOpenKeyExA(hKey, subKey, 0, KEY_READ, &hSubKey);
    if (result != ERROR_SUCCESS) {
        return NULL;
    }
    DWORD bufferSize = 1024;
    char* buffer = (char*)malloc(bufferSize);
    DWORD valueType;
    result = RegQueryValueExA(hSubKey, valueName, NULL, &valueType, (LPBYTE)buffer, &bufferSize);
    RegCloseKey(hSubKey);
    if (result != ERROR_SUCCESS) {
        free(buffer);
        return NULL;
    }
    return buffer;
}
bool isProcessRunningByName(const char* processName) {
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
        if (strcmp(entry.szExeFile, processName) == 0) {
            CloseHandle(snapshot);
            return true;
        }
    } while (Process32Next(snapshot, &entry));
    CloseHandle(snapshot);
    return false;
}
bool hasVirtualMacAddress() {
    const char* vmPrefixes[] = {
        "00-05-69", 
        "00-0C-29", 
        "00-1C-14", 
        "00-50-56", 
        "00-1C-42", 
        "00-03-FF", 
        "00-0F-4B", 
        "00-16-3E", 
        "08-00-27"  
    };
    int prefixCount = sizeof(vmPrefixes) / sizeof(vmPrefixes[0]);
    ULONG bufferSize = 0;
    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &bufferSize);
    if (bufferSize == 0) {
        return false;
    }
    IP_ADAPTER_ADDRESSES* addresses = (IP_ADAPTER_ADDRESSES*)malloc(bufferSize);
    if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, addresses, &bufferSize) != ERROR_SUCCESS) {
        free(addresses);
        return false;
    }
    IP_ADAPTER_ADDRESSES* current = addresses;
    while (current) {
        if (current->PhysicalAddressLength == 6) {
            char macAddr[18];
            sprintf(macAddr, "%02X-%02X-%02X-%02X-%02X-%02X",
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
bool detectVMwareRegistryKeys() {
    const char* vmwareKeys[] = {
        "SOFTWARE\\VMware, Inc.\\VMware Tools",
        "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"
    };
    int keyCount = sizeof(vmwareKeys) / sizeof(vmwareKeys[0]);
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
bool detectVirtualFiles() {
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
    int fileCount = sizeof(vmFiles) / sizeof(vmFiles[0]);
    for (int i = 0; i < fileCount; i++) {
        if (GetFileAttributesA(vmFiles[i]) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }
    return false;
}
bool detectVMProcesses() {
    const char* vmProcesses[] = {
        "vmtoolsd.exe",
        "vmwaretray.exe",
        "vmwareuser.exe",
        "VBoxService.exe",
        "VBoxTray.exe"
    };
    int processCount = sizeof(vmProcesses) / sizeof(vmProcesses[0]);
    for (int i = 0; i < processCount; i++) {
        if (isProcessRunningByName(vmProcesses[i])) {
            return true;
        }
    }
    return false;
}
bool detectVirtualServices() {
    SC_HANDLE scManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (scManager == NULL) {
        return false;
    }
    const char* vmServices[] = {
        "VMTools",
        "VBoxService"
    };
    int serviceCount = sizeof(vmServices) / sizeof(vmServices[0]);
    bool result = false;
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
    EnumServicesStatusExA(scManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
                         NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);
    if (bytesNeeded > 0) {
        ENUM_SERVICE_STATUS_PROCESS* services = (ENUM_SERVICE_STATUS_PROCESS*)malloc(bytesNeeded);
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
bool detectDebuggingPorts() {
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
bool detectDeviceBios() {
    char buffer[4096] = {0};
    DWORD size = sizeof(buffer);
    const char* vmIndicators[] = {
        "VMware",
        "VBOX",
        "Virtual",
        "Xen",
        "innotek",
        "QEMU"
    };
    int indicatorCount = sizeof(vmIndicators) / sizeof(vmIndicators[0]);
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
bool detectHardwareConfigurations() {
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
bool checkScreenResolution() {
    int desktopWidth = GetSystemMetrics(SM_CXSCREEN);
    int desktopHeight = GetSystemMetrics(SM_CYSCREEN);
    return (desktopWidth < 1024 || desktopHeight < 768);
}
bool checkMouseMovement() {
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
bool checkSystemUptime() {
    return (GetTickCount64() / 1000 < 60 * 10); 
}
bool checkUserActivity() {
    LASTINPUTINFO lastInput;
    lastInput.cbSize = sizeof(LASTINPUTINFO);
    if (GetLastInputInfo(&lastInput)) {
        DWORD idleTime = GetTickCount() - lastInput.dwTime;
        return (idleTime >= 600000); 
    }
    return false;
}
bool checkTimeAcceleration() {
    time_t start = time(NULL);
    Sleep(3000); 
    time_t end = time(NULL);
    time_t elapsed = end - start;
    return (elapsed < 2 || elapsed > 4); 
}
bool checkRecentFiles() {
    char recentPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_RECENT, NULL, 0, recentPath);
    WIN32_FIND_DATAA findData;
    char searchPath[MAX_PATH];
    sprintf(searchPath, "%s\\*.lnk", recentPath);
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
bool checkRegistry() {
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
    int keyCount = sizeof(keys) / sizeof(keys[0]);
    for (int i = 0; i < keyCount; i++) {
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
bool checkSandboxArtifacts() {
    const char* sandboxArtifacts[] = {
        "C:\\agent\\agent.pyw",
        "C:\\analysis",
        "C:\\sandbox",
        "C:\\Tools\\Wireshark",
        "C:\\iDEFENSE",
        "C:\\analysis_logs",
        "C:\\sandbox logs",
        "C:\\program files\\wireshark",
        "C:\\program files\\fiddler"
    };
    int artifactCount = sizeof(sandboxArtifacts) / sizeof(sandboxArtifacts[0]);
    for (int i = 0; i < artifactCount; i++) {
        if (GetFileAttributesA(sandboxArtifacts[i]) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }
    return false;
}
bool checkSandboxHostnames() {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        return false;
    }
    const char* sandboxNames[] = {
        "sandbox",
        "virus",
        "malware",
        "cuckoo",
        "analysis",
        "lab",
        "maltest",
        "test",
        "artifacts",
        "vm-",
        "pc-",
        "john-pc"
    };
    int nameCount = sizeof(sandboxNames) / sizeof(sandboxNames[0]);
    for (int i = 0; hostname[i]; i++) {
        hostname[i] = tolower(hostname[i]);
    }
    for (int i = 0; i < nameCount; i++) {
        if (strstr(hostname, sandboxNames[i]) != NULL) {
            return true;
        }
    }
    return false;
}
bool checkDriveSize() {
    UINT driveType = GetDriveTypeA("C:\\");
    if (driveType == DRIVE_FIXED) {
        ULARGE_INTEGER freeBytes, totalBytes, totalFreeBytes;
        if (GetDiskFreeSpaceExA("C:\\", &freeBytes, &totalBytes, &totalFreeBytes)) {
            return (totalBytes.QuadPart < 60000000000LL); 
        }
    }
    return false;
}
bool isRunningInHypervisor() {
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx >> 31) & 1;
    }
    return false;
}
bool detectAdditionalProcesses() {
    const char* additionalProcesses[] = {
        "procmon.exe",
        "wireshark.exe",
        "ollydbg.exe",
        "x64dbg.exe"
    };
    int count = sizeof(additionalProcesses) / sizeof(additionalProcesses[0]);
    for (int i = 0; i < count; i++) {
        if (isProcessRunningByName(additionalProcesses[i])) {
            return true;
        }
    }
    return false;
}
bool checkVirtualMAC() {
    return hasVirtualMacAddress();
}
bool isKeyboardUsed() {
    for (int i = 0; i < 300; i++) {
        for (int key = 0; key < 256; key++) {
            if (GetAsyncKeyState(key) & 0x8000) {
                return true;
            }
        }
        Sleep(10);
    }
    return false;
}
void runTests(SandboxDetector* detector) {
    addResult(detector, "Runtime", "Time Acceleration", checkTimeAcceleration());
    addResult(detector, "System", "VM Registry Keys", detectVMwareRegistryKeys());
    addResult(detector, "System", "Virtual Files", detectVirtualFiles());
    addResult(detector, "System", "Virtual Processes", detectVMProcesses());
    addResult(detector, "System", "Virtual Services", detectVirtualServices());
    addResult(detector, "System", "BIOS/Device Information", detectDeviceBios());
    addResult(detector, "System", "Registry Indicators", checkRegistry());
    addResult(detector, "System", "Sandbox Artifacts", checkSandboxArtifacts());
    addResult(detector, "System", "Sandbox Hostnames", checkSandboxHostnames());
    addResult(detector, "Hardware", "Virtual MAC Address", hasVirtualMacAddress());
    addResult(detector, "Hardware", "Limited Hardware Configuration", detectHardwareConfigurations());
    addResult(detector, "Hardware", "Low Screen Resolution", checkScreenResolution());
    addResult(detector, "Hardware", "Small Disk Drive", checkDriveSize());
    addResult(detector, "User", "No Mouse Movement", checkMouseMovement());
    addResult(detector, "User", "Short System Uptime", checkSystemUptime());
    addResult(detector, "User", "No User Activity", checkUserActivity());
    addResult(detector, "User", "Few Recent Files", checkRecentFiles());
    addResult(detector, "Network", "Debugging Ports", detectDebuggingPorts());
    addResult(detector, "Runtime", "Hypervisor Detected", isRunningInHypervisor());
    addResult(detector, "User", "Additional Security Processes", detectAdditionalProcesses());
    addResult(detector, "Hardware", "Virtual MAC (Alternate)", checkVirtualMAC());
    addResult(detector, "User", "Keyboard Used", isKeyboardUsed());
}
void printResults(SandboxDetector* detector) {
    printf("==== Sandbox Detection Results ====\n\n");
    const char* categories[] = {"Runtime", "System", "Hardware", "User", "Network"};
    int categoryCount = sizeof(categories) / sizeof(categories[0]);
    for (int i = 0; i < categoryCount; i++) {
        printf("--- %s Tests ---\n", categories[i]);
        for (int j = 0; j < detector->resultCount; j++) {
            if (strcmp(detector->results[j].category, categories[i]) == 0) {
                const char* status = detector->results[j].detected ? "Detected!" : "Not detected";
                printf("%s: %s\n", detector->results[j].test, status);
            }
        }
        printf("\n");
    }
    printf("==== Overall Assessment ====\n");
    if (detector->isInSandbox) {
        printf("WARNING: System appears to be running in a sandbox or virtual environment!\n");
    } else {
        printf("System appears to be a genuine environment.\n");
    }
    printf("\n");
    int detectedCount = 0;
    for (int i = 0; i < detector->resultCount; i++) {
        if (detector->results[i].detected) {
            detectedCount++;
        }
    }
    int percentage = (detector->resultCount > 0) ? (detectedCount * 100) / detector->resultCount : 0;
    printf("Detection ratio: %d/%d (%d%%)\n", detectedCount, detector->resultCount, percentage);
    printf("\nby ARXHR007\n");

}
int main() {
    printf("Running sandbox detection...\n");
    printf("Please wait while tests are being performed (takes upto 10 seconds)...\n\n");
    SandboxDetector* detector = newSandboxDetector();
    runTests(detector);
    printResults(detector);
    printf("Press any key to exit...\n");
    getchar();
    free(detector->results);
    free(detector);
    return 0;
}
