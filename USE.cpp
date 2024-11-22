
#include "ex.h"

#pragma comment(lib, "ntdll.lib")

DWORD64 NTOKernelBase;
HMODULE NTOUserBase;


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

}