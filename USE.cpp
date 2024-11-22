
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

    HANDLE hCurrentProc = GetCurrentProcess(); // ��ȡ��ǰ���̾��
    DWORD CurrentPid = GetCurrentProcessId(); // ��ȡ��ǰ����pid

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