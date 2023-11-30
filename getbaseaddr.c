#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>

BOOL SetPriv(HANDLE token, char *privilege) {
	TOKEN_PRIVILEGES tp;
	LUID luid;
	int err = 0;

	if (!LookupPrivilegeValueA(
		NULL,       // lookup privilege on local system
		privilege,  // privilege to lookup 
		&luid))     // receives LUID of privilege
	{
		printf("LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Enable the privilege

	AdjustTokenPrivileges(token, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	if ((err = GetLastError()) != ERROR_SUCCESS) {
		//printf("AdjustTokenPrivileges error: %u\n", err); //Get error here (ie invalid handle)
		return FALSE;
	}
	else {
		printf("Applied %s\n", privilege);
	}
	return TRUE;
}

BYTE* GetModuleBaseAddress(LPCSTR szProcessName, LPCSTR szModuleName) {
	HANDLE hSnap;
	HANDLE procSnap;
	PROCESSENTRY32 pe32;
	int PID;
	MODULEENTRY32 xModule;

	procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (procSnap == INVALID_HANDLE_VALUE) {
		printf("Create Snapshot error\n");
		return 0;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(procSnap, &pe32) == 0) {
		printf("Process32First error\n");
		CloseHandle(procSnap);
		return 0;
	}

	// Loop through processes until we find szProcessName
	do {
		if (_strcmpi(pe32.szExeFile, szProcessName) == 0) {
			PID = pe32.th32ProcessID;
			hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, PID); //

			if (hSnap == INVALID_HANDLE_VALUE) {
				printf("Received invalid handle value for PID: %d\n", PID);
				printf("Error: %u (try running with admin privileges)\n", GetLastError());
				return 0;
			}
			xModule.dwSize = sizeof(MODULEENTRY32);
			if (Module32First(hSnap, &xModule) == 0) {
				printf("Module32First error\n");
				CloseHandle(hSnap);
				return 0;
			}
			// Loop through modules until we find szModuleName
			do {
				if (_strcmpi(xModule.szModule, szModuleName) == 0) {
					CloseHandle(hSnap);
					return xModule.modBaseAddr;
				}
			} while (Module32Next(hSnap, &xModule));
			CloseHandle(hSnap);
			printf("Couldnt find module\n");
			return 0;
		}
	} while (Process32Next(procSnap, &pe32));
	CloseHandle(procSnap);
	printf("Failed to find process\n");
	return 0;
}

int main(int argc, char **argv) {
	BYTE* addr;
	HANDLE self = NULL;

	if (argc < 2) {
		printf("[ === %s === ]\nUsage:\n  ./%s <executable> <module (optional)>\n", argv[0], argv[0]);
		printf("example:\n  ./%s main.exe kernel32.dll\n", argv[0]);
		return 0;
	}

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &self)) {
		printf("Token err: %u\n", GetLastError());
	}

	SetPriv(self, (char *)SE_DEBUG_NAME); //SeDebugPriv needed if trying to access a system process

	addr = GetModuleBaseAddress(argv[1], argv[argc - 1]); //If only 1 argument, argv[1]. If 2 arguments, argv[2]
	
	if (addr) {
		printf("%s\n  [Base Address]: 0x%llx  (%lld)\n", argv[argc-1], addr, addr);
	}
	return !addr;
}
