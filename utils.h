#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <winternl.h>
#include <vector>
#include "xor.h"

#define STATUS_SUCCESS    ((NTSTATUS)0x00000000L)
#define ThreadQuerySetWin32StartAddress 9
typedef NTSTATUS(WINAPI* pNtQIT)(HANDLE, LONG, PVOID, ULONG, PULONG);

namespace Utils
{
	int StrToBytes(const char* pattern, int* bytes);
	void* PatternScan(void* addrbase, uintptr_t sizeOfImage, const char* pattern);

	uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName);
	uintptr_t GetProcAddressEx(HANDLE hProcess, DWORD pid, const wchar_t* module, const char* function);
	DWORD64 WINAPI GetThreadStartAddress(HANDLE hCurrentProcess, HANDLE hThread);
	MODULEENTRY32 GetModuleInfoByName(HANDLE process, LPCSTR name);
	DWORD FindPIDByName(const char* name);

	void* SpawnTrap(HANDLE hProc);
	int RedirectThreadsToTrap(HANDLE hProc, DWORD PID, void* pThreadTrap);
}
