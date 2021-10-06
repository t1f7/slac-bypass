#include "utils.h"

namespace Utils
{
	int StrToBytes(const char* pattern, int* bytes)
	{

		auto start = const_cast<char*>(pattern);
		auto end = const_cast<char*>(pattern) + strlen(pattern);
		int c = 0;

		for (auto current = start; current < end; ++current)
		{
			if (*current == '?')
			{
				++current;
				if (*current == '?')
					++current;
				bytes[c] = -1;
			}
			else
				bytes[c] = strtoul(current, &current, 16);

			c++;
		}
		return c - 1;
	};

	void* PatternScan(void* addrbase, uintptr_t sizeOfImage, const char* pattern)
	{
		int bytes[100];
		auto s = StrToBytes(pattern, bytes);
		auto scanBytes = reinterpret_cast<unsigned char*>(addrbase);

		for (auto i = 0ull; i < sizeOfImage - s; ++i)
		{
			bool found = true;
			for (auto j = 0; j < s; ++j)
			{
				if (scanBytes[i + j] != bytes[j] && bytes[j] != -1)
				{
					found = false;
					break;
				}
			}

			if (found)
				return (void*)i;

		}

		return nullptr;
	}
	
	uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
	{
		uintptr_t modBaseAddr = 0;
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);

		if (hSnap != INVALID_HANDLE_VALUE)
		{
			MODULEENTRY32W modEntry;
			modEntry.dwSize = sizeof(modEntry);
			if (Module32FirstW(hSnap, &modEntry))
			{
				do
				{
					if (!_wcsicmp(modEntry.szModule, modName))
					{
						modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
						break;
					}
				} while (Module32NextW(hSnap, &modEntry));
			}
		}
		CloseHandle(hSnap);
		return modBaseAddr;
	}

	uintptr_t GetProcAddressEx(HANDLE hProcess, DWORD pid, const wchar_t* module, const char* function)
	{
		if (!module || !function || !pid || !hProcess)
			return 0;

		uintptr_t moduleBase = GetModuleBaseAddress(pid, module);

		if (!moduleBase)
			return 0;

		IMAGE_DOS_HEADER Image_Dos_Header = { 0 };

		if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase), &Image_Dos_Header, sizeof(IMAGE_DOS_HEADER), nullptr))
			return 0;

		if (Image_Dos_Header.e_magic != IMAGE_DOS_SIGNATURE)
			return 0;

		IMAGE_NT_HEADERS Image_Nt_Headers = { 0 };

		if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + Image_Dos_Header.e_lfanew), &Image_Nt_Headers, sizeof(IMAGE_NT_HEADERS), nullptr))
			return 0;

		if (Image_Nt_Headers.Signature != IMAGE_NT_SIGNATURE)
			return 0;

		IMAGE_EXPORT_DIRECTORY Image_Export_Directory = { 0 };
		uintptr_t img_exp_dir_rva = 0;

		if (!(img_exp_dir_rva = Image_Nt_Headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress))
			return 0;

		if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + img_exp_dir_rva), &Image_Export_Directory, sizeof(IMAGE_EXPORT_DIRECTORY), nullptr))
			return 0;

		uintptr_t EAT = moduleBase + Image_Export_Directory.AddressOfFunctions;
		uintptr_t ENT = moduleBase + Image_Export_Directory.AddressOfNames;
		uintptr_t EOT = moduleBase + Image_Export_Directory.AddressOfNameOrdinals;

		WORD ordinal = 0;
		SIZE_T len_buf = strlen(function) + 1;
		char* temp_buf = new char[len_buf];

		for (size_t i = 0; i < Image_Export_Directory.NumberOfNames; i++)
		{
			uintptr_t tempRvaString = 0;

			if (!ReadProcessMemory(hProcess, (LPCVOID)(ENT + (i * sizeof(uintptr_t))), &tempRvaString, sizeof(uintptr_t), nullptr))
				return 0;

			if (!ReadProcessMemory(hProcess, (LPCVOID)(moduleBase + tempRvaString), temp_buf, len_buf, nullptr))
				return 0;

			if (!lstrcmpi(function, temp_buf))
			{
				if (!ReadProcessMemory(hProcess, (LPCVOID)(EOT + (i * sizeof(WORD))), &ordinal, sizeof(WORD), nullptr))
					return 0;

				uintptr_t temp_rva_func = 0;

				if (!ReadProcessMemory(hProcess, (LPCVOID)(EAT + (ordinal * sizeof(uintptr_t))), &temp_rva_func, sizeof(uintptr_t), nullptr))
					return 0;

				delete[] temp_buf;
				return moduleBase + temp_rva_func;
			}
		}
		delete[] temp_buf;
		return 0;
	}

	DWORD64 WINAPI GetThreadStartAddress(HANDLE hCurrentProcess, HANDLE hThread)
	{
		NTSTATUS ntStatus;
		HANDLE hDupHandle;
		DWORD64 dwStartAddress;

		auto NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");

		if (NtQueryInformationThread == NULL)
			return 0;

		ntStatus = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(DWORD64), NULL);
		if (ntStatus != STATUS_SUCCESS)
			return 0;

		return dwStartAddress;

	}

	MODULEENTRY32 GetModuleInfoByName(HANDLE process, LPCSTR name)
	{
		auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(process));
		if (snapshot == INVALID_HANDLE_VALUE) {
			return { 0 };
		}

		MODULEENTRY32 entry = { 0 };
		entry.dwSize = sizeof(entry);
		if (Module32First(snapshot, &entry)) {
			do {
				if (_stricmp(entry.szModule, name) == 0) {
					CloseHandle(snapshot);
					return entry;
				}
			} while (Module32Next(snapshot, &entry));
		}

		CloseHandle(snapshot);
		return { 0 };
	}

	DWORD FindPIDByName(const char* name)
	{
		PROCESSENTRY32 PE32{ 0 };
		PE32.dwSize = sizeof(PE32);

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnap == INVALID_HANDLE_VALUE)
		{
			DWORD Err = GetLastError();
			return 0;
		}

		DWORD PID = 0;
		BOOL bRet = Process32First(hSnap, &PE32);
		while (bRet)
		{
			if (!strcmp(name, PE32.szExeFile))
			{
				PID = PE32.th32ProcessID;
				break;
			}
			bRet = Process32Next(hSnap, &PE32);
		}

		CloseHandle(hSnap);

		return PID;
	}

	void* SpawnTrap(HANDLE hProc)
	{
		// find SleepEx RVA at target process
		auto remoteModule = Utils::GetModuleInfoByName(hProc, xorstr_("KERNELBASE.dll"));
		auto pModule = LoadLibraryA(xorstr_("KERNELBASE"));
		auto function = reinterpret_cast<PBYTE>(GetProcAddress(pModule, xorstr_("SleepEx")));
		auto remoteFunction = remoteModule.modBaseAddr + (function - reinterpret_cast<PBYTE>(pModule));

		// while(1) SleepEx(10);
		void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		byte shellCode[] = {
			0x48, 0x83, 0xEC, 0x28,
			0xB9, 0x64, 0x00, 0x00, 0x00,
			0xFF, 0x15, 0x02, 0x00, 0x00, 0x00, 0xEB, 0x08,
			0xA0, 0xAD, 0x3B, 0x74, 0xFB, 0x7F, 0x00, 0x00,
			0xEB, 0xEE
		};
		*reinterpret_cast<PVOID*>(&shellCode[17]) = remoteFunction;
		WriteProcessMemory(hProc, pShellcode, shellCode, sizeof(shellCode), nullptr);

		return pShellcode;
	}

	int RedirectThreadsToTrap(HANDLE hProc, DWORD PID, void* pThreadTrap)
	{
		HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (hThreadSnap == INVALID_HANDLE_VALUE)
			return 0;

		auto mSLAC = Utils::GetModuleInfoByName(hProc, xorstr_("sl-ac.dll"));
		auto mSCPSL = Utils::GetModuleInfoByName(hProc, xorstr_("scpsl.exe"));

		// copy full module for really quick pattern scan
		std::vector<char> tmp;
		tmp.resize(mSCPSL.modBaseSize);

		size_t copied;
		if (!ReadProcessMemory(hProc, (LPCVOID)mSCPSL.modBaseAddr, &tmp[0], mSCPSL.modBaseSize, &copied))
		{
			CloseHandle(hThreadSnap);
			return 0;
		}

		// launcher calls FindWindow and something else ...
		auto niggerThreadInLauncher = (DWORD64)mSCPSL.modBaseAddr + (DWORD64)Utils::PatternScan(tmp.data(), mSCPSL.modBaseSize, xorstr_("E8 ?? ?? ?? ?? 41 52 49 89 E2 41 52"));
		auto niggaThreadInLauncher = (DWORD64)mSCPSL.modBaseAddr + (DWORD64)Utils::PatternScan(tmp.data(), mSCPSL.modBaseSize, xorstr_("E9 ?? ?? ?? ?? 63 41 67 51 DE"));

		int niggersCaught = 0;

		THREADENTRY32 te;
		te.dwSize = sizeof(te);

		if (Thread32First(hThreadSnap, &te))
		{
			do
			{

				if (te.th32OwnerProcessID != PID)
					continue;

				if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
				{

					uintptr_t baseAddress = 0;
					auto handle = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
					if (!handle)
						continue;

					auto threadBase = Utils::GetThreadStartAddress(hProc, handle);
					if (threadBase == niggerThreadInLauncher || threadBase == niggaThreadInLauncher || (threadBase >= (uintptr_t)mSLAC.modBaseAddr && threadBase <= (uintptr_t)mSLAC.modBaseAddr + mSLAC.modBaseSize))
					{

						CONTEXT ctx{ 0 };
						ctx.ContextFlags = CONTEXT_FULL;

						GetThreadContext(handle, &ctx);
						ctx.Rip = (uintptr_t)pThreadTrap;
						SetThreadContext(handle, &ctx);

						CloseHandle(handle);

						niggersCaught++;
					}

				}
				te.dwSize = sizeof(te);
			} while (Thread32Next(hThreadSnap, &te));
		}
		CloseHandle(hThreadSnap);

		CloseHandle(hProc);

		return niggersCaught++;
	}
}
