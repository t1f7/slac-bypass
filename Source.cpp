#include "utils.h"

int GracefulExit(char* reason)
{
	printf(reason);
	system(xorstr_("PAUSE"));

	return 0;
}

int main()
{

	auto PID = Utils::FindPIDByName(xorstr_("SCPSL.exe"));
	if (!PID)
		return GracefulExit(xorstr_("- [error]\nProcess is not running!\n"));

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProc)
		return GracefulExit(xorstr_("- [error]\nAttach to process failed!\n"));

	auto pThreadTrap = Utils::SpawnTrap(hProc);

	auto iThreadsTrapped = Utils::RedirectThreadsToTrap(hProc, PID, pThreadTrap);
	printf(xorstr_("+ [success]\nThreads trapped: %i"), iThreadsTrapped);

	GracefulExit(xorstr_(".\n"));

	return 0;
}