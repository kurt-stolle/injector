#define _CRT_SECURE_NO_WARNINGS
#define MAX_STR_LEN 64

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include "injector.h"

using namespace std;

// Type definition
typedef HINSTANCE(*fpLoadLibrary)(char*);

// Process entry
int main()
{
	// Variables
	DWORD pid = NULL;
	PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
	HANDLE hProcSnap;
	char processName[128] = "";
	char injectableName[128] = "";

	// Request information
	cout << "Enter process name (.exe): ";
	cin >> processName;
	cout << "Enter injectable name (.dll): ";
	cin >> injectableName;

	// Keep searching until a process id is found
	do {
		// Notify the user
		system("CLS");
		cout << "Searching for " << processName << "..." << endl;

		// Snapshot processes
		hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		// Check if our process is running
		if (Process32First(hProcSnap, &pe32))
		{
			do
			{
				if (!strcmp((const char *) pe32.szExeFile, processName))
				{
					// Set the process ID
					pid = pe32.th32ProcessID;
					break;
				}
			} while (Process32Next(hProcSnap, &pe32));
		}

		// Wait until we're ready to do another search
		Sleep(1000);
	} while (!pid);

	// Attempt to inject the DLL
	while (!injectDLL(pid,injectableName))
	{
		// If we got here, the injection failed. Notify the user.
		system("CLS");
		cout << "DLL failed to inject" << endl;

		// Wait a little while until trying again.
		Sleep(1000);
	}

	// Notify the user
	cout << "DLL Injected successfuly!" << endl << endl;

	// Close snapshot
	CloseHandle(hProcSnap);

	// Wait a little while until closing, to notify the user.
	Sleep(3000);

	return 0;
}

// injectDLL will write to memory, this is the actual injection
bool injectDLL(DWORD pid, const char* file)
{
	LPVOID paramAddr;

	// Open the process
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);;

	// Load the library
	HINSTANCE hDll = LoadLibrary((LPCWCHAR) "KERNEL32");
	fpLoadLibrary LoadLibraryAddr = (fpLoadLibrary)GetProcAddress(hDll, "LoadLibraryA");

	// DLL Path
	char dllPath[250] = "C:\\INJECTABLES\\";
	strcat(dllPath, file);

	// Allocate memory
	paramAddr = VirtualAllocEx(hProc, 0, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);

	// Write to memory (!! is `not not`. This satisfies the compiler.)
	bool memoryWritten = !!(WriteProcessMemory(hProc, paramAddr, dllPath, strlen(dllPath) + 1, NULL));

	// Create thread
	CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryAddr, paramAddr, 0, 0);

	// Close handles
	CloseHandle(hProc);

	// Return the memory
	return memoryWritten;
}