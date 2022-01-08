#pragma once

#include <Windows.h>
#include "imagehlp.h"
#include <Winternl.h>
#include <fileapi.h>
#include <iostream>
#include <fstream>

using namespace std;
#define PATH_MAX_SIZE 50
#define _CET_SECURE_NO_WARNINGS
#define TARGET_FUNCTION "NtQueryDirectoryFile"
#define TARGET_DLL "windows.storage.dll"
#define LOG_FILENAME "C:\\Users\\Shahar\\Desktop\\project\\log.txt"

typedef NTSTATUS(WINAPI* originalFuncPtr)( // target Function Pointer 
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PVOID FileInformation,
	ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	BOOLEAN ReturnSingleEntry,
	PUNICODE_STRING FileName,
	BOOLEAN RestartSca
	);

typedef NTSTATUS(*convertFuncPtr) ( // strings convertion Function Pointer 
	PANSI_STRING     DestinationString,
	PCUNICODE_STRING SourceString,
	BOOLEAN          AllocateDestinationString
	);

typedef struct _FILE_ID_BOTH_DIR_INFORMATION { //Directory struct
	ULONG         NextEntryOffset;
	ULONG         FileIndex;
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER EndOfFile;
	LARGE_INTEGER AllocationSize;
	ULONG         FileAttributes;
	ULONG         FileNameLength;
	ULONG         EaSize;
	CCHAR         ShortNameLength;
	WCHAR         ShortName[12];
	LARGE_INTEGER FileId;
	WCHAR         FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION, * PFILE_ID_BOTH_DIR_INFORMATION;


