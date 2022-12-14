#include "ApcLib.h"
#include "PeParser.h"
#include <stdio.h>
#include <winternl.h>
#include <psapi.h>

PNT_GET_NEXT_THREAD NtGetNextThread;
PNT_QUEUE_APC_THREAD NtQueueApcThread;
PNT_QUEUE_APC_THREAD RtlQueueApcWow64Thread;
PNT_QUEUE_APC_THREAD_EX NtQueueApcThreadEx;
PLOAD_LIBRARY_A LoadLibraryAPtr;
PLDR_LOAD_DLL LdrLoadDllPtr;
ULONG_PTR addr_RtlDispatchAPC;

VOID
InitializeApcLib(
	VOID
)
{
	// let's see what is GetModuleHandleA doing
	// according to the doc, the module must be already loaded
	// well, I didn't notice where are these modules loaded
	// the handle retrived here is then used in GetProcAddress function
	// I'm a little confused about the doc, but whatever, just use it like this 
	// maybe the doc means that the module should be loaded because we gonna use it 
	// in GetProcAddress, if not loaded, there will be error when calling GetProcAddress
	HMODULE NtdllHandle = GetModuleHandleA("ntdll.dll");
	HMODULE Kernel32Handle = GetModuleHandleA("kernel32.dll");

	// as a good habit, always check the return value
	if (NtdllHandle == NULL || Kernel32Handle == NULL) {
		printf("GetModuleHandleA failed!\n");
		return;
	}
	printf("this is the base address of ntdll.dll: \t%p\n", (void*)NtdllHandle);
	// so PNT_GET_NEXT_THREAD is a self defined function typedef
	// I don't know why we have to convert the retrived function
	// so this function NtGetNextThread is undocumented, we need to convert it 
	// so it can be used by us, the parameter and return value is discovered 
	// by reverse enginnering, thes guys are really good
	// I have no idea how they discovered these undocumented functions
	// this function's assembly code can be viewed with windbg
	// I ask a question in my qq group: https://img-blog.csdnimg.cn/76a0fa3a476d4fbfa551cc17fd4ad3a6.png
	// now I know where to look, https://github.com/processhacker/phnt
	// thie repository contains almost all of the undocumented APIs
	// in case someday this repository is deleted, I archived this repository as 
	// an 7z file an upload it here: https://github.com/wqreytuk/phnt/blob/main/phnt-master_2.7z
	// the password is: 1
	// so yes, I can find this function here: https://img-blog.csdnimg.cn/9811de369f73486f92023f624eace44f.png 
	// so this is what InitializeApcLib does, he generate a few undocumented functions for us
	NtGetNextThread = (PNT_GET_NEXT_THREAD)GetProcAddress(NtdllHandle, "NtGetNextThread");
	NtQueueApcThread = (PNT_QUEUE_APC_THREAD)GetProcAddress(NtdllHandle, "NtQueueApcThread");
	RtlQueueApcWow64Thread = (PNT_QUEUE_APC_THREAD)GetProcAddress(NtdllHandle, "RtlQueueApcWow64Thread");
	NtQueueApcThreadEx = (PNT_QUEUE_APC_THREAD_EX)GetProcAddress(NtdllHandle, "NtQueueApcThreadEx");
	printf("this is the address of ntdll!NtQueueApcThreadEx: \t%p\n", NtQueueApcThreadEx);
	LdrLoadDllPtr = (PLDR_LOAD_DLL)GetProcAddress(NtdllHandle, "LdrLoadDll");
	// ????ntdll!RtlDispatchAPC????????????????????NtQueueApcThread????????????
	// ????????????????????????????????????????GetProcAddress????????????????????????
	// ????????????????win8 6.2 9200 x64????
	addr_RtlDispatchAPC = (ULONG_PTR)(void*)NtdllHandle + 0x65E04;
	printf("this is the address of ntdll!RtlDispatchAPC: \t%p\n", (void*)addr_RtlDispatchAPC);
	// as far as I know, LoadLibraryA is a documented function, I have no idea why 
	// we have to get it with GetProcAddress, I'll try it without using GetProcAddress
	// oh I see, this function is passed to QueueUserAPC as an APC, so we need to 
	// get this function's address and make some convertion
	LoadLibraryAPtr = (PLOAD_LIBRARY_A)GetProcAddress(Kernel32Handle, "LoadLibraryA");
}

PVOID 
WriteLibraryNameToRemote(
	HANDLE ProcessHandle,
	PCSTR Library			// dll path
	)
{
	SIZE_T LibraryLength = strlen(Library);

	// from doc: Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process. The function initializes the memory it allocates to zero
	PVOID LibraryRemoteAddress = VirtualAllocEx(
		ProcessHandle,
		NULL,			// opt, specify start address of the virtual memory region you want to allocate
		LibraryLength + 1,	// allocated memory size, so what is the meaning of writing a 
							// DLL path to this process?
		MEM_RESERVE | MEM_COMMIT,		// reserve and commit memory, reserve means no memory allocated, just reserved for us for future use
		// commit means allocate memory for the reserved memory region, but the actual 
		// physical memory is allocated until the virtual memory is accessed				
		PAGE_READWRITE			// memory protection
	);

	if (!LibraryRemoteAddress) {
		printf("Cannot allocate memory for library path. Error: 0x%08X\n", GetLastError());
		exit(-1);
	}

	// from doc: Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails
	// so we write out specified dll path to the target process
	if (!WriteProcessMemory(
		ProcessHandle,
		LibraryRemoteAddress,
		Library,
		LibraryLength + 1,
		NULL
	)) {
		printf("Cannot write library path to remote process. Error: 0x%08X\n", GetLastError());
		exit(-1);
	}

	return LibraryRemoteAddress;
}


VOID
OpenTargetHandles(
	__in ULONG ProcessId,
	__in_opt ULONG ThreadId,
	__out PHANDLE ProcessHandle,
	__out PHANDLE ThreadHandle
	)
{
	NTSTATUS Status;

	// from doc: Opens an existing local process object
	*ProcessHandle = OpenProcess(
		PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION |
		PROCESS_VM_READ |
		PROCESS_VM_WRITE,		// see https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
		FALSE,			// bInheritHandle
		ProcessId
	);

	// good habit, check ret value
	if (!*ProcessHandle) {
		printf("Cannot open process handle: 0x%08X\n", GetLastError());
		exit(-1);
	}

	// check if optional param exists
	if (ThreadId) {
		// from doc: Opens an existing thread object
		*ThreadHandle = OpenThread(THREAD_SET_CONTEXT, // see https://docs.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights
			FALSE,		// bInheritHandle
			ThreadId);

		if (!*ThreadHandle) {
			printf("Cannt open thread handle 0x%08X\n", GetLastError());
			exit(-1);
		}
	}
	else {
		// this uncodumented function will retrive the first thread in specified process
		// ignore this function, it makes no sense
		Status = NtGetNextThread(
			*ProcessHandle,
			NULL,
			THREAD_SET_CONTEXT,
			0,
			0,
			ThreadHandle
		);

		if (!NT_SUCCESS(Status)) {
			printf("Cannot open thread handle 0x%08X\n", Status);
			exit(-1);
		}
	}
}


BOOLEAN
Is32BitProcess(
	HANDLE ProcessHandle
	)
{
	USHORT ProcessMachine;
	USHORT NativeMachine;

	if (!IsWow64Process2(ProcessHandle, &ProcessMachine, &NativeMachine)) {
		printf("IsWow64Process2 Failed: 0x%08X\n", GetLastError());
		exit(-1);
	}

	return ProcessMachine == IMAGE_FILE_MACHINE_I386;
}


ULONG64
DecodeWow64ApcRoutine(
	ULONG64 ApcRoutine
)
{
	return (ULONG64)(-((INT64)ApcRoutine >> 2));
}

ULONG64
EncodeWow64ApcRoutine(
	ULONG64 ApcRoutine
)
{
	return (ULONG64)((-(INT64)ApcRoutine) << 2);
}


PVOID 
GetRemoteModuleAddress(
	HANDLE ProcessHandle,
	PCSTR ModuleName
	)
{
	HMODULE ProcessModules[50];
	DWORD ProcessModulesByteCount;
	DWORD ProcessModulesCount;
	DWORD ModuleBaseNameLength;
	CHAR ModuleFileName[MAX_PATH];
	RtlZeroMemory(ProcessModules, sizeof(ProcessModules));

	if (!EnumProcessModulesEx(ProcessHandle, ProcessModules, sizeof(ProcessModules), &ProcessModulesByteCount, LIST_MODULES_32BIT)) {
		printf("EnumProcessModules Failed. 0x%08X\n", GetLastError());
		exit(-1);
	}

	ProcessModulesCount = ProcessModulesByteCount / sizeof(HMODULE);

	for (DWORD i = 0; i < ProcessModulesCount; i++) {

		ModuleBaseNameLength = GetModuleBaseNameA(ProcessHandle, ProcessModules[i], &ModuleFileName[0], sizeof(ModuleFileName) - 1);

		if (ModuleBaseNameLength == 0) {
			continue;
		}

		if (!_stricmp(ModuleFileName, ModuleName)) {
			return (PVOID)ProcessModules[i];
		}
	}

	return NULL;
}

PVOID
QueryWow64LoadLibraryAddress(
	HANDLE ProcessHandle
	)
{

	PVOID Kernel32Address = NULL;
	ULONG LoadLibraryAOffset;

	Kernel32Address = GetRemoteModuleAddress(ProcessHandle, "kernel32.dll");

	LoadLibraryAOffset = GetExportOffset("c:\\windows\\syswow64\\kernel32.dll", "LoadLibraryA");

	return OffsetPtr(Kernel32Address, LoadLibraryAOffset);
}

PVOID 
WriteUnicodeLibraryNameToRemote(
	HANDLE ProcessHandle,
	PCSTR LibraryPath
	)
{
	PWSTR UnicodeLibraryPath = AsciiStringToUnicodeString(LibraryPath);
	USHORT LibraryBytesCount = (USHORT)(wcslen(UnicodeLibraryPath) * sizeof(WCHAR));
	USHORT AllocationBytesCount = LibraryBytesCount + 1 + sizeof(UNICODE_STRING);

	PVOID LibraryRemoteAddress = VirtualAllocEx(
		ProcessHandle,
		NULL,
		AllocationBytesCount,
		MEM_RESERVE | MEM_COMMIT,
		PAGE_READWRITE
	);

	if (!LibraryRemoteAddress) {
		printf("Cannot allocate memory for library path. Error: 0x%08X\n", GetLastError());
		exit(-1);
	}


	PUNICODE_STRING LocalUnicodeString = (PUNICODE_STRING)HeapAlloc(GetProcessHeap(), 0, AllocationBytesCount);

	if (LocalUnicodeString == NULL) {
		exit(-1);
	}

	RtlZeroMemory(LocalUnicodeString, AllocationBytesCount);

	LocalUnicodeString->MaximumLength = LibraryBytesCount;
	LocalUnicodeString->Length = LibraryBytesCount;
	LocalUnicodeString->Buffer = (PWCHAR)(((PUCHAR)LibraryRemoteAddress) + sizeof(UNICODE_STRING));

	RtlCopyMemory((((PUCHAR)LocalUnicodeString) + sizeof(UNICODE_STRING)), UnicodeLibraryPath, LibraryBytesCount);

	if (!WriteProcessMemory(
		ProcessHandle,
		LibraryRemoteAddress,
		LocalUnicodeString,
		sizeof(UNICODE_STRING) + LibraryBytesCount + 1,
		NULL
	)) {
		printf("Cannot write library path to remote process. Error: 0x%08X\n", GetLastError());
		exit(-1);
	}

	return LibraryRemoteAddress;
}



PWSTR
AsciiStringToUnicodeString(
	PCSTR AsciiString
	)
{
	USHORT Length = (USHORT)strlen(AsciiString);
	PWSTR UnicodeString = (PWSTR)malloc(Length * 2);

	if (UnicodeString == NULL) {
		printf("Failed allocating unicode string.");
		exit(-1);
	}

	if (MultiByteToWideChar(CP_OEMCP, 0, AsciiString, Length + 1, UnicodeString, Length + 1) != (Length + 1)) {
		printf("Cannot convert command line to utf-16 0x%08X\n", GetLastError());
		exit(-1);
	}

	return UnicodeString;
}