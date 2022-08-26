#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <ApcLib/ApcLib.h>

BOOL FileExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

typedef enum _APC_TYPE {
	ApcTypeWin32,
	ApcTypeNative,
	ApcTypeSpecial
} APC_TYPE;

typedef struct _APC_INJECTOR_ARGS {
	APC_TYPE ApcType;
	PCSTR DllPath;
	ULONG ProcessId;
	ULONG ThreadId;
} APC_INJECTOR_ARGS, * PAPC_INJECTOR_ARGS;

VOID
ParseArguments(
	__in int ArgumentCount,
	__in const char** Arguments,
	__out PAPC_INJECTOR_ARGS Args)
{
	// so we need submit 3 cmdline params at least
	// the fourth is optional
	if (ArgumentCount < 4) {
		printf("Missing arguments!\n");
		printf("ApcDllInjector.exe <native/win32/special> <process_id> <dll_path> [thread_id]\n");
		exit(-1);
	}

	// atoi means string to int
	Args->ProcessId = atoi(Arguments[2]);
	Args->DllPath = Arguments[3];
	Args->ThreadId = 0;
	// so this is the default apc type
	// I guess win32 means user mode
	Args->ApcType = ApcTypeWin32;

	// here comes the thread id
	if (ArgumentCount > 4) {
		Args->ThreadId = atoi(Arguments[4]);
	}

	// check apc type
	if (strcmp(Arguments[1], "native") == 0) {
		Args->ApcType = ApcTypeNative;
	}
	else if (strcmp(Arguments[1], "win32") == 0) {
		Args->ApcType = ApcTypeWin32;
	}
	else if (strcmp(Arguments[1], "special") == 0) {
		Args->ApcType = ApcTypeSpecial;
	}
	else {
		printf("Invalid injection mode '%s'\n", Arguments[1]);
		exit(-1);
	}
}

// this project should be a user mode APC usage
int main(int argc, const char** argv) {

	APC_INJECTOR_ARGS Args;
	NTSTATUS Status;
	HANDLE ThreadHandle;
	HANDLE ProcessHandle;
	PVOID RemoteLibraryAddress;
	PVOID stack_param_tester;

	// a couple of undocumented functions is generated in this function
	InitializeApcLib();

	// take care of arguments from cmdline
	// the third param should be an out param, the first two params is taken from main function
	ParseArguments(argc, argv, &Args);

	// self-defined function in apclib.c
	// first two params in, last two params out
	OpenTargetHandles(
			Args.ProcessId,
			Args.ThreadId,		// optional
			&ProcessHandle,
			&ThreadHandle
		);

	// self-defined function in apclib.c
	// return value is an address of memory allocated in target process
	RemoteLibraryAddress = WriteLibraryNameToRemote(ProcessHandle, Args.DllPath);
	stack_param_tester = WriteLibraryNameToRemote(ProcessHandle, TEXT("woaiouye"));

	switch (Args.ApcType) {
	case ApcTypeWin32: {
		// from doc: Adds a user-mode asynchronous procedure call (APC) object to the APC queue of the specified thread
		while (1) {
			if (FileExists(TEXT("C:\\1.txt"))) {
				if (FileExists(TEXT("C:\\1.txt")))
					if (!QueueUserAPC((PAPCFUNC)LoadLibraryAPtr, ThreadHandle,
						(ULONG_PTR)RemoteLibraryAddress) // this is the param to LoadLibraryAPtr(function)
						// I guess this is why we have to write this dll path to the memory of target process
						// because APC is associated with thread, and thread is in process, so 
						// APC can only access memory in this process memory region
						// this seems to be the only way to pass dll path to APC
						) {
						printf("QueueUserAPC Error! 0x%08X\n", GetLastError());
						exit(-1);
					}
				break;
			}
			Sleep(500);
		}
	}
					   break;
	case ApcTypeNative: {
		// I guess native means this function(API) is not documented, only the function name is known to us
		// but I have no idea how they found that this function is in ntdll.dll
		// I'll make a test, delete this function usage and the correspond code in apclib.c
		// then build this exe and analysis the import table with my pe_parser
		// well, this is not nessary, I've traced the call stack and record it in my blog
		// http://144.34.164.217/practical-reverse-engineering-notes-part-ii.html#81b65a32e5e542619c5e1d868f9d2b25
		// let's make a char array to check if the fifth parameter is pass through stack
		printf("here is the address of stack_param_tester: %p\n", stack_param_tester);
		while (1) {
			if (FileExists(TEXT("C:\\1.txt"))) {
				Status = NtQueueApcThread(
					// you may notice that this function have more params than the documented one
					// with this fucntion, you can pass three parameter to you APC routine
					// not so much to say, almost same as QueueUserAPC, only two more params can be passed
					// emmm, seems like something is run, APC is inserted, but the data there is not
					// quiet right
					// I'll continue dig this function when I got home
					ThreadHandle,
					(void*)addr_RtlDispatchAPC,
					(PPS_APC_ROUTINE)LoadLibraryAPtr,
					RemoteLibraryAddress,
					stack_param_tester);
				break;
			}
			Sleep(500);
		}

		if (!NT_SUCCESS(Status)) {
			printf("NtQueueApcThread Failed: 0x%08X\n", Status);
			exit(-1);
		}
	}
						break;
	case ApcTypeSpecial: {
		USER_APC_OPTION UserApcOption;
		UserApcOption.UserApcFlags = QueueUserApcFlagsSpecialUserApc;

		Status = NtQueueApcThreadEx(
			ThreadHandle,
			UserApcOption,
			(PPS_APC_ROUTINE)LoadLibraryAPtr,
			RemoteLibraryAddress,
			NULL,
			NULL
		);

		if (!NT_SUCCESS(Status)) {
			printf("NtQueueApcThreadEx Failed: 0x%08X\n", Status);
			exit(-1);
		}
	}
						 break;
	default:
		break;
	}

	return 0;
}