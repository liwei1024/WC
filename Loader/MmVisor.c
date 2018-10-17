#include "stdafx.h"
#include <intrin.h>
#include <winternl.h>
#include "stddef.h"
#include "MmVisor.h"

#define RVATOVA(BaseAddress, Offset)\
    (PVOID)((ULONG_PTR)BaseAddress + (ULONG_PTR)Offset)

SIZE_T
MmStrLen(
	CONST CHAR * Str
)
{
	CONST CHAR *Eos = Str;
	while (*Eos++);
	return((INT)(Eos - Str - 1));
}

INT
MmCompareMemory(
	CONST CHAR *Dest,
	CONST CHAR *Src,
	SIZE_T cbData)
{
	if (!cbData) return 0;

	while (--cbData && (*Dest == *Src))
	{
		Dest++;
		Src++;
	}

	return(*Dest - *Src);
}

VOID
MmCopyMemory(
	VOID * Dest,
	CONST VOID * Src,
	SIZE_T Count
)
{
	while (Count--)
	{
		((CHAR*)Dest)[Count] = ((CHAR*)Src)[Count];
	}
}

SIZE_T
MmGetModuleSize(
	HMODULE hModule
)
{
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)RVATOVA(hModule, 0);
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)RVATOVA(hModule, DosHeader->e_lfanew);
	return NtHeader->OptionalHeader.SizeOfImage;
}

PVOID
MmGetProcAddress(
	HMODULE hModule,
	LPCSTR lpProcName
)
{
	if (!hModule)return NULL;

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)RVATOVA(hModule, 0);
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)RVATOVA(hModule, DosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER OptionalHeader = &NtHeader->OptionalHeader;
	DWORD ImageBase = OptionalHeader->ImageBase;

	if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
	{
		PIMAGE_EXPORT_DIRECTORY ExmportDirectory =
			(PIMAGE_EXPORT_DIRECTORY)RVATOVA(hModule,
				OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		LPCSTR Name = (LPCSTR)RVATOVA(hModule, ExmportDirectory->Name);
		DWORD NumberOfFunctions = ExmportDirectory->NumberOfFunctions;
		DWORD NumberOfNames = ExmportDirectory->NumberOfNames;
		DWORD Base = ExmportDirectory->Base;
		PDWORD AddressOfFunctions = (PDWORD)RVATOVA(hModule, ExmportDirectory->AddressOfFunctions);
		PDWORD AddressOfNames = (PDWORD)RVATOVA(hModule, ExmportDirectory->AddressOfNames);
		PUSHORT AddressOfNameOrdinals = (PUSHORT)RVATOVA(hModule, ExmportDirectory->AddressOfNameOrdinals);

		if ((ULONG)lpProcName <= 0xFFFF)
		{
			return RVATOVA(hModule, AddressOfFunctions[(WORD)lpProcName - 1]);
		}
		else
		{
			for (DWORD i = 0; i < NumberOfNames; i++)
			{
				if (!MmCompareMemory(
					(PCHAR)RVATOVA(hModule, AddressOfNames[i]),
					lpProcName,
					MmStrLen(lpProcName)))
				{
					return RVATOVA(hModule, AddressOfFunctions[AddressOfNameOrdinals[i]]);
				}
			}
		}
	}

	return NULL;
}

HMODULE
MmGetModuleHandle(
	LPCSTR lpProcName
)
{
#ifndef _AMD64_
	PNT_TIB nt_tib = (PNT_TIB)__readfsdword(offsetof(NT_TIB, Self));
#else
	PNT_TIB nt_tib = (PVOID)__readgsqword(offsetof(NT_TIB, Self));
#endif // !_AMD64_

	PTEB Teb = (PTEB)nt_tib;
	PPEB Peb = Teb->ProcessEnvironmentBlock;
	PPEB_LDR_DATA Ldr = Peb->Ldr;
	PLIST_ENTRY Dlink = Ldr->InMemoryOrderModuleList.Flink;

	PLDR_DATA_TABLE_ENTRY Ldt = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(
		(PLDR_DATA_TABLE_ENTRY)Dlink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

	PUNICODE_STRING UnicodeString = NULL;

	do
	{
		UnicodeString = &Ldt->FullDllName + 1;
		Ldt = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(
			Dlink->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		Dlink = Dlink->Flink;
	} while (Dlink != Ldr->InMemoryOrderModuleList.Flink && Ldt->DllBase);

	return NULL;
}

VOID
MmFixImportDescriptor(
	HMODULE hModule
)
{
	if (!hModule)return;

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)RVATOVA(hModule, 0);
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)RVATOVA(hModule, DosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER OptionalHeader = &NtHeader->OptionalHeader;

	if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor =
			(PIMAGE_IMPORT_DESCRIPTOR)RVATOVA(hModule,
				OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		PCHAR Name = NULL;
		PIMAGE_THUNK_DATA OriginalFirstThunk = NULL;
		PIMAGE_THUNK_DATA FirstThunk = NULL;
		PIMAGE_IMPORT_BY_NAME ImportByName = NULL;
		DWORD ProcAddress = 0;

		for (DWORD Index = 0; ImportDescriptor[Index].Characteristics; Index++)
		{
			Name = (PCHAR)RVATOVA(hModule, ImportDescriptor[Index].Name);
			OriginalFirstThunk = (PIMAGE_THUNK_DATA)RVATOVA(hModule, ImportDescriptor[Index].OriginalFirstThunk);
			FirstThunk = (PIMAGE_THUNK_DATA)RVATOVA(hModule, ImportDescriptor[Index].FirstThunk);

			if (!GetModuleHandleA(Name))LoadLibraryA(Name);

			for (DWORD i = 0; OriginalFirstThunk[i].u1.Function; i++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(OriginalFirstThunk[i].u1.Ordinal))
				{
					ProcAddress =
						(DWORD)MmGetProcAddress(GetModuleHandleA(Name),
							MAKEINTRESOURCEA(OriginalFirstThunk[i].u1.Ordinal));
				}
				else
				{
					ImportByName = (PIMAGE_IMPORT_BY_NAME)RVATOVA(hModule, OriginalFirstThunk[i].u1.AddressOfData);

					ProcAddress =
						(DWORD)MmGetProcAddress(GetModuleHandleA(Name), ImportByName->Name);
				}

				*(DWORD *)&OriginalFirstThunk[i].u1.Function = ProcAddress;
				*(DWORD *)&FirstThunk[i].u1.Function = ProcAddress;
			}
		}
	}
}

VOID
MmFixBaseRelocation(
	HMODULE hModule
)
{
	if (!hModule)return;

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)RVATOVA(hModule, 0);
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)RVATOVA(hModule, DosHeader->e_lfanew);
	PIMAGE_OPTIONAL_HEADER OptionalHeader = &NtHeader->OptionalHeader;
	DWORD ImageBase = OptionalHeader->ImageBase;

	*(DWORD *)&OptionalHeader->ImageBase = (DWORD)hModule;

	if (OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
	{
		PIMAGE_BASE_RELOCATION Relocation =
			(PIMAGE_BASE_RELOCATION)RVATOVA(hModule,
				OptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		while (Relocation->SizeOfBlock)
		{
			PUCHAR VirtualAddress = (PUCHAR)RVATOVA(hModule, Relocation->VirtualAddress);
			PUSHORT TypeOffset = (PUSHORT)(&Relocation->VirtualAddress + 2);

			for (DWORD i = 0; TypeOffset[i]; i++)
			{
				if (TypeOffset[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
				{
					*(DWORD *)(VirtualAddress + (TypeOffset[i] & 0xfff)) +=
						(DWORD)hModule - ImageBase;
				}
			}

			Relocation = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)Relocation +
				Relocation->SizeOfBlock);
		}
	}
}

HMODULE
MmLoadLibrary(
	LPCTSTR lpFileName
)
{
	HANDLE hFile = CreateFile(
		lpFileName,
		GENERIC_WRITE | GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)return NULL;

	SIZE_T nSize = GetFileSize(hFile, NULL);
	PVOID BaseAddress =
		VirtualAlloc(NULL, nSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	ReadFile(hFile, BaseAddress, nSize, NULL, NULL);

	if (hFile)CloseHandle(hFile);

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)RVATOVA(BaseAddress, 0);
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)RVATOVA(BaseAddress, DosHeader->e_lfanew);
	HMODULE hModule =
		(HMODULE)VirtualAlloc(NULL, NtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	PIMAGE_SECTION_HEADER SectionHeader = IMAGE_FIRST_SECTION(NtHeader);

	for (WORD i = 0; i < NtHeader->FileHeader.NumberOfSections; i++)
	{
		MmCopyMemory(
			RVATOVA(hModule, SectionHeader[i].VirtualAddress),
			RVATOVA(BaseAddress, SectionHeader[i].PointerToRawData),
			SectionHeader[i].Misc.VirtualSize);
	}

	MmCopyMemory(
		hModule,
		BaseAddress,
		(PUCHAR)IMAGE_FIRST_SECTION(NtHeader) - (PUCHAR)BaseAddress);
	DosHeader = (PIMAGE_DOS_HEADER)RVATOVA(hModule, 0);
	NtHeader = (PIMAGE_NT_HEADERS)RVATOVA(hModule, DosHeader->e_lfanew);

	VirtualFree(BaseAddress, NtHeader->OptionalHeader.SizeOfImage, MEM_RELEASE);

	MmFixImportDescriptor(hModule);
	MmFixBaseRelocation(hModule);

	return hModule;
}
//
//int
//main(
//	int argc,
//	char *argv[],
//	char *envp[]
//)
//{
//	HMODULE hModule = MmLoadLibrary(TEXT("MmTest.dll"));
//
//	FARPROC foo6 = MmGetProcAddress(hModule, MAKEINTRESOURCEA(6));
//	foo6();
//
//	foo6 = MmGetProcAddress(hModule, "foo6");
//	foo6();
//
//	return 0;
//}
