#pragma once

HMODULE MmLoadLibrary(LPCTSTR lpFileName);

PVOID MmGetProcAddress(HMODULE hModule, LPCSTR lpProcName);
