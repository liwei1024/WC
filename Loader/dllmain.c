// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "MmVisor.h"

HANDLE hThread;
HMODULE Module;
TCHAR szPath[MAX_PATH] = { 0 };
CHAR buffer[200] = { 0 };

typedef BOOL(*Start)(HMODULE hModule,TCHAR* LoaderPath);

Start _Start;

DWORD WINAPI UnloadProc(HMODULE hModule,PVOID param)
{
	FreeLibraryAndExitThread(hModule, 0);
	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		
		sprintf_s(buffer, sizeof(buffer), "MemoryLoad %d\n", 123);
		OutputDebugStringA(buffer);

		Module = MmLoadLibrary(TEXT("C:\\Users\\lw\\source\\repos\\WC\\Release\\DxfAssistant.dll"));

		_Start = (Start)MmGetProcAddress(Module,"Start");

		GetModuleFileName(hModule, szPath,sizeof(szPath));

		OutputDebugString(szPath);

		if (_Start(hModule,szPath) == TRUE) {
			Sleep(1000);
			hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UnloadProc, NULL, 0, NULL);
			WaitForSingleObject(hThread, 0xFF);
			CloseHandle(hThread);
		}
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

