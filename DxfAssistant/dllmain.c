// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
CHAR buffer[200] = { 0 };
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		/*sprintf_s(buffer, sizeof(buffer), "MemoryLoad %d\n", 123);
		OutputDebugStringA(buffer);*/
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

