// DxfAssistant.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"


void abc()
{
	while (1)
	{
		OutputDebugString(L"MemoryLoad");
		Sleep(100);
	}
}

__declspec(dllexport) BOOL Start(HMODULE hModule,TCHAR * LoaderPath) {
	int Buffer;
	/*while (TRUE)
	{
		if (ReadProcessMemory(-1, (LPCVOID)hModule, &Buffer, sizeof(Buffer), NULL) == FALSE)
		{

		}
		Sleep(1000);
	}*/

	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)abc, NULL, 0, 0);
	return TRUE;
}