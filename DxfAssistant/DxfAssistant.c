// DxfAssistant.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"


void abc()
{
	wchar_t buffer[200] = { 0 };
	while (1)
	{
		/*OutputDebugString(L"MemoryLoad");
		
		memset(buffer, 0, sizeof(buffer));
		swprintf_s(buffer, sizeof(buffer), L"MemoryLoad %d\n", 123);
		OutputDebugString(buffer);*/
		FILE *pf;

		Sleep(100);
	}
}

__declspec(dllexport) BOOL Start(HMODULE hModule,TCHAR * LoaderPath) {
	//int Buffer;
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