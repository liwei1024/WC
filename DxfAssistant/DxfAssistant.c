// DxfAssistant.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"

void DbgPrint(LPCWSTR format, ...)
{
	// 此函数输出调试信息到DebugView
	WCHAR buffer[0x1000] = { 0 };
	va_list args;
	va_start(args, format);
	//vswprintf_s(buffer, sizeof(buffer), _countof(buffer), format, args);
	vswscanf(buffer,format, args);
	va_end(args);
	OutputDebugString(buffer);

}

void abc()
{
	WCHAR Buffer[MAX_PATH] = { 0 };
	while (1)
	{
		//DbgPrint(L"MemoryLoad %d", 123);
		wscanf_s(Buffer, L"%d", 1231);
		OutputDebugString(Buffer);
		Sleep(100);
		OutputDebugString(L"MemoryLoad");
		Sleep(100);
	}
}

__declspec(dllexport) BOOL Start(HMODULE hModule,TCHAR * LoaderPath) 
{
	LoadLibrary(L"C:\\Windows\\System32\\dsrole.dll");
	FreeLibrary(hModule);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)abc, NULL, 0, 0);
	return TRUE;
}