// DxfAssistant.cpp : 定义 DLL 应用程序的导出函数。
//

#include <windows.h>
//#include <windowsx.h>
//#include <winternl.h>
#include <stdio.h>

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
	OutputDebugString(L"MemoryLoad");
	WCHAR Buffer[MAX_PATH] = { 0 };
	OutputDebugString(L"MemoryLoad");
	OutputDebugString(L"MemoryLoad");
	while (1)
	{
		//DbgPrint(L"MemoryLoad %d", 123);
		//wscanf_s(Buffer, L"%d", 1231);
		/*memset(Buffer,0, sizeof(Buffer));
		swprintf_s(Buffer,sizeof(Buffer),L"MemoryLoad 1231 %d",123);
		OutputDebugString(Buffer);*/
		//Sleep(100);
		OutputDebugString(L"MemoryLoad");
		Sleep(100);
	}
}

__declspec(dllexport) VOID Start(HMODULE hModule,TCHAR * LoaderPath)
{
	OutputDebugString(L"MemoryLoad 666666");
	LoadLibrary(L"C:\\Windows\\System32\\dsrole.dll");
	FreeLibrary(hModule);
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)abc, NULL, 0, 0);
}