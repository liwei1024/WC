// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "MmVisor.h"

HANDLE hThread;
HMODULE Module;
HMODULE g_hModule;
TCHAR szPath[MAX_PATH] = { 0 };
CHAR buffer[200] = { 0 };

typedef VOID(*Start)(HMODULE hModule,TCHAR* LoaderPath);

Start _Start;

// 导出函数
#pragma comment(linker, "/EXPORT:DsRoleFreeMemory=_JMP_DsRoleFreeMemory,@1")
#pragma comment(linker, "/EXPORT:DsRoleGetPrimaryDomainInformation=_JMP_DsRoleGetPrimaryDomainInformation,@2")
// 宏定义
#define EXTERNC extern "C"
#define NAKED __declspec(naked)
#define EXPORT __declspec(dllexport)
#define ALCPP EXPORT NAKED
#define ALSTD  EXPORT NAKED void __stdcall
#define ALCFAST  EXPORT NAKED void __fastcall
#define ALCDECL  NAKED void __cdecl
//全局变量
HMODULE hDll = NULL;
DWORD dwRetaddress[3];							//存放返回地址
// 内部函数 获取真实函数地址
CHAR szTemp[MAX_PATH] = { 0 };
TCHAR swzTemp[MAX_PATH] = { 0 };
FARPROC WINAPI GetAddress(PCSTR pszProcName)
{
	FARPROC fpAddress;
	fpAddress = GetProcAddress(hDll, pszProcName);
	if (fpAddress == NULL)
	{
		sprintf_s(szTemp, MAX_PATH, "MemoryLoad 无法找到函数 :%s 的地址 ", pszProcName);
		MessageBoxA(NULL, szTemp, "错误", MB_OK);
		ExitProcess(-2);
	}
	//返回真实地址
	return fpAddress;
}

DWORD WINAPI UnloadProc(PVOID param)
{
	//MessageBoxA(NULL, "aaa", "错误", MB_OK);
	FreeLibraryAndExitThread(g_hModule, 0);
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
		
		hDll = LoadLibrary(L"C:\\Windows\\System32\\dsrole.dll");
		if (!hDll)
		{
			OutputDebugStringA("MemoryLoad 获取真实模块失败");
			return FALSE;
		}
		g_hModule = hModule;
		OutputDebugStringA("MemoryLoad 获取真实模块成功");
		swprintf_s(swzTemp, MAX_PATH, L"MemoryLoad g_hModule %x", (DWORD)g_hModule);
		OutputDebugString(swzTemp);
		Module = MmLoadLibrary(TEXT("C:\\Users\\lw\\source\\repos\\liwei1024\\WC\\Debug\\DxfAssistant.dll"));
		swprintf_s(swzTemp, MAX_PATH, L"MemoryLoad Module %x", (DWORD)Module);
		OutputDebugString(swzTemp);
		_Start = (Start)MmGetProcAddress(Module,"Start");

		
		//MessageBoxA(NULL, szTemp, "错误", MB_OK);

		GetModuleFileName(hModule, szPath,sizeof(szPath));

		
		_Start(hModule, szPath);
		//if ( == TRUE) {
		//	/*Sleep(1000);
		//	OutputDebugStringA("MemoryLoad 清理");
		//	hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UnloadProc, NULL, 0, NULL);
		//	WaitForSingleObject(hThread, 0xFF);
		//	CloseHandle(hThread);*/
		//}
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


ALCDECL JMP_DsRoleFreeMemory()
{
	//以下注释经过OD调试得出 编译环境:win10 x64 vs2013， 
			//一般情况下在这里为所欲为   注意堆栈平衡
	GetAddress("DsRoleFreeMemory");
	//此时栈订保持的是返回地址,因为我们前面没有破坏堆栈
	__asm pop dwRetaddress[1]						//弹出来，下面菜可以用call,为什么用call？因为如果用直接jmp的话 想获取执行返回值有点困难
		__asm call eax								//把返回地址入栈，这时候就相当于原来的返回地址被我们call的下一条指令地址入栈，这样真实函数返回后我们重新夺回控制权
		//一般情况下在这里继续为所欲为  注意堆栈平衡
	__asm jmp dword ptr dwRetaddress[1]			//跳回原函数
}

ALCDECL JMP_DsRoleGetPrimaryDomainInformation()
{
	//以下注释经过OD调试得出 编译环境:win10 x64 vs2013， 
			//一般情况下在这里为所欲为   注意堆栈平衡
	GetAddress("DsRoleGetPrimaryDomainInformation");
	//此时栈订保持的是返回地址,因为我们前面没有破坏堆栈
	__asm pop dwRetaddress[2]						//弹出来，下面菜可以用call,为什么用call？因为如果用直接jmp的话 想获取执行返回值有点困难
		__asm call eax								//把返回地址入栈，这时候就相当于原来的返回地址被我们call的下一条指令地址入栈，这样真实函数返回后我们重新夺回控制权
		//一般情况下在这里继续为所欲为  注意堆栈平衡
	__asm jmp dword ptr dwRetaddress[2]			//跳回原函数
}
