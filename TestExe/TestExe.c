// TestExe.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include "windows.h"
#include "stdio.h"
int main()
{
	LoadLibrary(L"C:\\Users\\lw\\source\\repos\\liwei1024\\WC\\Debug\\Loader.dll");
	/*char buffer[200] = { 0 };
	sprintf_s(buffer,sizeof(buffer),"MemoryLoad %d\n",123);
	printf(buffer);
	OutputDebugStringA(buffer);*/
	system("pause");
}

