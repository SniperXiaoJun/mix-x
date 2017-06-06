#include <windows.h>  
#include <tlhelp32.h> //进程快照函数头文件  
#include <stdio.h>  


int GetProcessCount(const char *processName, unsigned int *puiCountProcess)
{
	int i = 0;
	int countProcess = 0;                                 //当前进程数量计数变量  
	PROCESSENTRY32 currentProcess;                      //存放快照进程信息的一个结构体  
	currentProcess.dwSize = sizeof(currentProcess);     //在使用这个结构之前，先设置它的大小  
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//给系统内的所有进程拍一个快照  
	char big_chars[1024] = { 0 };
	char big_chars_process[1024] = { 0 };

	unsigned int processNameCount = 0;

	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot()调用失败!\n");
		return -1;
	}

	for (i = 0; i < strlen(processName); i++)
	{
		if (processName[i] >= 'a' && processName[i] <= 'z')
		{
			big_chars_process[i] = processName[i] - 32;
		}
		else
		{
			big_chars_process[i] = processName[i];
		}
	}

	BOOL bMore = Process32First(hProcess, &currentProcess);  //获取第一个进程信息  
	while (bMore)
	{
		memset(big_chars, 0, sizeof(big_chars));

		for (i = 0; i < strlen(currentProcess.szExeFile); i++)
		{
			if (currentProcess.szExeFile[i] >= 'a' && currentProcess.szExeFile[i] <= 'z')
			{
				big_chars[i] = currentProcess.szExeFile[i] - 32;
			}
			else
			{
				big_chars[i] = currentProcess.szExeFile[i];
			}
		}

		if (memcmp(big_chars, big_chars_process, strlen(big_chars_process)) == 0)
		{
			processNameCount++;
			printf("PID=%5u    PName= %s\n", currentProcess.th32ProcessID, currentProcess.szExeFile); //遍历进程快照，轮流显示每个进程信息  
		}


		bMore = Process32Next(hProcess, &currentProcess);    //遍历下一个  
		countProcess++;
	}

	CloseHandle(hProcess);  //清除hProcess句柄  
	*puiCountProcess = processNameCount;

	return 0;
}

int main()
{
	unsigned int i = 0;

	GetProcessCount("AdSafe.exe", &i);

	printf("共有以上%d个进程在运行\n", i);
	system("pause");
	return 0;
}