#include <windows.h>  
#include <tlhelp32.h> //进程快照函数头文件  
#include <stdio.h>  
#include<iostream>
#include <fstream>
#include<string>
#include<io.h>
#include <stdio.h>

#include <string>

using namespace std;

HANDLE GetProcessHandle(int nID)//通过进程ID获取进程句柄
{
	return OpenProcess(PROCESS_ALL_ACCESS, FALSE, nID);
}


int KillProcessByName(const char *processName, unsigned int *puiCountProcess)
{
	int i = 0;
	int countProcess = 0;                                 //当前进程数量计数变量  
	PROCESSENTRY32 currentProcess;                      //存放快照进程信息的一个结构体  
	currentProcess.dwSize = sizeof(currentProcess);     //在使用这个结构之前，先设置它的大小  
	HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//给系统内的所有进程拍一个快照  
	char big_chars[1024] = { 0 };
	char big_chars_process[1024] = { 0 };
	PROCESSENTRY32 topProcess = {0};

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
			
			if (topProcess.th32ProcessID == currentProcess.th32ParentProcessID)
			{
				printf("ParentPID=%10u    PID=%10u    PName= %s\n", currentProcess.th32ParentProcessID, currentProcess.th32ProcessID, currentProcess.szExeFile); //遍历进程快照，轮流显示每个进程信息  
				// top is the paraent process
				TerminateProcess(GetProcessHandle(currentProcess.th32ProcessID), 0);
			}
			else if (currentProcess.th32ProcessID == topProcess.th32ParentProcessID)
			{
				printf("ParentPID=%10u    PID=%10u    PName= %s\n", currentProcess.th32ParentProcessID, currentProcess.th32ProcessID, currentProcess.szExeFile); //遍历进程快照，轮流显示每个进程信息  
				// current is the parent process
				TerminateProcess(GetProcessHandle(topProcess.th32ProcessID), 0);
				topProcess = currentProcess;
			}
			else
			{
				// let top = current
				topProcess = currentProcess;
			}

		}

		bMore = Process32Next(hProcess, &currentProcess);    //遍历下一个  
		countProcess++;
	}

	printf("ParentPID=%10u    PID=%10u    PName= %s\n", topProcess.th32ParentProcessID, topProcess.th32ProcessID, topProcess.szExeFile); //遍历进程快照，轮流显示每个进程信息  
	TerminateProcess(GetProcessHandle(topProcess.th32ProcessID), 0);

	CloseHandle(hProcess);  //清除hProcess句柄  
	*puiCountProcess = processNameCount;

	return 0;
}


unsigned int GetPathDbFileIn(char *pDbPath)
{
	char smb_db_path[1024] = { 0 };
	int i = 0;

	//无权限
	//GetModuleFileNameA(GetSelfModuleHandle(), smb_db_path, 1024);
	GetModuleFileNameA(NULL, smb_db_path, 1024);
	for (i = strlen(smb_db_path); i > 0; i--)
	{
		if ('.' == smb_db_path[i])
		{
			smb_db_path[i] = '\0';
			break;
		}
	}

	strcat(smb_db_path, ".conf");
	
	strcpy(pDbPath, smb_db_path);

	return 0;
}

unsigned int WTF_RunApplication(string strAppPath, string strArgs)
{
	char szCmd[256] = { 0 };

	unsigned int ulRet = -1;

	PROCESS_INFORMATION processInfo;
	STARTUPINFOA si;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;

	sprintf(szCmd, "cmd /c \"%s\" %s", strAppPath.c_str(), strArgs.c_str());
	if (!CreateProcessA(NULL, szCmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &processInfo)) {
		return -1;
	}

	return 0;
}

int main(int argc, char * argv[])
{
	HCRYPTPROV	hCryptProv = NULL;
	DWORD dwError;
	char process_name[128] = { 0 };
	char file_in[255] = { 0 };

	GetPathDbFileIn(file_in);

	SetLastError(0);

	std::fstream _file;

	_file.open(file_in, std::ios::binary | std::ios::in);

	if (_file)
	{
		std::ios::pos_type length;
		unsigned int ulAlgType = 0;
		char * pbSqlData = NULL;
		int pos = 0;

		// get length of file:
		_file.seekg(0, std::ios::end);
		length = _file.tellg();
		_file.seekg(0, std::ios::beg);

		pbSqlData = new char[length];

		// read data as a block:
		_file.read(pbSqlData + pos, length);

		memcpy(process_name, pbSqlData, length);

		delete[]pbSqlData;

		_file.close();
	}
	else
	{

	}

	unsigned int i = 0;
	int j = 0;

	printf("process_name=%s\n", process_name);

	while (1)
	{
		WTF_RunApplication(string(process_name)+".exe","");
		Sleep(5000*12*2);
		KillProcessByName(process_name, &i);
		printf("current j=%d i = %d\n", j, i);
		j++;
	}


	return 0; //getchar();
}
