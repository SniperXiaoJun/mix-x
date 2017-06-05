// portAndProcess.cpp : Defines the entry point for the console application.
//http://blog.sina.com.cn/s/blog_9fc415370101cb98.html 
//参考文献如上，但是需要根据自己的编译器进行适当变量修改；
//该测试在window7 64 旗舰P1可以运行 平台VS2015
#pragma once
//#include <iostream.h>
#include <iostream>
#include <stdio.h>
#include <afxsock.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <tchar.h>
using namespace std;

#pragma comment(lib, "WS2_32.lib")


const DWORD ANY_TYSIZE = 256;
const DWORD TYMIB_TCP_STATE_CLOSED = 1;
const DWORD TYMIB_TCP_STATE_LISTEN = 2;
const DWORD TYMIB_TCP_STATE_SYN_SENT = 3;
const DWORD TYMIB_TCP_STATE_SYN_RCVD = 4;
const DWORD TYMIB_TCP_STATE_ESTAB = 5;
const DWORD TYMIB_TCP_STATE_FIN_WAIT1 = 6;
const DWORD TYMIB_TCP_STATE_FIN_WAIT2 = 7;
const DWORD TYMIB_TCP_STATE_CLOSE_WAIT = 8;
const DWORD TYMIB_TCP_STATE_CLOSING = 9;
const DWORD TYMIB_TCP_STATE_LAST_ACK = 10;
const DWORD TYMIB_TCP_STATE_TIME_WAIT = 11;
const DWORD TYMIB_TCP_STATE_DELETE_TCB = 12;

//////////////////////////////////////////////////////////////////////////2016

typedef DWORD(WINAPI *PGetExtendedTcpTable)(

	PVOID  pTcpTable2,
	PDWORD   pdwSize,
	BOOL   bOrder,
	ULONG   ulAf,
	TCP_TABLE_CLASS   TableClass,
	ULONG   Reserved
	);

typedef struct _MIB_TCPROW_OWNER_PIDTY
{
	DWORD       dwState;//连接状态
	DWORD       dwLocalAddr;//本地 IP地址
	DWORD       dwLocalPort;//本地端口
	DWORD       dwRemoteAddr;//远程 IP 地址
	DWORD       dwRemotePort;//远程端口
	DWORD       dwOwningPid;//关联的进程ID
} MIB_TCPROW_OWNER_PIDTY, *PMIB_TCPROW_OWNER_PIDTY;

typedef struct _MIB_TCPTABLE_OWNER_PIDTY
{
	DWORD                dwNumEntries;
	MIB_TCPROW_OWNER_PIDTY tablety[ANY_TYSIZE];
} MIBTCPTABLEOWNERPIDTY, *PMIBTCPTABLEOWNERPID;


//////////////////////////////////////////////////////////////////////////2016

int GetPortFromProcessName(PCHAR ProcessName, vector<std::string> &localAddressVector)
{


	// 获取扩展函数的入口地址 
	HMODULE hModule = ::LoadLibrary("iphlpapi.dll");


	PGetExtendedTcpTable pFuncGetTCPTable;
	pFuncGetTCPTable = (PGetExtendedTcpTable)::GetProcAddress(hModule, "GetExtendedTcpTable");
	if (pFuncGetTCPTable == NULL)
	{
		printf("pFuncGetTCPTable can't not to call, Ex APIs are not present \n ");
		// 说明你应该调用	普通的IP帮助API去获取TCP连接表和UDP监听表
		return 0;
	}

	PMIB_TCPTABLE_OWNER_PID pTcpExTable = new MIB_TCPTABLE_OWNER_PID;
	DWORD dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);


	//PGetExtendedTcpTable pPGetExtendedTcpTable;
	//the first time to get really dwSize
	if (pFuncGetTCPTable(pTcpExTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
		== ERROR_INSUFFICIENT_BUFFER
		)
	{
		printf(" Failed to snapshot TCP endpoints.\n");
		delete pTcpExTable;
		pTcpExTable = (MIB_TCPTABLE_OWNER_PID *)new char[dwSize];//重新分配缓冲区
																 //return -1;
	}
	if (pFuncGetTCPTable(pTcpExTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
	{

		delete pTcpExTable;
		return 0;
	}

	int nNum = (int)pTcpExTable->dwNumEntries; //TCP连接的数目
	for (int i = 0; i < nNum; i++)
	{
		printf("本地地址：%s:%d  远程地址：%s : %d  状态：%d  进程ID : %d\n",
			inet_ntoa(*(in_addr*)& pTcpExTable->table[i].dwLocalAddr), //本地IP 地址
			htons(pTcpExTable->table[i].dwLocalPort), //本地端口
			inet_ntoa(*(in_addr*)& pTcpExTable->table[i].dwRemoteAddr), //远程IP地址
			htons(pTcpExTable->table[i].dwRemotePort), //远程端口
			pTcpExTable->table[i].dwState, //状态
			pTcpExTable->table[i].dwOwningPid
		); //所属进程PID
	}
	delete pTcpExTable;

	return 0;
}
//20160814_02_end


// 将进程ID号（PID）转化为进程名称
PCHAR ProcessPidToName(HANDLE hProcessSnap, DWORD ProcessId, PCHAR ProcessName)
{
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(processEntry);
	// 找不到的话，默认进程名为“???”
	strcpy(ProcessName, "???");
	if (!::Process32First(hProcessSnap, &processEntry))
		return ProcessName;
	do
	{
		if (processEntry.th32ProcessID == ProcessId) // 找到和id相对应的进程名称
		{
			strcpy(ProcessName, processEntry.szExeFile);
			OutputDebugString(processEntry.szExeFile);
			break;
		}
	} while (::Process32Next(hProcessSnap, &processEntry));

	return ProcessName;
}

int main()
{
	vector<std::string> AddressVector;
	GetPortFromProcessName("127.0.0.1", AddressVector);

	//while(1)
	//{
	//	Sleep(10);
	//}

	return 0;
}





