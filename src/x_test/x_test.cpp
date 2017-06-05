// portAndProcess.cpp : Defines the entry point for the console application.
//http://blog.sina.com.cn/s/blog_9fc415370101cb98.html 
//�ο��������ϣ�������Ҫ�����Լ��ı����������ʵ������޸ģ�
//�ò�����window7 64 �콢P1�������� ƽ̨VS2015
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
	DWORD       dwState;//����״̬
	DWORD       dwLocalAddr;//���� IP��ַ
	DWORD       dwLocalPort;//���ض˿�
	DWORD       dwRemoteAddr;//Զ�� IP ��ַ
	DWORD       dwRemotePort;//Զ�̶˿�
	DWORD       dwOwningPid;//�����Ľ���ID
} MIB_TCPROW_OWNER_PIDTY, *PMIB_TCPROW_OWNER_PIDTY;

typedef struct _MIB_TCPTABLE_OWNER_PIDTY
{
	DWORD                dwNumEntries;
	MIB_TCPROW_OWNER_PIDTY tablety[ANY_TYSIZE];
} MIBTCPTABLEOWNERPIDTY, *PMIBTCPTABLEOWNERPID;


//////////////////////////////////////////////////////////////////////////2016

int GetPortFromProcessName(PCHAR ProcessName, vector<std::string> &localAddressVector)
{


	// ��ȡ��չ��������ڵ�ַ 
	HMODULE hModule = ::LoadLibrary("iphlpapi.dll");


	PGetExtendedTcpTable pFuncGetTCPTable;
	pFuncGetTCPTable = (PGetExtendedTcpTable)::GetProcAddress(hModule, "GetExtendedTcpTable");
	if (pFuncGetTCPTable == NULL)
	{
		printf("pFuncGetTCPTable can't not to call, Ex APIs are not present \n ");
		// ˵����Ӧ�õ���	��ͨ��IP����APIȥ��ȡTCP���ӱ��UDP������
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
		pTcpExTable = (MIB_TCPTABLE_OWNER_PID *)new char[dwSize];//���·��仺����
																 //return -1;
	}
	if (pFuncGetTCPTable(pTcpExTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
	{

		delete pTcpExTable;
		return 0;
	}

	int nNum = (int)pTcpExTable->dwNumEntries; //TCP���ӵ���Ŀ
	for (int i = 0; i < nNum; i++)
	{
		printf("���ص�ַ��%s:%d  Զ�̵�ַ��%s : %d  ״̬��%d  ����ID : %d\n",
			inet_ntoa(*(in_addr*)& pTcpExTable->table[i].dwLocalAddr), //����IP ��ַ
			htons(pTcpExTable->table[i].dwLocalPort), //���ض˿�
			inet_ntoa(*(in_addr*)& pTcpExTable->table[i].dwRemoteAddr), //Զ��IP��ַ
			htons(pTcpExTable->table[i].dwRemotePort), //Զ�̶˿�
			pTcpExTable->table[i].dwState, //״̬
			pTcpExTable->table[i].dwOwningPid
		); //��������PID
	}
	delete pTcpExTable;

	return 0;
}
//20160814_02_end


// ������ID�ţ�PID��ת��Ϊ��������
PCHAR ProcessPidToName(HANDLE hProcessSnap, DWORD ProcessId, PCHAR ProcessName)
{
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(processEntry);
	// �Ҳ����Ļ���Ĭ�Ͻ�����Ϊ��???��
	strcpy(ProcessName, "???");
	if (!::Process32First(hProcessSnap, &processEntry))
		return ProcessName;
	do
	{
		if (processEntry.th32ProcessID == ProcessId) // �ҵ���id���Ӧ�Ľ�������
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





