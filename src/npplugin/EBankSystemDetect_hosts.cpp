#if 0

#include "stdafx.h"
#include "afxcmn.h"
#include "json/json.h"
#include "EBankSystemDetect.h"
#include "FILE_LOG.h"
#include "afxdialogex.h"
#include "WTF_Interface.h"
#include "common.h"

string WTF_CheckHostFile(string strURL)  
{  
	CString strPath; 

	CString strSystem, strWindows;  
	BOOL bFlagExist = FALSE;

	Json::Value item;
	
	char data_value_ip[BUFFER_LEN_1K] = {0};

	::GetSystemDirectory(strSystem.GetBuffer(MAX_PATH), MAX_PATH);  
	::GetWindowsDirectory(strWindows.GetBuffer(32), 32);  

	strPath.Format("%s\\drivers\\etc\\hosts", strSystem);     

	CStdioFile sf;     
	CFileException e;   
	CString strLine, strFile, strReal;
	
	bool bOpen = sf.Open(strPath, CFile::typeText|CFile::modeRead, &e);  

	/*

	if(bOpen)    
	{         
		while(sf.ReadString(strLine) != NULL)    
		{
			strFile += strLine;  
			strFile += "\r\n";    
			if(strLine.Trim().GetLength() == 0 || strLine.GetAt(0)=='#'|| strLine.GetAt(0)==';')  
			{
				continue;
			}
			else
			{
				strReal += strLine;
				strReal += "\r\n";

				char *strWeb =strLine.GetBuffer(strLine.GetLength());  
				strLine.ReleaseBuffer(); 

				if (const char * pos = strstr(strWeb,strURL.c_str()))
				{
					bFlagExist = TRUE;

					strcpy(data_value_ip,strWeb);

					data_value_ip[pos - strWeb - 1] = 0;
				}
				else
				{

				}

			}

		}  
		sf.Close();  
	}  
	if (bFlagExist)  
	{  
		item["success"] = TRUE;
		item["ip"] = data_value_ip;
		item["url"] = strURL;
		item["sec_level"] = TYPE_SEC_NORMAL;
	}   
	else  
	{  
		item["success"] = FALSE;
		item["sec_level"] = TYPE_SEC_WARNING;
	}  
	*/
	return item.toStyledString();
} 


#else
#include "json/json.h"
#include "EBankSystemDetect.h"
#include "FILE_LOG.h"
#include "WTF_Interface.h"
#include "common.h"
#include <iostream>
#include <fstream>
#include <string>
#include "encode_switch.h"

using namespace std;

string& trim(string &s)   
{  
	if (s.empty())   
	{  
		return s;  
	}  
	s.erase(0,s.find_first_not_of(" "));  
	s.erase(s.find_last_not_of(" ") + 1);  
	return s;  
} 

string WTF_CheckHostFile(string strURL)  
{  
	string strPath; 
	string strLine, strFile, strReal;

	char strSystem[MAX_PATH] = {0};
	char strWindows[MAX_PATH] = {0};  
	BOOL bFlagExist = FALSE;

	Json::Value item;
	
	char data_value_ip[BUFFER_LEN_1K] = {0};

	::GetSystemDirectory(strSystem, MAX_PATH);  
	::GetWindowsDirectory(strWindows, 32);

	strPath += strSystem;

	strPath += "\\drivers\\etc\\hosts";

	std::fstream file2Read;

	file2Read.open(strPath,ios::in);

	if(file2Read)
	{         
		while(getline(file2Read,strLine))
		{
			strFile += strLine;  
			strFile += "\r\n";  

			strLine = trim(strLine);

			if (strLine.size() == 0 || strLine[0] == '#' || strLine[0]==';')
			{
				continue;
			}
			else
			{
				strReal += strLine;
				strReal += "\r\n";

				const char * strWeb = strLine.c_str();

				if (const char * pos = strstr(strWeb,strURL.c_str()))
				{
					bFlagExist = TRUE;

					strcpy(data_value_ip,strLine.c_str());

					data_value_ip[pos - strWeb - 1] = 0;
				}
				else
				{

				}

			}
		}
 
		file2Read.close(); 
	}  
	if (bFlagExist)  
	{  
		item["success"] = TRUE;
		item["ip"] = data_value_ip;
		item["url"] = strURL;
		item["sec_level"] = TYPE_SEC_NORMAL;
	}   
	else  
	{  
		item["success"] = FALSE;
		item["sec_level"] = TYPE_SEC_WARNING;
	}  

	return item.toStyledString();
} 



string WTF_RepairHostFile(string strProName, string strKey)
{
	string strPath; 
	string strLine, strFile, str2After;

	char strSystem[MAX_PATH] = {0};
	char strWindows[MAX_PATH] = {0};  
	BOOL bFlagExist = FALSE;

	Json::Value item;

	char data_value_ip[BUFFER_LEN_1K] = {0};

	::GetSystemDirectory(strSystem, MAX_PATH);  
	::GetWindowsDirectory(strWindows, 32);

	strPath += strSystem;

	strPath += "\\drivers\\etc\\hosts";

	std::fstream file2Read;

	file2Read.open(strPath,ios::in);

	if(file2Read)
	{         
		while(getline(file2Read,strLine))
		{
			strFile += strLine;  
			strFile += "\r\n";  

			strLine = trim(strLine);

			if (strLine.size() == 0 || strLine[0] == '#' || strLine[0]==';')
			{
				str2After += strLine;
				continue;
			}
			else
			{
				const char * strWeb = strLine.c_str();

				if (const char * pos = strstr(strWeb,strKey.c_str()))
				{
					bFlagExist = TRUE;

					strcpy(data_value_ip,strLine.c_str());

					data_value_ip[pos - strWeb - 1] = 0;
				}
				else
				{
					str2After += strLine;
					str2After += "\r\n";
				}

			}
		}

		file2Read.close(); 
	}  

	if (bFlagExist)  // first repair
	{  
		//°ÑÐÂÄÚÈÝÐ´ÈëHOSTÎÄ¼þ
		std::fstream file2Write;

		file2Write.open(strPath,ios::out);

		if (file2Write)
		{
			file2Write.write(str2After.c_str(), str2After.length());
			file2Write.close(); 
		}
	}

	file2Read.open(strPath,ios::in);

	if(file2Read&&bFlagExist)
	{         
		while(getline(file2Read,strLine))
		{
			strFile += strLine;  
			strFile += "\r\n";  

			strLine = trim(strLine);

			if (strLine.size() == 0 || strLine[0] == '#' || strLine[0]==';')
			{
				str2After += strLine;
				continue;
			}
			else
			{
				const char * strWeb = strLine.c_str();

				if (const char * pos = strstr(strWeb,strKey.c_str()))
				{
					bFlagExist = TRUE;

					strcpy(data_value_ip,strLine.c_str());

					data_value_ip[pos - strWeb - 1] = 0;
				}
				else
				{
					str2After += strLine;
					str2After += "\r\n";
				}

			}
		}

		file2Read.close(); 
	}  


	if (bFlagExist)  
	{
		item["success"] = FALSE;
		item["ip"] = data_value_ip;
		item["url"] = strKey;
		item["sec_level"] = TYPE_SEC_NORMAL;
		item["msg"] =  utf8_encode(L"hosts文件异常，请手动修改hosts文件");
		
	}   
	else  
	{  
		item["success"] = TRUE;
		item["url"] = strKey;
		item["sec_level"] = TYPE_SEC_WARNING;
		item["msg"] =  utf8_encode(L"hosts修复成功");
	}  

	return item.toStyledString();
}


#endif