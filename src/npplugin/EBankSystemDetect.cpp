#include "EBankSystemDetect.h"
#include "json/json.h"
#include <Windows.h>
#include "CheckAPI.h"

#include "HttpConnect.h"
#include "TimeAPI.h"

std::string utf8_encode(const std::wstring &wstr);


string WTF_GetFireWallInfo()
{
	Json::Value item;

	CSecurityProductList secList;

	SECURITY_PRODUCT product;

	int i = 0;

	//wchar_t wValue[1024] = {0};

	BOOL bFlag = TRUE;

	item["success"] = 0;

	memset(&product, 0, sizeof(SECURITY_PRODUCT));

	unsigned long ulResult = CheckSecurityCenter(SECURITYCENTER_FIREWALL,&secList);

	bFlag = secList.Next(&product);

	for (i = 0; (i < 5) && (ulResult || !bFlag); i++)
	{
		Sleep(500);
		memset(&product, 0, sizeof(SECURITY_PRODUCT));
		ulResult = CheckSecurityCenter(SECURITYCENTER_FIREWALL,&secList);
		bFlag = secList.Next(&product);
	}

	if ( ulResult )
	{
		item["success"] = FALSE;
		item["msg"] = utf8_encode(L"不存在");
		item["sec_level"] = TYPE_SEC_WARNING;
		goto err;
	}
	//bFlag = secList.Next(&product);
	if(bFlag)
	{
		string pszActiveState;

		item["product_type"] = product.ulType == PROVIDER_FIREWALL? utf8_encode(L"防火墙"): utf8_encode(L"杀毒软件");
	
		item["product_name"] = utf8_encode(product.pDisplayName);

		item["company_name"] = utf8_encode(product.pCompanyName);

		switch(product.bActiveState)
		{
		case  ACTIVESTATE_ENABLED:
			pszActiveState = utf8_encode(L"启用");
			item["sec_level"] = TYPE_SEC_NORMAL;
			break;
		case  ACTIVESTATE_DISABLED:
			pszActiveState = utf8_encode(L"关闭");
			item["sec_level"] = TYPE_SEC_WARNING;
			break;
		default:
			pszActiveState = utf8_encode(L"未知");
			item["sec_level"] = TYPE_SEC_EXCEPT;
			break;
		}

		item["active_state"] = pszActiveState;

		item["success"] = TRUE;

	}
	else
	{
		item["success"] = FALSE;
		item["msg"] = utf8_encode(L"不存在");
		item["sec_level"] = TYPE_SEC_WARNING;
	}
err:
	return item.toStyledString();
}

string WTF_GetAntivirusInfo()
{
	Json::Value item;

	CSecurityProductList secList;

	SECURITY_PRODUCT product;
	int  i = 0;

	//wchar_t wValue[1024] = {0};

	BOOL bFlag = TRUE;

	memset(&product, 0, sizeof(SECURITY_PRODUCT));

	unsigned long ulResult = CheckSecurityCenter(SECURITYCENTER_ANTIVIRUS,&secList);

	bFlag = secList.Next(&product);

	for (i = 0; (i < 5) && (ulResult || !bFlag); i++)
	{
		Sleep(500);
		memset(&product, 0, sizeof(SECURITY_PRODUCT));
		ulResult = CheckSecurityCenter(SECURITYCENTER_ANTIVIRUS,&secList);
		bFlag = secList.Next(&product);
	}

	if ( ulResult )
	{
		item["success"] = FALSE;
		item["msg"] = utf8_encode(L"不存在");
		item["sec_level"] = TYPE_SEC_WARNING;
		goto err;
	}
	
	//bFlag = secList.Next(&product);

	if(bFlag)
	{
		string pszActiveState;
		string pszVesionState;

		item["success"] = TRUE;

		item["product_type"] = product.ulType == PROVIDER_FIREWALL? utf8_encode(L"防火墙"): utf8_encode(L"杀毒软件");

		item["product_name"] = utf8_encode(product.pDisplayName);

		item["company_name"] = utf8_encode(product.pCompanyName);

		switch(product.bActiveState)
		{
		case  ACTIVESTATE_ENABLED:
			pszActiveState = utf8_encode(L"启用");
			item["sec_level"] = TYPE_SEC_NORMAL;
			break;
		case  ACTIVESTATE_DISABLED:
			pszActiveState = utf8_encode(L"关闭");
			item["sec_level"] = TYPE_SEC_WARNING;
			break;
		default:
			pszActiveState = utf8_encode(L"未知");
			item["sec_level"] = TYPE_SEC_EXCEPT;
			break;
		}

		switch(product.bVesionState)
		{
		case  VESIONSTATE_NEW:
			pszVesionState =  utf8_encode(L"最新");
			item["sec_level"] = TYPE_SEC_NORMAL;
			break;
		case  VESIONSTATE_OLD:
			pszVesionState =  utf8_encode(L"过时");
			item["sec_level"] = TYPE_SEC_WARNING;
			break;
		default:
			pszVesionState =  utf8_encode(L"未知");
			item["sec_level"] = TYPE_SEC_EXCEPT;
			break;
		}

		item["active_state"] = pszActiveState;
		item["version_state"] = pszVesionState;
		item["version_number"] = product.pVersionNumber;;
	}
	else
	{
		item["success"] = FALSE;
		item["msg"] =  utf8_encode(L"不存在");
		item["sec_level"] = TYPE_SEC_WARNING;
	}

err:
	return item.toStyledString();
}



string WTF_GetTime()
{
	Json::Value item;

	unsigned long long timeNet;
	unsigned long long timeLocal;

	unsigned long ulRet = 0;

	try
	{
		ulRet = GetNetTime_T(&timeNet);

		item["success"] = 0;

		if (!ulRet)
		{
			char szTime[20] = {0};
			string strTime;
			time_t time = timeNet;

			sprintf(szTime, "%d", timeNet);
			API_TimeToStringEX(strTime,time);

			item["net_time"] = szTime;
			item["net_time_str"] = strTime;
		}
		else
		{
			item["msg"] =  utf8_encode(L"获取网络时间失败");
			item["sec_level"] = TYPE_SEC_WARNING;
		}

		GetLocalTime_T(&timeLocal);

		if (1)
		{
			char szTime[20] = {0};
			string strTime;
			time_t time = timeLocal;

			sprintf(szTime, "%d", timeLocal);

			API_TimeToStringEX(strTime,time);

			item["local_time"] = szTime;
			item["local_time_str"] = strTime;
		}

		if (0 == ulRet)
		{
			int time_diff = timeLocal - timeNet;

			if (time_diff < 0)
			{
				time_diff = -time_diff;
			}

			if (time_diff < 10 * 60)
			{
				item["msg"] =  utf8_encode(L"本地时间与服务器时间同步");
				item["success"] = TRUE;
				item["sec_level"] = TYPE_SEC_NORMAL;
			}
			else
			{
				item["msg"] =  utf8_encode(L"本地时间与服务器时间不同步");
				item["success"] = FALSE;
				item["sec_level"] = TYPE_SEC_EXCEPT;
			}
		}
	}
	catch (...)
	{
		item["msg"] =  utf8_encode(L"执行函数失败");
		item["sec_level"] = TYPE_SEC_EXCEPT;
		item["success"] = FALSE;
	}

	return item.toStyledString();
}

#include <iostream>
#include <fstream>

string WTF_GetLocalFileVersion(string strPath)
{
	Json::Value item;

	std::fstream _file;
	_file.open(strPath.c_str(),ios::in);

	if(_file)
	{
		char     szDllver[50];
		DWORD    dwSize=0;
		BYTE     *pbVersionInfo=NULL;                 // 获取文件版本信息
		VS_FIXEDFILEINFO    *pFileInfo=NULL; 
		UINT                puLenFileInfo=0; 
		dwSize=GetFileVersionInfoSizeA(strPath.c_str(), NULL);
		pbVersionInfo=new BYTE[dwSize]; 
		if(!GetFileVersionInfoA(strPath.c_str(),0,dwSize,pbVersionInfo))
		{
			delete[]pbVersionInfo; 
			item["version"] = "null";
		}
		if (!VerQueryValueA(pbVersionInfo,"\\",(LPVOID*)&pFileInfo,&puLenFileInfo)) 
		{ 
			delete[]pbVersionInfo; 
			item["version"] = "null";
		}
		WORD d1 = HIWORD(pFileInfo->dwFileVersionMS);
		WORD d2 = LOWORD(pFileInfo->dwFileVersionMS);
		WORD d3 = HIWORD(pFileInfo->dwFileVersionLS);
		WORD d4 = LOWORD(pFileInfo->dwFileVersionLS);
		sprintf(szDllver,"%d.%d.%d.%d",d1,d2,d3,d4);
		delete[]pbVersionInfo;

		item["version"] = szDllver;

		item["success"] = TRUE;
	}
	else
	{
		item["success"] = FALSE;
		item["msg"] = utf8_encode(L"文件不存在");
	}
	
err:
	
	return item.toStyledString();
}


string WTF_RepairLocalTime()
{
	Json::Value item;

	unsigned long long timeNet;

	unsigned long ulRet = 0;

	item["success"] = false;

	ulRet = GetNetTime_T(&timeNet);

	if (!ulRet)
	{
		ulRet = SetLocalTime_T(timeNet);

		if (ulRet)
		{
			item["msg"] =  utf8_encode(L"同步本地时间失败");
			item["success"] = false;
		}
		else
		{
			item["msg"] =  utf8_encode(L"同步本地时间成功");
			item["success"] = true;

			char szTime[20] = {0};
			string strTime;
			time_t time = timeNet;

			sprintf(szTime, "%d", timeNet);
			API_TimeToStringEX(strTime,time);

			item["time"] = szTime;
			item["time_str"] = strTime;
		}
	}
	else
	{
		item["msg"] =  utf8_encode(L"获取网络时间失败");
		item["sec_level"] = TYPE_SEC_WARNING;
	}

	return item.toStyledString();
}




BOOL ElevateCurrentProcess(string strPath, string strParameters, unsigned int nTimeoutMilliseconds)
{
	// Launch itself as administrator.  
	SHELLEXECUTEINFOA sei = { 0 };
	sei.lpVerb = "runas";
	sei.lpFile = strPath.c_str();
	sei.lpParameters = strParameters.c_str();
	//  sei.hwnd = hWnd;  
	sei.nShow = SW_SHOWNORMAL;
	sei.cbSize = sizeof(SHELLEXECUTEINFO);
	sei.fMask = SEE_MASK_NOCLOSEPROCESS;
	sei.hwnd = NULL;
	sei.lpDirectory = NULL;
	sei.hInstApp = NULL;

	if (!ShellExecuteExA(&sei)) {
		DWORD dwStatus = GetLastError();
		if (dwStatus == ERROR_CANCELLED) {
			return FALSE;
		}
		else if (dwStatus == ERROR_FILE_NOT_FOUND) {
			return FALSE;
		}
		return FALSE;
	}

	if (0 != nTimeoutMilliseconds)
	{
		DWORD res = WaitForSingleObject(sei.hProcess, nTimeoutMilliseconds);

		if (WAIT_OBJECT_0 == res)
		{
			return TRUE;
		}
		else if (WAIT_TIMEOUT == res)
		{
			TerminateProcess(sei.hProcess, 0);
			return FALSE;
		}
		else
		{
			TerminateProcess(sei.hProcess, 0);
			return FALSE;
		}
	}

	return TRUE;

}

unsigned int WTF_InstallApplication(string strAppPath,string strArgs, unsigned int nTimeoutMilliseconds)
{
	char szCmd[256] = {0};

	unsigned int ulRet = -1;

	HANDLE hRead,hWrite;
	SECURITY_ATTRIBUTES sa;
	sa.bInheritHandle = TRUE;
	sa.lpSecurityDescriptor = NULL;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	if(!CreatePipe(&hRead, &hWrite, &sa, 0)){
		return -1;
	}

	PROCESS_INFORMATION processInfo;
	STARTUPINFOA si;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.hStdOutput =  hWrite;
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;

	sprintf(szCmd, "cmd /c \"%s\" %s", strAppPath.c_str(), strArgs.c_str());
	if(!CreateProcessA(NULL, szCmd, NULL, NULL,TRUE,0,NULL,NULL,&si,&processInfo)){
		return -1;
	}

	DWORD res = WaitForSingleObject(processInfo.hProcess,nTimeoutMilliseconds);

	if (WAIT_OBJECT_0 == res)
	{
		ulRet = 0;
	}
	else if (WAIT_TIMEOUT == res)
	{
		TerminateProcess(processInfo.hProcess,0);
	}
	else
	{
		TerminateProcess(processInfo.hProcess,0);
	}

	CloseHandle(processInfo.hProcess);
	CloseHandle(processInfo.hThread);

	return ulRet;
}

string WTF_InstallApp(string strAppPath,string strArgs, unsigned int nTimeoutMilliseconds, int ulFlag)
{
	Json::Value item;
	unsigned long ulRet = 0;
	std::fstream _file;

	item["success"] = FALSE;

	item["timeoutMilliseconds"] = nTimeoutMilliseconds;

	item["application_path"] = strAppPath;

	item["file_path"] = strAppPath;

	item["flag"] = ulFlag;

	_file.open(strAppPath.c_str(),ios::in);

	if(_file)
	{
		//ulRet = WTF_InstallApplication(strAppPath,strArgs, nTimeoutMilliseconds);
		if (!ElevateCurrentProcess(strAppPath, strArgs, nTimeoutMilliseconds))
		{
			item["success"] = FALSE;
			item["msg"] = utf8_encode(L"应用程序未安装成功，请卸载后重新安装客户端");
		}
		else
		{
			item["success"] = TRUE;
			item["msg"] = utf8_encode(L"应用程序安装成功");
		}
	}
	else
	{
		item["success"] = FALSE;
		item["msg"] = utf8_encode(L"应用程序文件不存在，请卸载后重新安装客户端");
	}

	return item.toStyledString();
}


unsigned int WTF_RunApplication(string strAppPath,string strArgs)
{
	char szCmd[256] = {0};

	unsigned int ulRet = -1;

	PROCESS_INFORMATION processInfo;
	STARTUPINFOA si;
	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;

	sprintf(szCmd, "cmd /c \"%s\" %s", strAppPath.c_str(), strArgs.c_str());
	if(!CreateProcessA(NULL, szCmd, NULL, NULL,TRUE,0,NULL,NULL,&si,&processInfo)){
		return -1;
	}

	return 0;
}

string WTF_RunApplication(string strAppPath, string strArgs, int ulFlag)
{
	Json::Value item;
	unsigned long ulRet = 0;
	std::fstream _file;

	item["success"] = FALSE;

	item["application_path"] = strAppPath;

	item["file_path"] = strAppPath;

	item["flag"] = ulFlag;

	_file.open(strAppPath.c_str(),ios::in);

	if(_file)
	{
		//ulRet = WTF_InstallApplication(strAppPath,strArgs, nTimeoutMilliseconds);
		if (!ElevateCurrentProcess(strAppPath, strArgs, 0))
		{
			item["success"] = FALSE;
			item["msg"] = utf8_encode(L"应用程序未启动成功，请卸载后重新安装客户端");
		}
		else
		{
			item["success"] = TRUE;
			item["msg"] = utf8_encode(L"应用程序启动成功");
		}
	}
	else
	{
		item["success"] = FALSE;
		item["msg"] = utf8_encode(L"应用程序文件不存在，请卸载后重新安装客户端");
	}

	return item.toStyledString();
}

#include "msclient_api.h"

string WTF_DetectMACAddress()
{
	Json::Value item;
	unsigned int ulRet = 0;
	item["success"] = FALSE;

	char data_value_macaddress[BUFFER_LEN_1K] = {0}; 
	unsigned int data_len_macaddress = BUFFER_LEN_1K;

	
	ulRet = MSCAPI_ReadHostMACAddress(data_value_macaddress,&data_len_macaddress,0);

	if (ulRet)
	{
		item["success"] = FALSE;
		item["msg"] = utf8_encode(L"异常错误，获取MAC地址失败");
		
	}
	else
	{
		item["success"] = TRUE;
		item["msg"] = utf8_encode(L"获取MAC地址成功");
		item["mac_address"] = data_value_macaddress;
	}
	
	return item.toStyledString();
}

string WTF_DetectLocalIPAddress()
{
	Json::Value item;
	unsigned int ulRet = 0;
	item["success"] = FALSE;

	char data_value_ip[BUFFER_LEN_1K] = {0}; 
	unsigned int data_len_ip = BUFFER_LEN_1K;

#if defined(WIN32)
	WSADATA wsaData;
	int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != 0) {
		fprintf(stderr, "WSAStartup failed with error %d\n", err);
	}
#endif

	ulRet = MSCAPI_ReadHostIPAddress(data_value_ip,&data_len_ip,0);

	if (ulRet)
	{
		item["success"] = FALSE;
		item["msg"] = utf8_encode(L"异常错误，获取IP地址失败");
	}
	else
	{
		item["success"] = TRUE;
		item["msg"] = utf8_encode(L"获取IP地址成功");
		item["ip_address"] = data_value_ip;
	}

	return item.toStyledString();
}

bool getPublicIp(string& ip_remote, string &ip_local);

string WTF_DetectNetworkIPAddress()
{
	Json::Value item;
	unsigned int ulRet = 0;
	item["success"] = FALSE;

	std::string strIP;
	std::string strLocalIP;

#if defined(WIN32)
	WSADATA wsaData;
	int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != 0) {
		fprintf(stderr, "WSAStartup failed with error %d\n", err);
	}
#endif


	if (getPublicIp(strIP, strLocalIP))
	{
		item["success"] = TRUE;
		item["msg"] = utf8_encode(L"获取IP地址成功");
		item["ip_address"] = strIP;
	}
	else
	{
		item["success"] = FALSE;
		item["msg"] = utf8_encode(L"异常错误，获取IP地址失败");
	}

	return item.toStyledString();
}



string WTF_DetectHostAddress()
{
	Json::Value item;
	unsigned int ulRet = 0;
	item["success"] = FALSE;

	std::string strIP;
	std::string strLocalIP;

#if defined(WIN32)
	WSADATA wsaData;
	int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != 0) {
		fprintf(stderr, "WSAStartup failed with error %d\n", err);
	}
#endif


	if (getPublicIp(strIP, strLocalIP))
	{
		STHostAddress *address = NULL;
		unsigned int address_len = 0;
		int i = 0;

		MSCAPI_ReadHostAddress(address, &address_len);

		address = (STHostAddress*)malloc(sizeof(STHostAddress)*address_len);

		MSCAPI_ReadHostAddress(address, &address_len);

		for (i = 0; i < address_len; i++)
		{
			if (0 == strcmp(address[i].szIPAddress, strLocalIP.c_str()))
			{
				break;
			}
		}

		item["success"] = TRUE;
		item["msg"] = utf8_encode(L"获取IP地址成功");
		item["local_ip"] = strLocalIP;
		item["remote_ip"] = strIP;
		item["mac"] = address[i].szMacAddress;
	}
	else
	{
		item["success"] = FALSE;
		item["msg"] = utf8_encode(L"异常错误，获取IP地址失败");
	}

	return item.toStyledString();
}