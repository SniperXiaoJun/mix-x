

#include "EBankSystemDetect.h"
#include "json/json.h"
#include <Windows.h>

using namespace std;
#include "common.h"
#include "json/json.h"

#ifdef __cplusplus
extern "C"{
#endif
	/*************************************************************
	* 以下函数是网银检测需要用到的
	**************************************************************/

	/*
	功能名称:	获取站点
	函数名称:	GetTrustfunUrl
	输入参数:	hKey		注册表根键
	uiType URL_TRUST_TYPE
	输出参数:	
	pszUrl		站点内容
	puiUrlLen	站点长度
	返回值:		TRUE：成功
	功能描述:	获取站点
	*/
	BOOL GetTrustfunUrl(HKEY hKey, char *pszUrl, unsigned int *puiUrlLen, unsigned int uiType);

	/*
	功能名称:	检测信任站点
	函数名称:	DetectSilkStreetUrl
	输入参数:	
	输出参数:	
	pszUrl		站点内容
	puiUrlLen	站点长度	
	返回值:		TRUE：成功
	功能描述:	获取站点
	*/
	BOOL DetectSilkStreetUrl(char *pszURL, unsigned int *puiURLLen);

	/*
	功能名称:	是否自动更新
	函数名称:	DetectAutoUpdate
	输入参数:	
	输出参数:	
	返回值:		TRUE：成功
	失败：		错误码
	功能描述:	是否自动更新
	*/
	BOOL DetectAutoUpdate();

	/*
	功能名称:	检测默认浏览器
	函数名称:	DetectDefaultBrowser
	输入参数:	
	输出参数:	pszDefaultBrowser		默认浏览器内容
	puiDefaultBrowserLen	默认浏览器内容长度
	返回值:		
	失败：		
	功能描述:	检测默认浏览器
	*/
	void DetectDefaultBrowser(char * pszDefaultBrowser, unsigned int * puiDefaultBrowserLen);

	/*
	功能名称:	检测系统信息
	函数名称:	DetectDefaultBrowser
	输入参数:	
	输出参数:	
	pszSystemInfo			系统信息内容
	puiSystemInfoLen		系统信息内容长度
	返回值:		
	失败：		
	功能描述:	检测系统信息
	*/
	void DetectSystemInfo(char * pszSystemInfo, unsigned int *puiSystemInfoLen);
	void DetectIESafeType(char * pszIESafeType, unsigned int *puiIESafeTypeLen);
	void RepairAutoUpdate(char * pszErrorInfo, unsigned int * puiErrorInfoLen);
	void RepairSilkStreetUrl(char * pszErrorInfo, unsigned int * puiErrorInfoLen);
	void RepairIESafeType(char * pszErrorInfo, unsigned int * puiErrorInfoLen);
	BOOL RepairVPN(char * pszErrorInfo, unsigned int * puiErrorInfoLen);

	BOOL GetIESafeType(HKEY hKey, DWORD *pdwType);
	BOOL SetTrustfulUrl(HKEY hKey, char *pszUrl, DWORD dwType);

	/*************************************************************
	* 以下函数将来可能会用到（保留函数）
	**************************************************************/

	/*
	功能名称:	检测VPN存在
	函数名称:	DetectVPN
	输入参数:	
	输出参数:	
	返回值:		0：成功
	失败：		错误码
	功能描述:	检测VPN存在
	*/
	int DetectVPN();

	/*
	功能名称:	检测IE版本
	函数名称:	DetectIEVersion
	输入参数:	
	输出参数:	
	返回值:		0：成功
	失败：		错误码
	功能描述:	检测IE版本
	*/
	int DetectIEVersion(char *pszIEVer, unsigned int *uiIEVerLen);
#ifdef __cplusplus
}
#endif





//将wchar_t* 转成char*的实现函数如下：

char *w2c(char *pcstr,const wchar_t *pwstr, size_t len)
{
	int nlength=wcslen(pwstr);
	//获取转换后的长度
	int nbytes = WideCharToMultiByte( 0, // specify the code page used to perform the conversion
		0,         // no special flags to handle unmapped characters
		pwstr,     // wide character string to convert
		nlength,   // the number of wide characters in that string
		NULL,      // no output buffer given, we just want to know how long it needs to be
		0,
		NULL,      // no replacement character given
		NULL );    // we don't want to know if a character didn't make it through the translation
	// make sure the buffer is big enough for this, making it larger if necessary
	if(nbytes>len)   nbytes=len;
	// 通过以上得到的结果，转换unicode 字符为ascii 字符
	WideCharToMultiByte( 0, // specify the code page used to perform the conversion
		0,         // no special flags to handle unmapped characters
		pwstr,   // wide character string to convert
		nlength,   // the number of wide characters in that string
		pcstr, // put the output ascii characters at the end of the buffer
		nbytes,                           // there is at least this much space there
		NULL,      // no replacement character given
		NULL );
	return pcstr ;
}

// Convert a wide Unicode string to an UTF8 string
static std::string utf8_encode(const std::wstring &wstr){
	// when got a empty wstring, vs2010 will break on an asserting: string 
	// substring out of range
	if (wstr.size()==0) return "";
	int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
	std::string strTo( size_needed, 0 );
	WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
	return strTo;
}

// Convert an UTF8 string to a wide Unicode String
static std::wstring utf8_decode(const std::string &str){
	if (str.size()==0) return L"";
	int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
	std::wstring wstrTo( size_needed, 0 );
	MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
	return wstrTo;
}


//*****************************************************************************/
//* 获取站点                                                         
//* DWORD dwType 2--受信任站点   4--受限制站点                            
//*****************************************************************************/
BOOL GetTrustfunUrl(HKEY hKey, char *pszUrl, unsigned int *puiUrlLen, unsigned int uiType)
{
	int rc = 0;
	int rc2 = 0;
	int rc3 = 0;
	int index = 0;
	int subIndex = 0;
	int protocolIndex = 0;
	HKEY hkResult;
	HKEY hkSubKey;
	HKEY hkHost;
	char szKeyName[MAX_PATH] = {0};
	char szHost[MAX_PATH] = {0};
	char szTemp[MAX_PATH] = {0};
	char szProtocol[MAX_PATH] = {0};
	//char szUrlTmp[MAX_PATH] = {0};
	DWORD dwProtocol = 0;
	DWORD dwKeys = 0;
	DWORD dwData = 0;
	DWORD dwLen = sizeof(DWORD);
	DWORD dwUrlTmpLen = 0;			//用于保存可信URL长度

	if(puiUrlLen == NULL)
	{
		return FALSE;
	}
	if(pszUrl != NULL)
	{
		*pszUrl = 0;
	}

	//获取域名形式站点
	rc = RegCreateKeyA(hKey, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains", &hkResult);
	while (RegEnumKeyA(hkResult, index, szKeyName, MAX_PATH) == ERROR_SUCCESS)
	{
		if (RegOpenKeyA(hkResult, szKeyName, &hkSubKey) == ERROR_SUCCESS)
		{
			rc = RegQueryInfoKey(hkSubKey, NULL, NULL, NULL, &dwKeys, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
			//如果该项下没有子项，即没有主机名，表示为 *.xx.xxx
			if (1)
			{
				protocolIndex = 0;
				dwProtocol = sizeof(szProtocol);
				dwLen = sizeof(DWORD);
				while (RegEnumValueA(hkSubKey, protocolIndex, szProtocol, &dwProtocol, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
				{  
					RegQueryValueExA(hkSubKey, szProtocol, NULL, NULL, (LPBYTE)&dwData, &dwLen);
					if (dwData == uiType)
					{    
						if (strcmp(szProtocol, "*") == 0)
						{
							sprintf_s(szTemp, "*.%s", szKeyName);
						}
						else
						{
							sprintf_s(szTemp, "%s://*.%s", szProtocol, szKeyName);
						}                         

						if(pszUrl != NULL)
						{
							strcat_s(pszUrl, *puiUrlLen, szTemp);
							strcat_s(pszUrl, *puiUrlLen, ",");
							dwUrlTmpLen += strlen(szTemp) + 1;
						}
						else
						{
							dwUrlTmpLen += strlen(szTemp) + 1;
						}

						memset(szTemp, 0, MAX_PATH);
						//if (strlen(pszUrl) > MAX_GETURL_LEN)		//此处做了长度限制，可根据需要自行修改
						//{
						//    RegCloseKey(hkHost);
						//    RegCloseKey(hkSubKey);
						//    RegCloseKey(hkResult);
						//    hkHost = NULL;
						//    hkSubKey = NULL;
						//    hkResult = NULL;
						//    *strrchr(pszUrl, ',') = '\0';
						//    return TRUE;
						//}

						dwProtocol = sizeof(szProtocol);
						dwLen = sizeof(DWORD);

					}
					protocolIndex ++;
					memset(szProtocol, 0, MAX_PATH);
				} 
			}
			//else
			if (dwKeys > 0)
			{
				subIndex = 0;
				while (RegEnumKeyA(hkSubKey, subIndex, szHost, MAX_PATH) == ERROR_SUCCESS) 
				{    
					if (RegOpenKeyA(hkSubKey, szHost, &hkHost) == ERROR_SUCCESS)
					{    
						dwProtocol = sizeof(szProtocol);
						dwLen = sizeof(DWORD);
						protocolIndex = 0;
						while (RegEnumValueA(hkHost, protocolIndex, szProtocol, &dwProtocol, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
						{                                        
							RegQueryValueExA(hkHost, szProtocol, NULL, NULL, (LPBYTE)&dwData, &dwLen);
							if (dwData == uiType)
							{    
								if (strcmp(szProtocol, "*") == 0)
								{
									sprintf_s(szTemp, "%s.%s", szHost, szKeyName);
								}
								else
								{
									sprintf_s(szTemp, "%s://%s.%s", szProtocol, szHost, szKeyName);
								}                              

								if(pszUrl != NULL)
								{
									strcat_s(pszUrl, *puiUrlLen, szTemp);
									strcat_s(pszUrl, *puiUrlLen, ",");
									dwUrlTmpLen += strlen(szTemp) + 1;
								}
								else
								{
									dwUrlTmpLen += strlen(szTemp) + 1;
								}

								memset(szTemp, 0, MAX_PATH);
								//if (strlen(pszUrl) > MAX_GETURL_LEN)		//此处做了长度限制，可根据需要自行修改
								//{
								//    RegCloseKey(hkHost);
								//    RegCloseKey(hkSubKey);
								//    RegCloseKey(hkResult);
								//    hkHost = NULL;
								//    hkSubKey = NULL;
								//    hkResult = NULL;
								//    *strrchr(pszUrl, ',') = '\0';
								//    return TRUE;
								//}
							}
							protocolIndex ++;
							memset(szProtocol, 0, MAX_PATH);

							dwProtocol = sizeof(szProtocol);
							dwLen = sizeof(DWORD);
						} 
						RegCloseKey(hkHost);
						hkHost = NULL;
					}
					subIndex ++;
					memset(szHost, 0, MAX_PATH);
				} 
			}
			RegCloseKey(hkSubKey);
			hkSubKey = NULL;
		}
		index ++;
		memset(szKeyName, 0, MAX_PATH);
	} 
	RegCloseKey(hkResult);
	hkResult = NULL;

	//获取IP形式站点
	rc = RegCreateKeyA(hKey, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Ranges", &hkResult);
	index = 0;
	while (RegEnumKeyA(hkResult, index, szKeyName, MAX_PATH) == ERROR_SUCCESS)
	{
		if (RegOpenKeyA(hkResult, szKeyName, &hkSubKey) == ERROR_SUCCESS)
		{
			DWORD dwHost = MAX_PATH;
			RegQueryValueExA(hkSubKey, ":Range", NULL, NULL, (LPBYTE)szHost, &dwHost);
			subIndex = 0;
			dwProtocol = sizeof(szProtocol);
			while (RegEnumValueA(hkSubKey, subIndex, szProtocol, &dwProtocol, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
			{
				if (strcmp(szProtocol, ":Range") != 0)
				{
					RegQueryValueExA(hkSubKey, szProtocol, NULL, NULL, (LPBYTE)&dwData, &dwLen);
					if (dwData == uiType)
					{
						if (strcmp(szProtocol, "*") == 0)
						{
							sprintf_s(szTemp, "%s", szHost);
						}
						else
						{                                            
							sprintf_s(szTemp, "%s://%s", szProtocol, szHost);
						}

						if(pszUrl != NULL)
						{
							strcat_s(pszUrl, *puiUrlLen, szTemp);
							strcat_s(pszUrl, *puiUrlLen, ",");
							dwUrlTmpLen += strlen(szTemp) + 1;
						}
						else
						{
							dwUrlTmpLen += strlen(szTemp) + 1;
						}

					}                    
					memset(szTemp, 0, MAX_PATH);
					//if (strlen(pszUrl) > MAX_GETURL_LEN)		//此处做了长度限制，可根据需要自行修改
					//{
					//    RegCloseKey(hkSubKey);
					//    RegCloseKey(hkResult);
					//     hkSubKey = NULL;
					//     hkResult = NULL;
					//     *strrchr(pszUrl, ',') = '\0';
					//     return TRUE;
					// }
				}
				subIndex++;
				memset(szProtocol, 0, MAX_PATH);
			}
			RegCloseKey(hkSubKey);
			hkSubKey = NULL;
		}
		index ++;
		memset(szKeyName, 0, MAX_PATH);
	}
	RegCloseKey(hkResult);
	hkResult = NULL;

	dwUrlTmpLen++;		//最后有字符串结束符+1

	if(pszUrl != NULL)
	{
		if(strrchr(pszUrl, ',') != NULL)
		{
			*strrchr(pszUrl, ',') = '\0';
		}
	}
	else
	{
		*puiUrlLen = dwUrlTmpLen;
	}
	return TRUE;
}


string WTF_GetTrustUrl(bool bTrust)
{
	BOOL bFlag = FALSE;

	Json::Value item;

	char * szData = NULL;

	unsigned int trustType = bTrust? URL_TRUST_TYPE_YES : URL_TRUST_TYPE_NO;

	unsigned int dataLen = BUFFER_LEN_1K;

	szData = (char *)malloc(BUFFER_LEN_1K);

	memset(szData, 0, dataLen);

	bFlag = GetTrustfunUrl(HKEY_CURRENT_USER, szData, &dataLen, trustType);

	if (bFlag)
	{
		item["success"] = TRUE;
		item["url"] = szData;
		item["sec_level"] = TYPE_SEC_NORMAL;
	}
	else
	{
		item["success"] = FALSE;
		item["sec_level"] = TYPE_SEC_WARNING;
	}


err:
	if(szData)
	{
		free(szData);
	}

	return item.toStyledString();
}

BOOL GetNtVersionNumbers(DWORD&dwMajorVer, DWORD& dwMinorVer,DWORD& dwBuildNumber)
{
	BOOL bRet= FALSE;
	HMODULE hModNtdll= NULL;
	if (hModNtdll= ::LoadLibraryA("ntdll.dll"))
	{
		typedef void (WINAPI *pfRTLGETNTVERSIONNUMBERS)(DWORD*,DWORD*, DWORD*);
		pfRTLGETNTVERSIONNUMBERS pfRtlGetNtVersionNumbers;
		pfRtlGetNtVersionNumbers = (pfRTLGETNTVERSIONNUMBERS)::GetProcAddress(hModNtdll, "RtlGetNtVersionNumbers");
		if (pfRtlGetNtVersionNumbers)
		{
			pfRtlGetNtVersionNumbers(&dwMajorVer, &dwMinorVer,&dwBuildNumber);
			dwBuildNumber&= 0x0ffff;
			bRet = TRUE;
		}

		::FreeLibrary(hModNtdll);
		hModNtdll = NULL;
	}

	return bRet;
}

bool GetUserSystemInfo(wstring & output){
	SYSTEM_INFO si;
	OSVERSIONINFOEX osvi;
	DWORD dwType; 

	ZeroMemory(&si, sizeof(SYSTEM_INFO));
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX)); 
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

	BOOL bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO*) &osvi); 
	if(bOsVersionInfoEx == 0)
		return false; // Call GetNativeSystemInfo if supported or GetSystemInfo otherwise.

	PGNSI pGNSI = (PGNSI) GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
	if(NULL != pGNSI)
		pGNSI(&si);
	else 
		GetSystemInfo(&si); // Check for unsupported OS

	if(TRUE == GetNtVersionNumbers(osvi.dwMajorVersion,osvi.dwMinorVersion,osvi.dwBuildNumber))
	{
		//
	}

	// 忽略早期版本
	if (VER_PLATFORM_WIN32_NT != osvi.dwPlatformId || osvi.dwMajorVersion <= 4 ) {
		return false;
	} 

	output.clear();
	output.append(L"Microsoft ");

	// Test for the specific product. 
	if (osvi.dwMajorVersion == 10)
	{
		output += L"Windows 10 ";
	}
	else if ( osvi.dwMajorVersion == 6 ){

		if( osvi.dwMinorVersion == 0 ){
			if( osvi.wProductType == VER_NT_WORKSTATION )
				output += L"Windows Vista ";
			else output += L"Windows Server 2008 ";
		}  
		else if ( osvi.dwMinorVersion == 1 ){
			if( osvi.wProductType == VER_NT_WORKSTATION )
				output += L"Windows 7 ";
			else output += L"Windows Server 2008 R2 ";
		}  
		else if (osvi.dwMinorVersion == 2){
			if (osvi.wProductType == VER_NT_WORKSTATION)
				output += L"Windows 8 ";
			else
				output += L"Windows Server 2012 ";
		}
		else if (osvi.dwMinorVersion == 3){
			if (osvi.wProductType == VER_NT_WORKSTATION)
				output += L"Windows 8.1 ";
			else
				output += L"Windows Server 2012 R2 ";
		}
	} 

	PGPI pGPI = (PGPI) GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetProductInfo");
	if (pGPI)
	{
		pGPI( osvi.dwMajorVersion, osvi.dwMinorVersion, 0, 0, &dwType);  
	} 

	switch( dwType ){
	case PRODUCT_ULTIMATE:
		output += L"Ultimate Edition";
		break;
	case PRODUCT_PROFESSIONAL:
		output += L"Professional";
		break;
	case PRODUCT_HOME_PREMIUM:
		output += L"Home Premium Edition";
		break;
	case PRODUCT_HOME_BASIC:
		output += L"Home Basic Edition";
		break;
	case PRODUCT_ENTERPRISE:
		output += L"Enterprise Edition";
		break;
	case PRODUCT_BUSINESS:
		output += L"Business Edition";
		break;
	case PRODUCT_STARTER:
		output += L"Starter Edition";
		break;
	case PRODUCT_CLUSTER_SERVER:
		output += L"Cluster Server Edition";
		break;
	case PRODUCT_DATACENTER_SERVER:
		output += L"Datacenter Edition";
		break;
	case PRODUCT_DATACENTER_SERVER_CORE:
		output += L"Datacenter Edition (core installation)";
		break;
	case PRODUCT_ENTERPRISE_SERVER:
		output += L"Enterprise Edition";
		break;
	case PRODUCT_ENTERPRISE_SERVER_CORE:
		output += L"Enterprise Edition (core installation)";
		break;
	case PRODUCT_ENTERPRISE_SERVER_IA64:
		output += L"Enterprise Edition for Itanium-based Systems";
		break;
	case PRODUCT_SMALLBUSINESS_SERVER:
		output += L"Small Business Server";
		break;
	case PRODUCT_SMALLBUSINESS_SERVER_PREMIUM:
		output += L"Small Business Server Premium Edition";
		break;
	case PRODUCT_STANDARD_SERVER:
		output += L"Standard Edition";
		break;
	case PRODUCT_STANDARD_SERVER_CORE:
		output += L"Standard Edition (core installation)";
		break;
	case PRODUCT_WEB_SERVER:
		output += L"Web Server Edition";
		break;
	}

	if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2 ){
		if( GetSystemMetrics(SM_SERVERR2) )
			output += L"Windows Server 2003 R2, ";
		else if ( osvi.wSuiteMask & VER_SUITE_STORAGE_SERVER )
			output += L"Windows Storage Server 2003";
		else if ( osvi.wSuiteMask & VER_SUITE_WH_SERVER )
			output += L"Windows Home Server";
		else if( osvi.wProductType == VER_NT_WORKSTATION &&
			si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64){
				output += L"Windows XP Professional x64 Edition";
		} else output += L"Windows Server 2003, ";

		// Test for the server type.
		if ( osvi.wProductType != VER_NT_WORKSTATION ){
			if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_IA64 ){
				if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
					output += L"Datacenter Edition for Itanium-based Systems";
				else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
					output += L"Enterprise Edition for Itanium-based Systems";
			}   
			else if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 ){
				if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
					output += L"Datacenter x64 Edition";
				else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
					output += L"Enterprise x64 Edition";
				else 
					output += L"Standard x64 Edition";
			}   
			else {
				if ( osvi.wSuiteMask & VER_SUITE_COMPUTE_SERVER )
					output += L"Compute Cluster Edition";
				else if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
					output += L"Datacenter Edition";
				else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
					output += L"Enterprise Edition";
				else if ( osvi.wSuiteMask & VER_SUITE_BLADE )
					output += L"Web Edition";
				else 
					output += L"Standard Edition";
			}
		}
	} 

	if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1 ){
		output += L"Windows XP ";
		if( osvi.wSuiteMask & VER_SUITE_PERSONAL )
			output += L"Home Edition";
		else 
			output += L"Professional";
	} 

	if ( osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0 ){
		output += L"Windows 2000 ";
		if ( osvi.wProductType == VER_NT_WORKSTATION ){
			output += L"Professional";
		}
		else {
			if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
				output += L"Datacenter Server";
			else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
				output += L"Advanced Server";
			else 
				output += L"Server";
		}
	}

	// Include service pack (if any) and build number. 
	if(wcslen(osvi.szCSDVersion) > 0) {
		output += osvi.szCSDVersion;
	}
	output += L" (build ";

	{
		wchar_t dataBuildNumber[BUFFER_LEN_1K]  = {0};

		wsprintf(dataBuildNumber, L"%d", osvi.dwBuildNumber);

		output += dataBuildNumber;
	}

	output += L")";

	// 32位，64位
	if ( osvi.dwMajorVersion >= 6 ) {
		if ( si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64 )
			output += L", 64-bit";
		else if (si.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_INTEL )
			output += L", 32-bit";
	} 

	return true; 
}

string WTF_GetSystemInfo()
{
	BOOL bFlag = FALSE;

	Json::Value item;

	wstring strData;

	bFlag = GetUserSystemInfo(strData);

	if (bFlag)
	{
		item["success"] = TRUE;
		item["sysinfo"] = utf8_encode(strData);
		item["sec_level"] = TYPE_SEC_NORMAL;
	}
	else
	{
		item["success"] = FALSE;
		item["sec_level"] = TYPE_SEC_WARNING;
	}


err:

	return item.toStyledString();
}

#include <string>
#include <sstream>
#include <fstream>
#include <vector>

#include <Windows.h>
#include "comdef.h"
// windows update agent
#include <wuerror.h>
#include "Wuapi.h"
#include "json/json.h"
#include "registry.h"
#include <ATLComTime.h>

string WTF_CheckSystemUpdateState(){
	// 定义变量
	IUpdateSession* session = NULL;
	string msg;
	Json::Value items;
	Json::Value itemAll;

	// 初始化
	HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr)){
		msg="COM Initialization failed!";
		goto err;
	}

	// 创建 session 实例
	hr = CoCreateInstance(CLSID_UpdateSession, NULL, CLSCTX_INPROC_SERVER, IID_IUpdateSession, (LPVOID*)&session);
	if( session==NULL || FAILED(hr) ) {
		msg = "Creating session failed!";
		goto err;
	}

	IUpdateSearcher* searcher = NULL;
	ISearchResult* results = NULL;

	// 创建 searcher
	hr = session->CreateUpdateSearcher(&searcher);
	if( FAILED(hr) || searcher==NULL ){
		goto err;
	}

	// 定义搜索条件
	BSTR criteria = SysAllocString(L"IsInstalled=0 and Type='Software' and IsHidden=0");

	// 开始搜索, 结果放入 result
	msg="Searching updates...";
	hr = searcher->Search(criteria, &results); 

	if( FAILED(hr) ){
		msg="Searching failed!";
		goto err;
	}

	// 补丁列表
	IUpdateCollection *updateList;
	results->get_Updates(&updateList);

	// 补丁个数
	LONG updateCount;
	updateList->get_Count(&updateCount);

	if (updateCount == 0){
		msg="No updates found";
		goto err;
	}

	for( LONG i = 0; i < updateCount; i++ ){
		Json::Value item;

		// 补丁指针
		IUpdate* updateItem;
		updateList->get_Item(i, &updateItem);

		// 补丁名
		BSTR bstrUpdateName;
		updateItem->get_Title(&bstrUpdateName);

		// IUpdateIdentity 
		IUpdateIdentity* uId;
		updateItem->get_Identity(&uId);
		BSTR bstrUId;
		uId->get_UpdateID(&bstrUId);

		// 发布时间
		std::wostringstream ossDate;
		DATE retdate;
		updateItem->get_LastDeploymentChangeTime(&retdate);
		COleDateTime odt;
		odt.m_dt=retdate;
		ossDate << (LPCTSTR)odt.Format(_T("%A, %B %d, %Y"));

		// 描述
		BSTR bstrDescription;
		updateItem->get_Description(&bstrDescription);

		// 级别
		DownloadPriority priority;
		updateItem->get_DownloadPriority(&priority);

		// KBArticleIDs
		std::wostringstream ossKBArticleIDs;
		IStringCollection* kbIds;
		updateItem->get_KBArticleIDs(&kbIds);
		LONG kbItemCount;
		kbIds->get_Count(&kbItemCount);
		ossKBArticleIDs<< L"个数" << kbItemCount << L"<br/>";
		for(LONG kbIdx=0; kbIdx<kbItemCount; kbIdx++){
			BSTR bstrKbItem;
			kbIds->get_Item(kbIdx, &bstrKbItem);
			ossKBArticleIDs << L"更新包情况：KB" << bstrKbItem << L" ";
		}

		//notifyUpdate( std::wstring(bstrUId), std::wstring(bstrUpdateName), ossDate.str(), ossKBArticleIDs.str(),
		//	std::wstring(bstrDescription), priority);

		item["bstrUId"] = utf8_encode( std::wstring(bstrUId));
		item["bstrUpdateName"] = utf8_encode( std::wstring(bstrUpdateName));
		item["ossDate"] = utf8_encode( std::wstring(ossDate.str()));
		item["ossKBArticleIDs"] = utf8_encode( std::wstring(ossKBArticleIDs.str()));
		item["bstrDescription"] = utf8_encode( std::wstring(bstrDescription));
		item["priority"] = priority;

		items.append(item);
	}

	searcher->Release();

	msg="Searching finished!";

err:
	itemAll["items"] = items;
	itemAll["msg"] = msg;

	return itemAll.toStyledString();
}

BOOL SetTrustfulUrl(HKEY hKey, char *pszUrl, DWORD dwType){
	HKEY hkResult;
	int rc = 0;
	char *p = NULL;
	char szProtocol[MAX_PATH] = {0};
	char szData[MAX_PATH] = {0};
	char szTemp[MAX_PATH] = {0};
	char szRegPath[MAX_PATH] = {0};

	strcpy_s(szTemp, pszUrl);

	//获取协议
	p = strchr(szTemp, ':');
	if (p != NULL)
	{
		*p = '\0';
		strcpy_s(szProtocol, szTemp);
		p += 3;
		strcpy_s(szTemp, p);
	}
	else
	{
		strcpy_s(szProtocol, "*");
	}

	//去除多余的url
	p = strrchr(szTemp, '/');
	if (p != NULL)
	{
		*p = '\0';
	}

	p = strrchr(szTemp, '.');
	if (p == NULL)
	{
		sprintf_s(szRegPath, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%s", szTemp);
	} 
	else
	{
		char szTempStr[MAX_PATH] = {0};
		strcpy_s(szTempStr, p);
		*p = '\0';
		p = strrchr(szTemp, '.');
		if (p == NULL)
		{
			sprintf_s(szRegPath, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%s%s", szTemp, szTempStr);
		}
		else
		{
			*p = '\0';
			p++;
			sprintf_s(szRegPath, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\ZoneMap\\Domains\\%s%s\\%s", p, szTempStr, szTemp);
		}
	}
	rc = RegCreateKeyA(hKey, szRegPath, &hkResult);
	RegSetValueExA(hkResult, szProtocol, NULL, REG_DWORD, (BYTE*)&dwType, sizeof(DWORD));
	RegCloseKey(hkResult);
	hkResult = NULL;
	return TRUE;
}


string WTF_SetTrustUrl(string str_site, bool bTrust)
{
	BOOL bFlag = FALSE;

	Json::Value item;

	DWORD dwType = bTrust? URL_TRUST_TYPE_YES : URL_TRUST_TYPE_NO;

	bFlag = SetTrustfulUrl(HKEY_CURRENT_USER, (char *)str_site.c_str(), dwType);

	if (bFlag)
	{
		item["success"] = TRUE;
		item["url"] = str_site;
		item["sec_level"] = TYPE_SEC_NORMAL;
	}
	else
	{
		item["success"] = FALSE;
		item["sec_level"] = TYPE_SEC_WARNING;
	}

err:

	return item.toStyledString();
}


/*
启动动、停止服务
*/
#include <winsvc.h>

BOOL CStartService(BOOL bStart)
{
	// 打开服务管理对象
	SC_HANDLE hSvc = NULL;
	SC_HANDLE hSC = ::OpenSCManager( NULL,NULL, GENERIC_EXECUTE);
	char * msg = NULL;


	if (hSC == NULL)
	{
		msg =  "open SCManager error";
		goto err;
	}

	// 打开www服务。
	hSvc = ::OpenServiceA( hSC, "W3SVC",SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP);

	if(hSvc == NULL)
	{
		msg =  "Open www error";
		CloseServiceHandle( hSC);

		goto err;
	}
	// 获得服务的状态
	SERVICE_STATUS status;
	if( ::QueryServiceStatus( hSvc, &status) == FALSE)
	{
		msg = "Get Service state error";
		::CloseServiceHandle( hSvc);
		::CloseServiceHandle( hSC);

		goto err;
	}
	//如果处于停止状态则启动服务，否则停止服务。
	if( status.dwCurrentState == SERVICE_RUNNING)
	{
		// 停止服务
		if( ::ControlService( hSvc,SERVICE_CONTROL_STOP, &status) == FALSE)
		{
			msg =  "stop service error";
			::CloseServiceHandle( hSvc);
			::CloseServiceHandle( hSC);
			goto err;
		}
		// 等待服务停止
		while( ::QueryServiceStatus( hSvc, &status) == TRUE)
		{
			::Sleep( status.dwWaitHint);
			if( status.dwCurrentState == SERVICE_STOPPED)
			{
				msg ="stop success";
				::CloseServiceHandle( hSvc);
				::CloseServiceHandle( hSC);

				return TRUE;
			}
		}
	}
	else if( status.dwCurrentState == SERVICE_STOPPED)
	{
		// 启动服务
		if( ::StartService( hSvc, NULL, NULL) == FALSE)
		{
			msg ="start service error";
			::CloseServiceHandle( hSvc);
			::CloseServiceHandle( hSC);
			return -1;
		}
		// 等待服务启动
		while( ::QueryServiceStatus( hSvc, &status) == TRUE)
		{
			Sleep( status.dwWaitHint);
			if( status.dwCurrentState == SERVICE_RUNNING)
			{
				msg ="start success";
				::CloseServiceHandle( hSvc);
				::CloseServiceHandle( hSC);
				return TRUE;
			}
		}
	}

	msg ="start error";
	::CloseServiceHandle( hSvc);
	::CloseServiceHandle( hSC);

err:
	return FALSE;
}