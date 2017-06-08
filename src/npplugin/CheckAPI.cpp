#define _WIN32_DCOM

#define _WIN32_WINNT  0x0501

#include <Windows.h>

#include <WinUser.h>

#include <crtdbg.h>
#include <objbase.h>
#include <oleauto.h>
#include <stdio.h>
#include <netfw.h>

 



#include <comdef.h>
#include <Wbemidl.h>



#pragma comment( lib, "ole32.lib" )
#pragma comment( lib, "oleaut32.lib" )

#pragma comment(lib, "wbemuuid.lib")



 
#include "CheckAPI.h"




 


CSecurityProductList::CSecurityProductList():mp_Header(NULL),mp_Next(NULL)
{
	mp_Header = NULL;
	mp_Next = NULL;
}

CSecurityProductList::~CSecurityProductList()
{
	SECURITY_PRODUCT		*p_tmp = NULL;
	
	SECURITY_PRODUCT		*p_next = NULL;
	
	if ( mp_Header )
	{
		p_tmp = mp_Header;
		while(p_tmp->next != NULL)
		{
			p_next = p_tmp->next;	// 
			
			p_tmp->next = NULL;

			if ( p_tmp->pDisplayName )
			{
				free(p_tmp->pDisplayName);
				p_tmp->pDisplayName = NULL;
			}

			if ( p_tmp->pCompanyName )
			{
				free(p_tmp->pCompanyName);
				p_tmp->pCompanyName = NULL;
			}
			
			
			free(p_tmp);
			
			
			p_tmp = p_next;
		}
		
	}
	
	mp_Header = NULL;
	mp_Next = NULL;
	
}
 
BOOL	CSecurityProductList::Next(SECURITY_PRODUCT		*psp)
{
	BOOL	bResult = FALSE;



	if (NULL == mp_Next)
	{
		if ( mp_Header )
		{
			mp_Next = mp_Header;
			
			memcpy(psp, mp_Next, sizeof(SECURITY_PRODUCT));
			
			bResult = TRUE;
		}

	}
	else
	{
		mp_Next = mp_Next->next;
		if ( mp_Next )
		{
			memcpy(psp, mp_Next, sizeof(SECURITY_PRODUCT));

			bResult = TRUE;
		}
		
	}



	return bResult;

}

unsigned long	CSecurityProductList::Add(unsigned long ulProviderType, wchar_t *pszDisplayName, wchar_t *pszCompanyName, wchar_t* pszVersionNumber, char boolEnabled, char boolNew)
{
	SECURITY_PRODUCT		*p_tmp = NULL;
	int	nLen = 0;
	
	SECURITY_PRODUCT		*p_new = NULL;


	// 新增
	p_new = (SECURITY_PRODUCT*)malloc( sizeof(SECURITY_PRODUCT) );
	if ( NULL == p_new )
	{
		return -1;
	}
	memset(p_new, 0x00, sizeof(SECURITY_PRODUCT));

	
	nLen = wcslen(pszDisplayName) + 1;
	p_new->pDisplayName = (wchar_t*)malloc( nLen * 2);
	if ( NULL == p_new->pDisplayName )
	{
		return -2;
	}
	memset(p_new->pDisplayName, 0x00, nLen);

	nLen = wcslen(pszCompanyName) + 1;
	p_new->pCompanyName = (wchar_t*)malloc( nLen * 2);
	if ( NULL == p_new->pCompanyName )
	{
		return -3;
	}
	memset(p_new->pCompanyName, 0x00, nLen);

	
	nLen = wcslen(pszVersionNumber) + 1;
	p_new->pVersionNumber = (wchar_t*)malloc( nLen * 2);
	if ( NULL == p_new->pVersionNumber )
	{
		return -3;
	}
	memset(p_new->pVersionNumber, 0x00, nLen);
	

	//
	p_new->ulType = ulProviderType;	//	
	//
	wcscpy(p_new->pDisplayName, pszDisplayName);
	//
	wcscpy(p_new->pCompanyName, pszCompanyName);
	//
	wcscpy(p_new->pVersionNumber, pszVersionNumber);
	//
	p_new->bActiveState = boolEnabled;
	// 
	p_new->bVesionState = boolNew;
	//
	p_new->next = NULL;
	
	
	if ( NULL == mp_Header )
	{	
		mp_Header = p_new;
	}
	else
	{
		p_tmp = mp_Header;
		while(p_tmp->next != NULL)
		{
			p_tmp=p_tmp->next;
		}
		
		p_tmp->next = p_new;
		
	}
	
	

	return 0;

}



// 检测防火墙状态
static unsigned long WindowsFirewallIsOn( OUT BYTE *fwOn)
{
  
	unsigned long	ulResult = 0;
	
 
	// 打开服务管理对象
    SC_HANDLE hSCManager = NULL;
	
	// 打开防火墙服务。
    SC_HANDLE hSvc = NULL;
	
	// 服务的状态
	SERVICE_STATUS sStatus = {0};

	//
	char  *lpServiceName = NULL;

	OSVERSIONINFOEX  Os_WindVerInfoEx = {0};  // 版本信息
	

	// 获取 操作系统版本号
	Os_WindVerInfoEx.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO *)&Os_WindVerInfoEx); // 注意转换类型
	
	if (Os_WindVerInfoEx.dwPlatformId==VER_PLATFORM_WIN32_NT)
	{
		if (Os_WindVerInfoEx.dwMajorVersion <= 4 ) 
		{
			// Win98或NT;
			printf("OS is Win98或NT.\n");
			printf("Sorry, Current system do not support this WMI Stop !!\n");
			
			ulResult = 1;
			goto FINISH;                // Program has failed.
		}
		else
		{
			switch (Os_WindVerInfoEx.dwMajorVersion)
			{
			case 5:	
				// Windows 2000, Windows XP, Windows Server 2003 
				lpServiceName = "SharedAccess";
			
				break;
			case 6:		// >= 6
			default:
				// Windows Vista, Windows Server 2008, Windows 7, Windows 8
				lpServiceName = "MpsSvc";
				
				break;
			}
		}
		
	}
	else
	{
		// 
		ulResult = 2;
		goto FINISH;                // Program has failed.
	}

	
	// 打开服务管理对象
    hSCManager = ::OpenSCManager( NULL, NULL, GENERIC_EXECUTE);
    if( hSCManager == NULL)
    {
		ulResult = GetLastError(); 
        return ulResult;
    }
    // 打开防火墙服务
    // SharedAccess: Windows Firewall/Internet Connection Sharing (ICS) for Windows XP
    // MpsSvc: Windows Firewall for Windows 7
	// 
    hSvc = ::OpenServiceA( hSCManager, lpServiceName, SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP);
    if( hSvc == NULL)
    {
		ulResult = GetLastError();
        goto FINISH;
    }
	
    if( ::QueryServiceStatus( hSvc, &sStatus) == FALSE)
    {
		ulResult = GetLastError();
        goto FINISH; 
    }
	
	
    //  
    if( sStatus.dwCurrentState == SERVICE_RUNNING)
    {
        // 服务已启动
		*fwOn = ACTIVESTATE_ENABLED;
    }
    else if( sStatus.dwCurrentState == SERVICE_STOPPED)
    {
		// 服务已停止
		*fwOn = ACTIVESTATE_DISABLED;
    }
	else
	{
		*fwOn = ACTIVESTATE_UNKNOWN;
	}


FINISH:	
	
	if ( hSvc )
	{
		::CloseServiceHandle( hSvc);
	}
	
	if ( hSCManager )
	{
		::CloseServiceHandle( hSCManager);
	}
	
	
	
	
	return ulResult;

}


// 检测反病毒软件和防火墙软件
unsigned long	CheckSecurityCenter(unsigned long ulSecurityCenterType, CSecurityProductList *p_SecurityProductList)
{

	//////////////////////////////////////////////////////////////////////////
	// MSDN链接
	// The WMI Reference contains the following topics that discuss the core features of WMI.
	// WMI Reference: http://msdn.microsoft.com/en-us/library/aa394572(VS.85).aspx
	// 
	
	// 
	// 1. 开始-运行-输入: wbemtest 回车
	// 2. 单击"连接", 输入: XP-> root\SecurityCenter 或 Win7-> root\SecurityCenter2
	// 3. 单击"查询", 输入: select * from AntiVirusProduct  或  select * from FirewallProduct
	//



	HRESULT		hres = S_OK;

	IWbemClassObject *pclsObj = NULL;

    ULONG ulReturn = 0;

	
	
	
	OSVERSIONINFOEX  Os_WindVerInfoEx = {0};  // 版本信息
	//int inR2 = 0;  // 版本信息
	
	_bstr_t   bstrtWMINamespaceObjectPath = L"";


	_bstr_t   bstrtWMIQueryLanguage = L"";


	_bstr_t   bstrtProductEnabled =  L"";



	//
	IWbemLocator *pLoc = NULL;
	//
	IWbemServices *pSvc = NULL;
	//
	IEnumWbemClassObject* pEnumerator = NULL;

	
	
	unsigned long	ulProviderType = 0;	// 产品类型


	BYTE fwOn = ACTIVESTATE_UNKNOWN;

	


	// 获取 操作系统版本号
	Os_WindVerInfoEx.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO *)&Os_WindVerInfoEx); // 注意转换类型
	

	// 先判断 Windows 自带防火墙
	if ( SECURITYCENTER_FIREWALL == ulSecurityCenterType )
	{
		
		ulReturn = WindowsFirewallIsOn(&fwOn);
		if (ulReturn)
		{
			fwOn = ACTIVESTATE_UNKNOWN;
		}

		// 打开防火墙服务
		// SharedAccess: Windows Firewall/Internet Connection Sharing (ICS) for Windows XP
		// MpsSvc: Windows Firewall for Windows 7
	
		p_SecurityProductList->Add(PROVIDER_FIREWALL,  L"Windows Firewall",  L"Microsoft",  L"", fwOn, VESIONSTATE_UNKNOWN);
		
	  
	}
	else if ( SECURITYCENTER_ANTIVIRUS == ulSecurityCenterType )
	{
	}
	else
	{
		hres = 1;
		goto FINISH;
	}


//    printf("// Step 1: --------------------------------------------------\n");
    // Initialize COM. ------------------------------------------
    hres =  CoInitializeEx(0, COINIT_MULTITHREADED); 
	if (FAILED(hres))
    {
		printf("Failed to initialize COM library. Error code = 0x%08x", hres); 
		
        //return hres;                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------
    hres =  CoInitializeSecurity( NULL, 
								  -1,                          // COM authentication
								  NULL,                        // Authentication services
								  NULL,                        // Reserved
								  RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
								  RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
								  NULL,                        // Authentication info
								  EOAC_NONE,                   // Additional capabilities 
								  NULL                         // Reserved
								);     
	if (FAILED(hres))
    {
		printf("Failed to initialize security. Error code = 0x%08x\n", hres); 
        goto FINISH;                    // Program has failed.
    }

//    printf("// Step 3: ---------------------------------------------------\n");
    // Obtain the initial locator to WMI -------------------------
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *) &pLoc);
	if (FAILED(hres))
    {
        printf("Failed to create IWbemLocator object. Error code = 0x%08x", hres);
        goto FINISH;                 // Program has failed.
    }

	
	if (Os_WindVerInfoEx.dwPlatformId==VER_PLATFORM_WIN32_NT)
	{
		if (Os_WindVerInfoEx.dwMajorVersion <= 4 ) 
		{
			// Win98或NT;
			printf("OS is Win98或NT.\n");
			printf("Sorry, Current system do not support this WMI Stop !!\n");
			
			hres = 1;
			goto FINISH;                // Program has failed.
		}
		else
		{
			switch (Os_WindVerInfoEx.dwMajorVersion)
			{
			case 5:	
				// Windows 2000, Windows XP, Windows Server 2003
				// 旧的 WMI 根路径：\\Hostname\ROOT\SecurityCenter:AntiVirusProduct 
				bstrtWMINamespaceObjectPath = L"root\\SecurityCenter";
				

				//
				if ( SECURITYCENTER_ANTIVIRUS == ulSecurityCenterType )
				{
					bstrtProductEnabled = L"onAccessScanningEnabled"; 
				}
				else if ( SECURITYCENTER_FIREWALL == ulSecurityCenterType )
				{
					bstrtProductEnabled = L"enabled"; 
				}
				else
				{
					hres = 3;
					goto FINISH;
				}
				break;
			case 6:		// >= 6
			default:
				// Windows Vista, Windows Server 2008, Windows 7, Windows 8
				// 新的 WMI 根路径：\\Hostname\ROOT\SecurityCenter2:AntiVirusProduct 
				bstrtWMINamespaceObjectPath = L"root\\SecurityCenter2";
				
				//
				bstrtProductEnabled = L"productState";
				break;
			}
		}
		
	}
	else
	{
		// 
		hres = 2;
		goto FINISH;                // Program has failed.
	}

//    printf("// Step 4: -----------------------------------------------------\n");
    // Connect to WMI through the IWbemLocator::ConnectServer method
    // Connect to the root/SecurityCenter namespace with
    // the current user and obtain pointer pSvc
    // to make IWbemServices calls. 
    //								root\\SecurityCenter SecurityCenter2
    //								反病毒产品 防火墙产品
    hres = pLoc->ConnectServer( bstrtWMINamespaceObjectPath, // Object path of WMI namespace
								NULL,                    // User name. NULL = current user
								NULL,                    // User password. NULL = current
								0,                       // Locale. NULL indicates current
								NULL,                    // Security flags.
								0,                       // Authority (e.g. Kerberos)
								0,                       // Context object 
								&pSvc                    // pointer to IWbemServices proxy
								);
    if (FAILED(hres))
    {
        printf("Could not connect to \"%s\". Error code = 0x%08x", bstrtWMINamespaceObjectPath, hres);
        goto FINISH;                // Program has failed.

    }
 
    // printf("Connected to ROOT//SecurityCenter WMI namespace\n");

//    printf("// Step 5: --------------------------------------------------\n");
    // Set security levels on the proxy -------------------------
    hres = CoSetProxyBlanket(  pSvc,                        // Indicates the proxy to set
							   RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
							   RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
							   NULL,                        // Server principal name 
							   RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
							   RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
							   NULL,                        // client identity
							   EOAC_NONE                    // proxy capabilities 
							);
    if (FAILED(hres))
    {
        printf("Could not set proxy blanket. Error code = 0x%08x", hres);
        goto FINISH;               // Program has failed.
    }

	if ( SECURITYCENTER_ANTIVIRUS == ulSecurityCenterType )
	{
		bstrtWMIQueryLanguage = _bstr_t(L"SELECT * FROM AntiVirusProduct");

		ulProviderType = PROVIDER_ANTIVIRUS;
	}
	else if ( SECURITYCENTER_FIREWALL == ulSecurityCenterType )
	{
		bstrtWMIQueryLanguage = _bstr_t(L"SELECT * FROM FirewallProduct");

		ulProviderType = PROVIDER_FIREWALL;
	}
	else
	{
		hres = 3;
		goto FINISH;
	}


//    printf("// Step 6: --------------------------------------------------\n");
    // Use the IWbemServices pointer to make requests of WMI ----

    // For example, get the name of the operating system
    hres = pSvc->ExecQuery( bstr_t("WQL"), 
							bstrtWMIQueryLanguage,
							WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, 
							NULL,
							&pEnumerator);
    if (FAILED(hres))
    {
        printf("Query for operating system name failed. Error code = 0x%08x", hres);
        goto FINISH;               // Program has failed.
    }

//    printf("// Step 7: -------------------------------------------------\n");
    // Get the data from the query in step 6 -------------------
	
    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &ulReturn);
        if(0 == ulReturn)
        {
            break;
		}
	
     

		
		wchar_t* lpszDisplayName = NULL;	// 产品名称
		wchar_t* lpszCompanyName = NULL;	// 公司名称
		BOOL	boolEnabled = ACTIVESTATE_UNKNOWN;	// 激活状态
		
		BOOL	boolNew = VESIONSTATE_UNKNOWN;		// 病毒库版本状态
		wchar_t* lpszVersionNumber = NULL;	// 病毒库版本号


		_bstr_t bstrDisplayName; 
		_bstr_t bstrCompanyName; 
		ULONG	ulProductState;
		_bstr_t bstrVersionNumber; 

		VARIANT vtDisplayName;
		VARIANT vtCompanyName;
		VARIANT vtProductState;
		VARIANT vtVersionNumber;
		
		
		VariantInit(&vtDisplayName);
		VariantInit(&vtCompanyName);
		VariantInit(&vtProductState);
		VariantInit(&vtVersionNumber);
		


        // Get the value of the Name property
        hr = pclsObj->Get(L"displayName", 0, &vtDisplayName, 0, 0);
		if ( hr )	// 0x80041002
		{
			continue;
		}
		// 
        hr = pclsObj->Get(L"companyName", 0, &vtCompanyName, 0, 0);
		if ( hr )	// 0x80041002
		{	 

// 				//Create   a   BSTR   and   assign   it   to   a   Variant   
// 				BSTR   cn   =   SysAllocString(L"");   
// 				vtCompanyName.vt   =   VT_BSTR;   
// 				vtCompanyName.bstrVal   =   cn; 
// 				SysFreeString(cn); 

		}


		// 3. 版本号, 防火墙其实也没这项
		hr = pclsObj->Get(L"versionNumber", 0, &vtVersionNumber, 0, 0);
		if ( hr )	// 0x80041002
		{	 

		}

 

		// 
		bstrDisplayName = _bstr_t(vtDisplayName);
		lpszDisplayName = bstrDisplayName; 

		//
		if ( VT_NULL == vtCompanyName.vt )
		{ 
			bstrCompanyName = L"";
		}
		else
		{
			bstrCompanyName = _bstr_t(vtCompanyName);
		}	
		lpszCompanyName = bstrCompanyName;
	  
		// 
		if ( VT_NULL == vtVersionNumber.vt )
		{ 
			bstrVersionNumber = L"";
		}
		else
		{
			bstrVersionNumber = _bstr_t(vtVersionNumber);
		}
		lpszVersionNumber = bstrVersionNumber; 





		switch (Os_WindVerInfoEx.dwMajorVersion)
		{
		case 5:	
			// Windows 2000, Windows XP, Windows Server 2003

			// XP :  productUptoDate
			hr = pclsObj->Get(bstrtProductEnabled, 0, &vtProductState, 0, 0);
			if ( hr )	// 0x80041002
			{ 
				vtProductState.vt   =   VT_BOOL;   
				vtProductState.boolVal   =   1;		// -1: True   0: False   1: 自定义的, 表示未知
			}
			 
			// 1. 
			if ( VARIANT_TRUE == vtProductState.boolVal )
			{
				boolEnabled = ACTIVESTATE_ENABLED;
			}
			else if ( VARIANT_FALSE == vtProductState.boolVal )
			{
				boolEnabled = ACTIVESTATE_DISABLED;
			}
			else
			{
				boolEnabled = ACTIVESTATE_UNKNOWN;
			}
			
 			if ( SECURITYCENTER_ANTIVIRUS == ulSecurityCenterType )
 			{

				VariantClear(&vtProductState);
				VariantInit(&vtProductState);

				// 2. 病毒库版本状态
				hr = pclsObj->Get(L"productUptoDate", 0, &vtProductState, 0, 0);
				if ( hr )	// 0x80041002
				{
					vtProductState.vt   =   VT_BOOL;   
 					vtProductState.boolVal   =   1;		// -1: True   0: False   1: 自定义的, 表示未知
				}
  
				if ( VARIANT_TRUE == vtProductState.boolVal )
				{
					boolNew = VESIONSTATE_NEW;
				}
				else if ( VARIANT_FALSE == vtProductState.boolVal )
				{
					boolNew = VESIONSTATE_OLD;
				}
				else
				{
					boolNew = VESIONSTATE_UNKNOWN;
				}

 			} 
			else	// 防火墙没有这项
			{ 
				boolNew = VESIONSTATE_UNKNOWN;
			}



			break;
		case 6:		// >= 6
		default:
			// Windows Vista, Windows Server 2008, Windows 7, Windows 8  
			

			// Win 7: productState
			hr = pclsObj->Get(bstrtProductEnabled, 0, &vtProductState, 0, 0);
			if ( hr )	// 0x80041002
			{ 
				vtProductState.vt   =   VT_I4;   
				vtProductState.intVal   =   -1;		// -1: 自定义的, 表示未知
			}
			

			//productState = 393216 (0x60000)  关闭
			//productState = 397312 (0x61000) 启用
			// 
			
			if ( -1 == vtProductState.intVal )
			{
				boolEnabled = ACTIVESTATE_UNKNOWN;
				boolNew = VESIONSTATE_UNKNOWN;
			}
			else
			{
				ulProductState = vtProductState.intVal;
			
  

				//////////////////////////////////////////////////////////////////////////
				// MSDN文档Web链接: http://msdn.microsoft.com/en-us/library/jj155487(v=vs.85).aspx
				// Minimum supported client: Windows Vista
				// 
				// How to read the productState:
				// Convert productState to hex: 266240 -> 0x041000
				// Split the hex value up in 3 byte blocks, we get now 3 bytes: 0x04, 0x10, 0x00.
				// 1. The first byte is a WSC_SECURITY_PROVIDER Enumeration:
				// 2. I assume the second byte defines if the scanner is active or not:
				// 3. The third byte is also an assumption, it defines if the .dat file is up-to-date:
				// 
				// AvStatus 启用状态
				// AvStatus = Hex("ProductState".Value)
				// tbAvStatus = Mid(AvStatus, 2, 2)
				// AntiVirus enabled: 10或11
				// AntiVirus disabled: 00 或 01
				// 例如:
				// 393472 (060100) = disabled and up to date
				// 397584 (061110) = enabled and out of date
				// 397568 (061100) = enabled and up to date
				// 397312 (061000) = enabled and up to date
				// 393216 (060000) = disabled and up to date
				// 
				
				// 1. 
				if ( 0x00001000 == (ulProductState & 0x00001000) 
					|| 0x00001100 == (ulProductState & 0x00001100) )	// 10或11: AntiVirus enabled
				{
					boolEnabled = ACTIVESTATE_ENABLED;
				}
				else		//  00 或 01:  AntiVirus disabled
				{
					boolEnabled = ACTIVESTATE_DISABLED;
				}

				// AvStatus 病毒库版本状态
				// AvStatus = Hex("ProductState".Value);
				// AvCurrent = Mid(AvStatus, 4, 2)
				// 最新: 00
				// 过时: 10 
				//
				
				// 2. 
				if ( 0x00000000 == (ulProductState & 0x000000FF)  )	// 00:  definitions are current
				{
					boolNew = VESIONSTATE_NEW;
				}
				else		//  10:  definitions out of date
				{
					boolNew = VESIONSTATE_OLD;
				}
			

			}	// end if ( -1 == vtProductState.intVal )

		break;

		}	// end switch
        
           
 

 		
		// add 
		p_SecurityProductList->Add( ulProviderType, lpszDisplayName, lpszCompanyName, lpszVersionNumber, boolEnabled , boolNew);
		



		//
		VariantClear(&vtDisplayName); 
		VariantClear(&vtCompanyName); 
		VariantClear(&vtVersionNumber); 
		

		 
		//
        pclsObj->Release();

    }
FINISH:
	
    // ========

	if ( pEnumerator )
	{
		pEnumerator->Release();
	}

	if ( pSvc )
	{
		pSvc->Release();     
	}

	if ( pLoc )
	{
		pLoc->Release();     
	}
 
	CoUninitialize();
 

	

    return 0;   // Program successfully completed.

}




#if 0



//////////////////////////////////////////////////////////////////////////
// MSDN
// 
// http://msdn.microsoft.com/en-us/library/ms724833(v=vs.85).aspx
// The following table summarizes the values returned by supported versions of Windows. Use the information in the column labeled "Other" to distinguish between operating systems with identical version numbers.
//
// Operating system			Version	number	dwMajorVersion	dwMinorVersion	Other
// Windows 8.1				6.3*			6				3				OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION
// Windows Server 2012 R2	6.3*			6				3				OSVERSIONINFOEX.wProductType != VER_NT_WORKSTATION
// Windows 8				6.2				6				2				OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION
// Windows Server 2012		6.2				6				2				OSVERSIONINFOEX.wProductType != VER_NT_WORKSTATION
// Windows 7				6.1				6				1				OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION
// Windows Server 2008 R2	6.1				6				1				OSVERSIONINFOEX.wProductType != VER_NT_WORKSTATION
// Windows Server 2008		6.0				6				0				OSVERSIONINFOEX.wProductType != VER_NT_WORKSTATION
// Windows Vista			6.0				6				0				OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION
// Windows Server 2003 R2	5.2				5				2				GetSystemMetrics(SM_SERVERR2) != 0
// Windows Home Server		5.2				5				2				OSVERSIONINFOEX.wSuiteMask & VER_SUITE_WH_SERVER
// Windows Server 2003		5.2				5				2				GetSystemMetrics(SM_SERVERR2) == 0
// Windows XP Professional x64 Edition	5.2	5				2				(OSVERSIONINFOEX.wProductType == VER_NT_WORKSTATION) && (SYSTEM_INFO.wProcessorArchitecture==PROCESSOR_ARCHITECTURE_AMD64)
// Windows XP				5.1				5				1				Not applicable
// Windows 2000				5.0				5				0				Not applicable
//////////////////////////////////////////////////////////////////////////

unsigned long	GetOSVersion()
{  
	OSVERSIONINFOEX  Os_WindVerInfoEx = {0};  // 版本信息
	int inR2 = 0;  // 版本信息
	// 

	//////////////////////////////////////////////////////////////////////////
	// 判断操作系统版本
	//
	// 
	
	Os_WindVerInfoEx.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO *)&Os_WindVerInfoEx); // 注意转换类型
	//inR2=GetSystemMetrics(SM_SERVERR2);
	
	if (Os_WindVerInfoEx.dwPlatformId==VER_PLATFORM_WIN32_NT)
	{
		if (Os_WindVerInfoEx.dwMajorVersion <= 4 ) 
		{
			// Win98或NT;
			printf("OS is Win98或NT.\n");
			printf("Sorry, Current system do not support this WMI Stop !!\n");
 
			return 1;                // Program has failed.
		}
		else
		{
			switch (Os_WindVerInfoEx.dwMajorVersion)
			{
			case 5:
				if ( Os_WindVerInfoEx.dwMinorVersion == 0 )
				{
					// Win2000;
					printf("OS is Win2000.\n");
				}
				if ( Os_WindVerInfoEx.dwMinorVersion == 1 )
				{
					// WinXP;
					printf("OS is WinXP.\n");
				}
				if ((Os_WindVerInfoEx.dwMinorVersion == 2) && (inR2==0) )
				{
					// Server2003;
					printf("OS is Server2003.\n");
				}
				if ( (Os_WindVerInfoEx.dwMinorVersion == 2) && (inR2!=0) )
				{
					// Server2003_R2;
					printf("OS is Server2003_R2.\n");
				}
				
 
				
				break;
			case 6:
				if ((Os_WindVerInfoEx.dwMinorVersion == 0)&&( Os_WindVerInfoEx.wProductType==VER_NT_WORKSTATION) )
				{		
					// winVista;  
					printf("OS is winVista.\n");      
				}
				if ( (Os_WindVerInfoEx.dwMinorVersion == 0)&&( Os_WindVerInfoEx.wProductType!=VER_NT_WORKSTATION) )
				{
					// Server2008;
					printf("OS is Server2008.\n");
				}
				if ((Os_WindVerInfoEx.dwMinorVersion ==1)&&( Os_WindVerInfoEx.wProductType==VER_NT_WORKSTATION) )
				{
					// Win7;
					printf("OS is Win7.\n");
				}
				if ((Os_WindVerInfoEx.dwMinorVersion ==1)&&( Os_WindVerInfoEx.wProductType!=VER_NT_WORKSTATION) )
				{
					// Server2008_R2;
					printf("OS is Server2008_R2.\n");
				}
				
	 
				break;
			}
		}
		
	}

	
	return S_OK;
}

 

// // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\SharedAccess\Parameters\FirewallPolicy\PublicProfile
HRESULT WindowsFirewallTurn(BOOL boolEnabled)
{
	unsigned long	ulResult = 0;

	DWORD dwControl = 0;

	// 打开服务管理对象
    SC_HANDLE hSCManager = NULL;

	// 打开防火墙服务。
    SC_HANDLE hSvc = NULL;

	// 服务的状态
	SERVICE_STATUS sStatus = {0};

	//
	char  *lpServiceName = NULL;
	
	OSVERSIONINFOEX  Os_WindVerInfoEx = {0};  // 版本信息
	
	
	// 获取 操作系统版本号
	Os_WindVerInfoEx.dwOSVersionInfoSize=sizeof(OSVERSIONINFOEX);
	GetVersionEx((OSVERSIONINFO *)&Os_WindVerInfoEx); // 注意转换类型
	
	if (Os_WindVerInfoEx.dwPlatformId==VER_PLATFORM_WIN32_NT)
	{
		if (Os_WindVerInfoEx.dwMajorVersion <= 4 ) 
		{
			// Win98或NT;
			printf("OS is Win98或NT.\n");
			printf("Sorry, Current system do not support this WMI Stop !!\n");
			
			ulResult = 1;
			goto FINISH;                // Program has failed.
		}
		else
		{
			switch (Os_WindVerInfoEx.dwMajorVersion)
			{
			case 5:	
				// Windows 2000, Windows XP, Windows Server 2003 
				lpServiceName = "SharedAccess";
				
				break;
			case 6:		// >= 6
			default:
				// Windows Vista, Windows Server 2008, Windows 7, Windows 8
				lpServiceName = "MpsSvc";
				
				break;
			}
		}
		
	}
	else
	{
		// 
		ulResult = 2;
		goto FINISH;                // Program has failed.
	}

 
	// 打开服务管理对象	
    hSCManager = ::OpenSCManager( NULL, NULL, GENERIC_EXECUTE);	// SC_MANAGER_ALL_ACCESS
    if( hSCManager == NULL)
    {
		ulResult = GetLastError(); 
        return ulResult;
    }
    // 打开防火墙服务
    // SharedAccess: Windows Firewall/Internet Connection Sharing (ICS) for Windows XP
    // MpsSvc: Windows Firewall for Windows 7
	// 
    hSvc = ::OpenService( hSCManager, lpServiceName, SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP);
    if( hSvc == NULL)
    {
		ulResult = GetLastError();
        goto FINISH;
    }

    if( ::QueryServiceStatus( hSvc, &sStatus) == FALSE)
    {
		ulResult = GetLastError();
        goto FINISH; 
    }


	if ( TRUE == boolEnabled )
	{
		dwControl = SERVICE_CONTROL_CONTINUE;

		// 如果处于停止状态则启动服务

		if( sStatus.dwCurrentState == SERVICE_STOPPED)
		{
			// 启动服务
			if( ::StartService( hSvc, NULL, NULL) == FALSE)
			{
				ulResult = GetLastError();
				goto FINISH;
			}
			// 等待服务启动
			while( ::QueryServiceStatus( hSvc, &sStatus) == TRUE)
			{
				::Sleep( sStatus.dwWaitHint);
				if( sStatus.dwCurrentState == SERVICE_RUNNING)
				{
					// start success
					ulResult = 0;
					goto FINISH;
				}
			}
		}
     

	}
	else
	{
  
		// 如果处于启用状态则停止服务
		if( sStatus.dwCurrentState == SERVICE_RUNNING)
		{
			// 停止服务
			if( ::ControlService( hSvc, SERVICE_CONTROL_STOP, &sStatus) == FALSE)
			{ 
				ulResult = GetLastError();
				goto FINISH;
			}
			// 等待服务停止
			while( ::QueryServiceStatus( hSvc, &sStatus) == TRUE)
			{
				::Sleep( sStatus.dwWaitHint);
				if( sStatus.dwCurrentState == SERVICE_STOPPED)
				{
					// stop success
					ulResult = 0;
					goto FINISH;
				}
			}
		}

	}


    
	
	
    

FINISH:	
	
	if ( hSvc )
	{
		::CloseServiceHandle( hSvc);
	}
	
	if ( hSCManager )
	{
		::CloseServiceHandle( hSCManager);
	}
   



	return ulResult;
}

#endif


