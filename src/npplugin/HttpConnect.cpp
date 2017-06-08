
#include "HttpConnect.h"

#include <windows.h>
#include <Wininet.h>
#include <wincrypt.h>


unsigned int HttpConnect(const char * pszSite,const char * pszSub, unsigned int uiPort)
{
	unsigned int ulRet = 0;

	DWORD dwInfoLevel = HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER;
	long statusCode = 0;
	DWORD bufLen = sizeof(statusCode);
	DWORD errCode = GetLastError(); 
	DWORD secureFlags =  0;
	const char *accept[2] = {"text/*", NULL};
	HINTERNET m_hRequest = NULL;
	const char header[] = {"Content-Type: application/x-www-form-urlencoded"};
	const char * const post_data = "";
	BOOL  result = TRUE;
	HINTERNET m_hSession = NULL;
	HINTERNET m_hInternet = NULL;
	char buf[128*1024]={0};
	bufLen=128*1024;
	DWORD dwNumberOfBytesRead = 0;


	m_hInternet = InternetOpenA("My Agent",
                                         INTERNET_OPEN_TYPE_PRECONFIG,
                                          NULL,
                                          NULL,
                                          0);

	errCode = GetLastError();
	if (m_hInternet == NULL)
	{
		ulRet = -1;
	}
	else
	{
		ulRet = 0;
	}

    m_hSession = InternetConnectA( m_hInternet,
		                                    pszSite,//baidu没https。换成ssltest13.bbtest.net，你可以在浏览器里看这个页面的内容
                                            uiPort,//INTERNET_DEFAULT_HTTPS_PORT,//https默认端口 443
                                            "",
                                            "",
                                            INTERNET_SERVICE_HTTP,
                                            0,
                                            0);


	errCode = GetLastError();
	if (m_hSession == NULL)
	{
		ulRet = -1;
	}
	else
	{
		ulRet = 0;
	}
    
	if (8443 == uiPort || 443 == uiPort)
	{
		secureFlags =  INTERNET_FLAG_RELOAD         |
			INTERNET_FLAG_NO_CACHE_WRITE            |
			INTERNET_FLAG_SECURE                    |  
			INTERNET_FLAG_IGNORE_CERT_CN_INVALID    |
			INTERNET_FLAG_IGNORE_CERT_DATE_INVALID  |
			INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP	|
			INTERNET_FLAG_KEEP_CONNECTION			|
			INTERNET_FLAG_NO_AUTH					|
			INTERNET_FLAG_NO_COOKIES				|
			INTERNET_FLAG_NO_UI;
	}
	else
	{
		secureFlags =  INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP	|
			INTERNET_FLAG_KEEP_CONNECTION						|
			INTERNET_FLAG_NO_AUTH								|
			INTERNET_FLAG_NO_COOKIES							|
			INTERNET_FLAG_NO_UI;
	}

    m_hRequest =  HttpOpenRequestA(  m_hSession,
                                               "GET", //用get获取页面
                                               pszSub,//object,
                                               NULL,
                                               NULL,
                                               accept,//accept,
                                               secureFlags,
                                               0);

	errCode = GetLastError();
	if (m_hRequest == NULL)
	{
		ulRet = -1;
	}
	else
	{
		ulRet = 0;
	}

	result = HttpSendRequestA( m_hRequest,
		header,
		strlen(header),
		(LPVOID)post_data,
		strlen(post_data));

	errCode = GetLastError();
	if (!result)
	{
		ulRet = -1;
	}
	else
	{
		ulRet = 0;
	}
	
    result = HttpQueryInfoA(m_hRequest, dwInfoLevel, &statusCode, &bufLen, 0); //获得返回的http状态码

	errCode = GetLastError();
	if (!result)
	{
		ulRet = -1;
	}
	else
	{
		ulRet = 0;
	}

	result = InternetReadFile(m_hRequest, buf, bufLen, &dwNumberOfBytesRead);//获得http 体。也就是html页面

	errCode = GetLastError();
	if (!result || 0 == dwNumberOfBytesRead)
	{
		ulRet = -1;
	}
	else
	{
		ulRet = 0;
	}
err:
	if (m_hInternet)
	{
		InternetCloseHandle(m_hInternet);
	}

	if (ulRet)
	{
		ulRet = errCode;
	}

	return ulRet;
}


#include "SSLCon.h"
#include <iostream>
using namespace std;

string HttpGet(const char * pszSite,const char * pszSub, unsigned int uiPort)
{
	unsigned int ulRet = 0;

	string strRet = "";

	DWORD dwInfoLevel = HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER;
	long statusCode = 0;
	DWORD bufLen = sizeof(statusCode);
	DWORD errCode = GetLastError(); 
	DWORD secureFlags =  0;
	const char *accept[2] = {"text/*", NULL};
	HINTERNET m_hRequest = NULL;
	const char header[] = {"Content-Type: application/x-www-form-urlencoded"};
	const char * const post_data = "";
	BOOL  result = TRUE;
	HINTERNET m_hSession = NULL;
	HINTERNET m_hInternet = NULL;
	char buf[128*1024]={0};
	bufLen=128*1024;
	DWORD dwNumberOfBytesRead = 0;


	m_hInternet = InternetOpenA("My Agent",
                                         INTERNET_OPEN_TYPE_PRECONFIG,
                                          NULL,
                                          NULL,
                                          0);

	errCode = GetLastError();
	if (m_hInternet == NULL)
	{
		ulRet = -1;
	}
	else
	{
		ulRet = 0;
	}

    m_hSession = InternetConnectA( m_hInternet,
		                                    pszSite,//baidu没https。换成ssltest13.bbtest.net，你可以在浏览器里看这个页面的内容
                                            uiPort,//INTERNET_DEFAULT_HTTPS_PORT,//https默认端口 443
                                            "",
                                            "",
                                            INTERNET_SERVICE_HTTP,
                                            0,
                                            0);


	errCode = GetLastError();
	if (m_hSession == NULL)
	{
		ulRet = -1;
	}
	else
	{
		ulRet = 0;
	}
    
	if (8443 == uiPort || 443 == uiPort)
	{
		secureFlags =  INTERNET_FLAG_RELOAD         |
			INTERNET_FLAG_NO_CACHE_WRITE            |
			INTERNET_FLAG_SECURE                    |  
			INTERNET_FLAG_IGNORE_CERT_CN_INVALID    |
			INTERNET_FLAG_IGNORE_CERT_DATE_INVALID  |
			INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP	|
			INTERNET_FLAG_KEEP_CONNECTION			|
			INTERNET_FLAG_NO_AUTH					|
			INTERNET_FLAG_NO_COOKIES				|
			INTERNET_FLAG_NO_UI;
	}
	else
	{
		secureFlags =  INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP	|
			INTERNET_FLAG_KEEP_CONNECTION						|
			INTERNET_FLAG_NO_AUTH								|
			INTERNET_FLAG_NO_COOKIES							|
			INTERNET_FLAG_NO_UI;
	}

    m_hRequest =  HttpOpenRequestA(  m_hSession,
                                               "GET", //用get获取页面
                                               pszSub,//object,
                                               NULL,
                                               NULL,
                                               accept,//accept,
                                               secureFlags,
                                               0);

	errCode = GetLastError();
	if (m_hRequest == NULL)
	{
		ulRet = -1;
	}
	else
	{
		ulRet = 0;
	}

	result = HttpSendRequestA( m_hRequest,
		header,
		strlen(header),
		(LPVOID)post_data,
		strlen(post_data));

	errCode = GetLastError();
	if (!result)
	{
		ulRet = -1;
	}
	else
	{
		ulRet = 0;
	}
	
    result = HttpQueryInfoA(m_hRequest, dwInfoLevel, &statusCode, &bufLen, 0); //获得返回的http状态码

	errCode = GetLastError();
	if (!result)
	{
		ulRet = -1;
	}
	else
	{
		ulRet = 0;
	}

	result = InternetReadFile(m_hRequest, buf, bufLen, &dwNumberOfBytesRead);//获得http 体。也就是html页面

	errCode = GetLastError();
	if (!result || 0 == dwNumberOfBytesRead)
	{
		ulRet = -1;
	}
	else
	{
		ulRet = 0;
	}
err:
	if (m_hInternet)
	{
		InternetCloseHandle(m_hInternet);
	}

	if (ulRet)
	{
		ulRet = errCode;
		strRet += ulRet;
	}
	else
	{
		strRet += buf;
	}

	return strRet;
}

unsigned int SSLConnect(const char * pszSite,const char * pszSub, unsigned int uiPort, unsigned int uiTimeOutSecond)
{
	CSslConnection inetSec;
	string sAgentName("My Firm");
	string sServerName(pszSite); //Can be any https server address
	string sUserName("");//if required
	string sPass(""); //if required
	string sObjectName(pszSub);//there should be an object to send a verb

	//You may choose any field of a certificate to perform a context search, 
	//i just implemented the OU field of the Issuer here
	string sOrganizationUnitName("3-D Secure Compliance TestFacility");
	//end	
	string strVerb = "GET";//My sample verb 	

	inetSec.SetAgentName(sAgentName);
	inetSec.SetCertStoreType(certStoreMY);
	inetSec.SetObjectName(sObjectName);	
	inetSec.SetTimeOut(uiTimeOutSecond);
	//Sample field
	inetSec.SetOrganizationName(sOrganizationUnitName);
	//End

	inetSec.SetPort(uiPort);//443 is the default HTTPS port
	inetSec.SetServerName(sServerName); 

	//you should better assign a unique number for each internet connection
	inetSec.SetRequestID(0);
	//end

	if (!inetSec.ConnectToHttpsServer(strVerb)) {
		return -1;
	}

	if (!inetSec.SendHttpsRequest()) {
		return -1;
	}

	//string response = inetSec.GetRequestResult();

	//cout << response.c_str() << endl;

	return 0;
}

