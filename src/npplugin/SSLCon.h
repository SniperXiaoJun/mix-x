// SslCon: interface for the CSslConnection class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_WINETSEC_H__91AD1B9B_5B03_457E_A6B6_D66BB03147B7__INCLUDED_)
#define AFX_WINETSEC_H__91AD1B9B_5B03_457E_A6B6_D66BB03147B7__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include <windows.h>
#include <Wininet.h>
#include <wincrypt.h>

#pragma warning(disable:4786)

#include <string>
using namespace std;

enum CertStoreType {certStoreMY, certStoreCA, certStoreROOT, certStoreSPC};

class CSslConnection  
{
public:
	CSslConnection();
	virtual ~CSslConnection();	
public:	
	bool ConnectToHttpsServer(string &strVerb);
	bool SendHttpsRequest();
	string GetRequestResult();
public: //accessors
	void SetAgentName(string &strAgentName) { m_strAgentName = strAgentName; }
	void SetTimeOut(unsigned int uiTimeOutSecond) { m_uiTimeOutSecond = uiTimeOutSecond; }
	void SetCertStoreType(CertStoreType storeID) { m_certStoreType = storeID; }
	void SetServerName(string &strServerName) { m_strServerName = strServerName; }
	void SetObjectName(string &strObjectName) { m_strObjectName = strObjectName; }
	void SetPort(INTERNET_PORT wPort = INTERNET_DEFAULT_HTTPS_PORT) { m_wPort = wPort; }
	void SetRequestID(int reqID) { m_ReqID = reqID; }
	void SetSecurityFlags(int flags) { m_secureFlags = flags; }
	//Search indicators	
	void SetOrganizationName(string &strOName) { m_strOName = strOName;} 
	string GetLastErrorString() { return m_strLastError; }
	int GetLastErrorCode() { return m_lastErrorCode; }
private:
	// examine the following function in order to perform different certificate 
	// property searchs in stores. It detects the desired certificate with the organization name
	PCCERT_CONTEXT FindCertWithOUNITName();	
	/////////////////////////////////////
	bool SetClientCert();
	void ClearHandles();
private:
	HINTERNET m_hInternet;
	HINTERNET m_hRequest;
	HINTERNET m_hSession;
	
	string m_strServerName;
	string m_strObjectName;
	INTERNET_PORT m_wPort;
	int m_secureFlags;

	HCERTSTORE m_hStore;
	PCCERT_CONTEXT m_pContext;
	CertStoreType m_certStoreType;	
	string m_strUserName;
	string m_strPassword;		
	string m_strAgentName;
	string m_strOName;
	string m_strLastError;
	int m_lastErrorCode;
	int m_ReqID;
	unsigned int m_uiTimeOutSecond;
};

#endif // !defined(AFX_WINETSEC_H__91AD1B9B_5B03_457E_A6B6_D66BB03147B7__INCLUDED_)

