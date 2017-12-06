
#include <stdio.h>
#include "../npplugin/SSLCon.h"
#include "FILE_LOG.h"


unsigned int SSLConnect(const char * pszSite, const char * pszSub, unsigned int uiPort, unsigned int uiTimeOutSecond)
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

int main()
{
	static int i = 0;

	for(i = 0; i < 50; i++)
	{
		FILE_WRITE_FMT("network.log","%i time res=%d\n", i, SSLConnect("per.cmbc.com.cn", "pweb/static/login.html", 443, 5));
	}

	return 0;
}
