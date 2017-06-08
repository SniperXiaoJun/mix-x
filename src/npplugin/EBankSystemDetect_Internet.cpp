
#include "EBankSystemDetect.h"
#include "json/json.h"
#include "HttpConnect.h"
#include "common.h"
#include <string>

using namespace std;

string WTF_CheckWebSite(string strsite, string strSub, int nPort, unsigned int uiTimeOutSecond)
{
	Json::Value item;

	unsigned long ulRet = 0;

	ulRet = SSLConnect(strsite.c_str(), strSub.c_str(),nPort, uiTimeOutSecond);

	if (0 == ulRet)
	{
		item["success"] = TRUE;
		item["url"] = strsite;
		item["sec_level"] = TYPE_SEC_NORMAL;
	}
	else
	{
		item["success"] = FALSE;
		item["sec_level"] = TYPE_SEC_EXCEPT;
	}

err:

	return item.toStyledString();

}

string HttpGet(const char * pszSite,const char * pszSub, unsigned int uiPort);

string WTF_GetWebFileVersion(string strObjItem,string strsite, string strSub, int nPort)
{
	Json::Value item;

	string strRet = "";

	strRet = HttpGet(strsite.c_str(), strSub.c_str(),nPort);

	item["msg"] = strRet;
	item["success"] = TRUE;
	item["sec_level"] = TYPE_SEC_NORMAL;

err:

	return item.toStyledString();

}