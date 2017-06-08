#include "smb_cs.h"
#include "smb_dev.h"
#include "smb_qtui.h"
#include "EBankSystemDetect.h"
#include "json/json.h"
#include "smcert.h"
#include "common.h"
#include <string>
#include "modp_b64.h"
#include "FILE_LOG.h"
#include <list>
#include "encode_switch.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <map>
#include <setupapi.h>
#include <algorithm>
#include "TimeAPI.h"

#define REGIST_CERT_AFTER_READ_CERT
#define RE_HANDLE_AFTER_REGIST_CERT

using namespace std;

std::string g_CurrentCerts;

//USB\VID_14D6&PID_3032\5&376ABA2D&0&9
//USB\VID_14D6&PID_3002\5&376ABA2D&0&5

int CollectUSBInfo(int * piCount, char * pVID, char * pPID)
{  

#if defined(MIX_SHUNDE_BANK)
	int i = -1;
	int count = 0;
	// 获取当前系统所有使用的设备  
	DWORD dwFlag = (DIGCF_ALLCLASSES | DIGCF_PRESENT);  
	HDEVINFO hDevInfo = SetupDiGetClassDevs(NULL, NULL, NULL, dwFlag);  
	if( INVALID_HANDLE_VALUE == hDevInfo )  
	{   
		return -1;  
	}  

	// 准备遍历所有设备查找USB  
	SP_DEVINFO_DATA sDevInfoData;  
	sDevInfoData.cbSize = sizeof(SP_DEVINFO_DATA);   
	std::string strText;  
	TCHAR szDIS[MAX_PATH]; // Device Identification Strings,   
	DWORD nSize = 0 ;  
	for(int i = 0; SetupDiEnumDeviceInfo(hDevInfo,i,&sDevInfoData); i++ )  
	{  
		nSize = 0;  
		if ( !SetupDiGetDeviceInstanceId(hDevInfo, &sDevInfoData, szDIS, sizeof(szDIS), &nSize) )  
		{  
			goto err;
		}  

		// 设备识别串的前三个字符是否是"USB", 模板： USB\VID_XXXX&PID_XXXX\00000xxxxxxx  
		std::string strDIS( szDIS );  

		transform(strDIS.begin(),strDIS.end(),strDIS.begin(),toupper);

		if(strDIS.substr( 0,3 ) == std::string("USB") )  
		{ 
			count++;
		}  
	}  

	*piCount = count;

err:

	// 释放设备  
	SetupDiDestroyDeviceInfoList(hDevInfo);  

	return 0;

#elif defined(MIX_JILIN_BANK)
	int i = -1;
	int count = 0;
	// 获取当前系统所有使用的设备  
	DWORD dwFlag = (DIGCF_ALLCLASSES | DIGCF_PRESENT);  
	HDEVINFO hDevInfo = SetupDiGetClassDevs(NULL, NULL, NULL, dwFlag);  
	if( INVALID_HANDLE_VALUE == hDevInfo )  
	{   
		return -1;  
	}  

	// 准备遍历所有设备查找USB  
	SP_DEVINFO_DATA sDevInfoData;  
	sDevInfoData.cbSize = sizeof(SP_DEVINFO_DATA);   
	std::string strText;  
	TCHAR szDIS[MAX_PATH]; // Device Identification Strings,   
	DWORD nSize = 0 ;  
	for(int i = 0; SetupDiEnumDeviceInfo(hDevInfo,i,&sDevInfoData); i++ )  
	{  
		nSize = 0;  
		if ( !SetupDiGetDeviceInstanceId(hDevInfo, &sDevInfoData, szDIS, sizeof(szDIS), &nSize) )  
		{  
			goto err;
		}  

		// 设备识别串的前三个字符是否是"USB", 模板： USB\VID_XXXX&PID_XXXX\00000xxxxxxx  
		std::string strDIS( szDIS );  

		transform(strDIS.begin(),strDIS.end(),strDIS.begin(),toupper);

		if(strDIS.substr( 0,3 ) == std::string("USB") )  
		{ 
			count++;
		}  
	}  

	*piCount = count;

err:

	// 释放设备  
	SetupDiDestroyDeviceInfoList(hDevInfo);  

	return 0;
#else
	int i = -1;
	int count = 0;
	// 获取当前系统所有使用的设备  
	DWORD dwFlag = (DIGCF_ALLCLASSES | DIGCF_PRESENT);  
	HDEVINFO hDevInfo = SetupDiGetClassDevs(NULL, NULL, NULL, dwFlag);  
	if( INVALID_HANDLE_VALUE == hDevInfo )  
	{   
		return -1;  
	}  

	// 准备遍历所有设备查找USB  
	SP_DEVINFO_DATA sDevInfoData;  
	sDevInfoData.cbSize = sizeof(SP_DEVINFO_DATA);   
	std::string strText;  
	TCHAR szDIS[MAX_PATH]; // Device Identification Strings,   
	DWORD nSize = 0 ;  
	for(int i = 0; SetupDiEnumDeviceInfo(hDevInfo,i,&sDevInfoData); i++ )  
	{  
		nSize = 0;  
		if ( !SetupDiGetDeviceInstanceId(hDevInfo, &sDevInfoData, szDIS, sizeof(szDIS), &nSize) )  
		{  
			goto err;
		}  

		// 设备识别串的前三个字符是否是"USB", 模板： USB\VID_XXXX&PID_XXXX\00000xxxxxxx  
		std::string strDIS( szDIS );  

		transform(strDIS.begin(),strDIS.end(),strDIS.begin(),toupper);

		if(strDIS.substr( 0,3 ) == std::string("USB") )  
		{  
			strText += strDIS;  
			strText += _T("\r\n");  
			int iVID_Pos = strstr(strDIS.c_str(),pVID) - strDIS.c_str();  
			if( iVID_Pos == 8 )  
			{  
				// VID: 厂商号  
				//printf( NIKON_ID  );  
				//printf( "\n");  
				// PID :产品号  
				int iSlashPos = 0;

				for (const char * p = strDIS.c_str() + strDIS.size();p > strDIS.c_str(); p--)
				{
					if (*p == '\\')
					{
						iSlashPos = p - strDIS.c_str();
						break;
					}
				}

				int iPID_Pos = strstr(strDIS.c_str(),"PID_") - strDIS.c_str();
				std::string strProductID = strDIS.substr( iPID_Pos+4, iSlashPos - iPID_Pos - 4 );  

				if(std::string(pPID) == strProductID)
				{
					count++;
				}

				// 序列号  
				int iRight = strDIS.size() - iSlashPos  -1;  
				std::string strSerialNumber = strDIS.substr(iSlashPos+1 ,iRight );  

			}  
		}  
	}  

	*piCount = count;

err:

	// 释放设备  
	SetupDiDestroyDeviceInfoList(hDevInfo);  

	return 0;
#endif
	
}

//95568非国密：

//VID_14D6&PID_1004；

//VID_14D6&PID_1006；

//VID_14D6&PID_3002

//0305X4国密：

//VID_14D6&PID_3032（一代）

//VID_14D6&PID_3732（蓝牙二代）

int cspKeyCount = 0;
int skfKeyCount = 0;

int GetCMBCKeyCount(int *piCount)
{

#if defined(MIX_SHUNDE_BANK)
	int tmpCount = 0;
	int count = 0;

	CollectUSBInfo(&tmpCount, "14D6", "1004");

	count += tmpCount;

	*piCount = count;

	return 0;
#elif defined(MIX_JILIN_BANK)
	int tmpCount = 0;
	int count = 0;

	CollectUSBInfo(&tmpCount, "14D6", "1004");

	count += tmpCount;

	*piCount = count;

	return 0;
#else
	int tmpCount = 0;

	int count = 0;

	cspKeyCount = 0;
	skfKeyCount = 0;

	CollectUSBInfo(&tmpCount, "14D6", "1004");

	count += tmpCount;
	cspKeyCount += tmpCount;

	CollectUSBInfo(&tmpCount, "14D6", "1006");

	count += tmpCount;
	cspKeyCount += tmpCount;

	CollectUSBInfo(&tmpCount, "14D6", "3002");

	count += tmpCount;
	cspKeyCount += tmpCount;

	CollectUSBInfo(&tmpCount, "14D6", "3032");

	count += tmpCount;
	skfKeyCount += tmpCount;

	CollectUSBInfo(&tmpCount, "14D6", "3732");

	count += tmpCount;
	skfKeyCount += tmpCount;

	*piCount = count;

	return 0;
#endif

}
std::string WTF_GetCurrentCerts(int Expire);
string WTF_GetDevAllCerts(const char * pszDevName, int Expire){
	return WTF_GetCurrentCerts(Expire);
}

string WTF_GetAllDevs()
{
	Json::Value values;

	void * data_value = NULL;
	unsigned int data_len = 0;
	SK_CERT_CONTENT * pCertContent = NULL;
	int i = 0;
	unsigned int ulRet;

	DEVINFO * pDevInfo = (DEVINFO*)malloc(sizeof(DEVINFO) + 8);

	data_value = malloc(BUFFER_LEN_1K * BUFFER_LEN_1K);
	data_len = BUFFER_LEN_1K * BUFFER_LEN_1K;

	ulRet = WTF_EnumCert(NULL, data_value, &data_len,
		CERT_ALG_SM2_FLAG, // SM2
		CERT_SIGN_FLAG, // 签名
		CERT_VERIFY_TIME_FLAG ,// 验证有效期
		CERT_FILTER_FLAG_FALSE);

	if (ulRet)
	{

	}
	else
	{
		for (pCertContent = (SK_CERT_CONTENT *)data_value;(char *)pCertContent < (char *)data_value + data_len;pCertContent=(SK_CERT_CONTENT*)((BYTE *)pCertContent+pCertContent->nValueLen+sizeof(SK_CERT_CONTENT)) )
		{
			Json::Value item;

			// name重命名  ---->nickName
			item["devNickName"] = pCertContent->stProperty.szCommonName;

			memset(pDevInfo, 0, sizeof(DEVINFO));

			WTF_GetDevInfoByCertProperty(&(pCertContent->stProperty),pDevInfo);

			item["versionMajor"] = pDevInfo->Version.major;
			item["versionMinor"] = pDevInfo->Version.minor;

			item["manufacturer"] = pDevInfo->Manufacturer;
			item["issuer"] = pDevInfo->Issuer;
			item["label"] = pDevInfo->Label;
			item["serialNumber"] = pDevInfo->SerialNumber;

			item["hwVersionMajor"] = pDevInfo->HWVersion.major;
			item["hwVersionMinor"] = pDevInfo->HWVersion.minor;

			item["firmwareVersionMajor"] = pDevInfo->FirmwareVersion.major;
			item["firmwareVersionMinor"] = pDevInfo->FirmwareVersion.minor;

			item["algSymCap"] = (int)pDevInfo->AlgSymCap;
			item["algAsymCap"] = (int)pDevInfo->AlgAsymCap;
			item["algHashCap"] = (int)pDevInfo->AlgHashCap;
			item["devAuthAlgId"] = (int)pDevInfo->DevAuthAlgId;
			item["totalSpace"] = (int)pDevInfo->TotalSpace;
			item["freeSpace"] = (int)pDevInfo->FreeSpace;

			// 以后会修改对应的代码以适应项目调整
			if(1)
			{
				WCHAR * manufacturer = NULL;

				if (0 == memcmp(pDevInfo->Manufacturer,"HB",strlen(pDevInfo->Manufacturer)) || 0 == memcmp(pDevInfo->Manufacturer,"HB",strlen(pDevInfo->Manufacturer)))
				{
					manufacturer = L"恒宝股份";
				}
				else if(0 == memcmp(pDevInfo->Manufacturer,"WD",strlen(pDevInfo->Manufacturer)) || 0 == memcmp(pDevInfo->Manufacturer,"WD",strlen(pDevInfo->Manufacturer)))
				{
					//manufacturer= L"握奇";
					manufacturer= L"民生U宝";
				}
				else if(0 == memcmp(pDevInfo->Manufacturer,"FT",strlen(pDevInfo->Manufacturer)) || 0 == memcmp(pDevInfo->Manufacturer,"FT",strlen(pDevInfo->Manufacturer)))
				{
					manufacturer = L"飞天诚信";
				}
				else
				{
					manufacturer = L"其他";
				}

				item["manufacturer"] = utf8_encode(manufacturer);
			}

			values.append(item);
		}
	}

	free(data_value);

	if (pDevInfo)
	{
		free(pDevInfo);
	}

	return values.toStyledString();
}

string WTF_GetDevSignCert(const char * pszDevName)
{
	Json::Value values;
	
	void * data_value = NULL;
	unsigned int data_len = 0;
	SK_CERT_CONTENT * pCertContent = NULL;
	int i = 0;
	unsigned int ulRet;

	DEVINFO * pDevInfo = (DEVINFO*)malloc(sizeof(DEVINFO) + 8);

	data_value = malloc(BUFFER_LEN_1K * BUFFER_LEN_1K);
	data_len = BUFFER_LEN_1K * BUFFER_LEN_1K;

	ulRet = WTF_EnumCert(pszDevName, data_value, &data_len,
		CERT_ALG_SM2_FLAG, // SM2
		CERT_SIGN_FLAG, // 签名
		CERT_VERIFY_TIME_FLAG ,// 验证有效期
		CERT_FILTER_FLAG_FALSE);

	if (ulRet)
	{

	}
	else
	{
		for (pCertContent = (SK_CERT_CONTENT *)data_value;(char *)pCertContent < (char *)data_value + data_len;pCertContent=(SK_CERT_CONTENT*)((BYTE *)pCertContent+pCertContent->nValueLen+sizeof(SK_CERT_CONTENT)) )
		{
			Json::Value item;

			// name重命名  ---->nickName
			item["devNickName"] = pCertContent->stProperty.szCommonName;

			memset(pDevInfo, 0, sizeof(DEVINFO));

			WTF_GetDevInfoByCertProperty(&(pCertContent->stProperty),pDevInfo);

			item["versionMajor"] = pDevInfo->Version.major;
			item["versionMinor"] = pDevInfo->Version.minor;

			item["manufacturer"] = pDevInfo->Manufacturer;
			item["issuer"] = pDevInfo->Issuer;
			item["label"] = pDevInfo->Label;
			item["serialNumber"] = pDevInfo->SerialNumber;

			item["hwVersionMajor"] = pDevInfo->HWVersion.major;
			item["hwVersionMinor"] = pDevInfo->HWVersion.minor;

			item["firmwareVersionMajor"] = pDevInfo->FirmwareVersion.major;
			item["firmwareVersionMinor"] = pDevInfo->FirmwareVersion.minor;

			item["algSymCap"] = (int)pDevInfo->AlgSymCap;
			item["algAsymCap"] = (int)pDevInfo->AlgAsymCap;
			item["algHashCap"] = (int)pDevInfo->AlgHashCap;
			item["devAuthAlgId"] = (int)pDevInfo->DevAuthAlgId;
			item["totalSpace"] = (int)pDevInfo->TotalSpace;
			item["freeSpace"] = (int)pDevInfo->FreeSpace;

			if (0 == pCertContent->stProperty.ulVerify)
			{
				unsigned long long timeLocal = 0;
				unsigned long long daysLeft = 0;

				GetLocalTime_T(&timeLocal);

				daysLeft = (pCertContent->stProperty.ulNotAfter - timeLocal)/24/60/60;

				if (daysLeft < 30)
				{
					std::wostringstream oss; 

					oss<< L"证书还有";

					oss<<(int)daysLeft;

					oss<< L"天过期，请进行证书更新！";

					item["expire_msg"] = utf8_encode(oss.str()); 
					item["expiration_status"] = EXPIRATION_STATUS_LEFT_IN_EXPIRE;
				}
				else
				{
					item["expire_msg"] = utf8_encode(L"证书有效！");
					item["expiration_status"] = EXPIRATION_STATUS_IN;
				}
			}
			else
			{
				item["expire_msg"] =  utf8_encode(L"证书不在有效期！");
				item["expiration_status"] = EXPIRATION_STATUS_OUT;
			}

			// 以后会修改对应的代码以适应项目调整
			if(1)
			{
				WCHAR * manufacturer = NULL;

				if (0 == memcmp(pDevInfo->Manufacturer,"HB",strlen(pDevInfo->Manufacturer)) || 0 == memcmp(pDevInfo->Manufacturer,"HB",strlen(pDevInfo->Manufacturer)))
				{
					manufacturer = L"恒宝股份";
				}
				else if(0 == memcmp(pDevInfo->Manufacturer,"WD",strlen(pDevInfo->Manufacturer)) || 0 == memcmp(pDevInfo->Manufacturer,"WD",strlen(pDevInfo->Manufacturer)))
				{
					//manufacturer= L"握奇";
					manufacturer= L"民生U宝";
				}
				else if(0 == memcmp(pDevInfo->Manufacturer,"FT",strlen(pDevInfo->Manufacturer)) || 0 == memcmp(pDevInfo->Manufacturer,"FT",strlen(pDevInfo->Manufacturer)))
				{
					manufacturer = L"飞天诚信";
				}
				else
				{
					manufacturer = L"其他";
				}

				item["manufacturer"] = utf8_encode(manufacturer);
			}

			// b64 fomat encode certcontent
			{
				const char * data_value_in = (const char *)pCertContent;
				size_t data_len_in = sizeof(SK_CERT_CONTENT) + pCertContent->nValueLen;

				size_t data_len_out = modp_b64_encode_len(data_len_in);
				char * data_value_out = (char * )malloc(data_len_out);

				memset(data_value_out, 0, data_len_out);

				data_len_out = modp_b64_encode(data_value_out,data_value_in, data_len_in);

				item["certContentB64String"] = data_value_out;

				free(data_value_out);
			}

			values.append(item);

			//last_ukey_number++;
		}
	}
	

	

	free(data_value);

	if (pDevInfo)
	{
		free(pDevInfo);
	}

	return values.toStyledString();
}

#include <sstream>

string WTF_ChangeDevPassword(const std::string strDevName,const std::string strOldPassword, const std::string strNewPassword){
	unsigned int ulRetry = 0;
	unsigned int ulRet = ::WTF_ChangePIN(strDevName.c_str(), 1, strOldPassword.c_str(), strNewPassword.c_str(), &ulRetry);

	std::wstringstream msg;
	if (ulRet){
		msg << L"修改密码失败，剩余次数:" << ulRetry;
	} 
	else {
		msg << L"修改密码成功！";
	}

	Json::Value result;

	result["success"] = ulRet?FALSE:TRUE;
	result["msg"] = utf8_encode(msg.str());
	result["retryCount"] = ulRetry;

	return result.toStyledString();
}

string WTF_VerifyDevPassword(const std::string strDevName,const std::string strPassword){
	unsigned int ulRetry = 0;
	unsigned int ulRet = ::WTF_VerifyPIN(strDevName.c_str(), 1, strPassword.c_str(), &ulRetry);

	std::wstringstream msg;
	if (ulRet){
		msg << L"验证密码失败，剩余次数:" << ulRetry;
	} 
	else {
		msg << L"验证密码成功！";
	}

	Json::Value result;

	result["success"] = ulRet?FALSE:TRUE;
	result["msg"] = utf8_encode(msg.str());
	result["retryCount"] = ulRetry;

	return result.toStyledString();
}

string WTF_ChangeDevPasswordBySignCertPropB64(const std::string strSignCertPropB64,const std::string strOldPassword, const std::string strNewPassword){
	
	unsigned int ulRetry = 0;
	unsigned int ulRet = 0;

	SK_CERT_DESC_PROPERTY * pCertProp = NULL;

	// b64 fomat decode certcontent

	const char * data_value_in = (const char *)strSignCertPropB64.c_str();
	size_t data_len_in = strlen(strSignCertPropB64.c_str());

	size_t data_len_out = modp_b64_decode_len(data_len_in);
	char * data_value_out = (char * )malloc(data_len_out);

	memset(data_value_out, 0, data_len_out);

	data_len_out = modp_b64_decode(data_value_out,data_value_in, data_len_in);

	pCertProp = (SK_CERT_DESC_PROPERTY *)data_value_out;
	
	ulRet = ::WTF_ChangePINByCertProperty(pCertProp, 1, strOldPassword.c_str(), strNewPassword.c_str(), &ulRetry);

	std::wstringstream msg;
	if (ulRet){
		msg << L"修改密码失败，剩余次数:" << ulRetry;
	} 
	else {
		msg << L"修改密码成功！";
	}

	Json::Value result;

	result["success"] = ulRet?FALSE:TRUE;
	result["msg"] = utf8_encode(msg.str());
	result["retryCount"] = ulRetry;

	if (pCertProp)
	{
		free(pCertProp);
	}

	return result.toStyledString();
}

string WTF_VerifyDevPasswordBySignCertPropB64(const std::string strSignCertPropB64,const std::string strPassword){

	unsigned int ulRetry = 0;
	unsigned int ulRet = 0;

	SK_CERT_DESC_PROPERTY * pCertProp = NULL;

	// b64 fomat decode certcontent

	const char * data_value_in = (const char *)strSignCertPropB64.c_str();
	size_t data_len_in = strlen(strSignCertPropB64.c_str());

	size_t data_len_out = modp_b64_decode_len(data_len_in);
	char * data_value_out = (char * )malloc(data_len_out);

	memset(data_value_out, 0, data_len_out);

	data_len_out = modp_b64_decode(data_value_out,data_value_in, data_len_in);

	pCertProp = (SK_CERT_DESC_PROPERTY *)data_value_out;

	ulRet = ::WTF_VerifyPINByCertProperty(pCertProp, 1, strPassword.c_str(), &ulRetry);

	std::wstringstream msg;
	if (ulRet){
		msg << L"验证密码失败，剩余次数:" << ulRetry;
	} 
	else {
		msg << L"验证密码成功！";
	}

	Json::Value result;

	result["success"] = ulRet?FALSE:TRUE;
	result["msg"] = utf8_encode(msg.str());
	result["retryCount"] = ulRetry;

	if (pCertProp)
	{
		free(pCertProp);
	}

	return result.toStyledString();
}

string WTF_VerifyDevPasswordBySignCertPropB64(const std::string strSignCertPropB64,CallBackCfcaGetEncryptPIN GetEncryptPIN, void * pArgs){

	unsigned int ulRetry = 0;
	unsigned int ulRet = 0;

	SK_CERT_DESC_PROPERTY * pCertProp = NULL;

	// b64 fomat decode certcontent

	const char * data_value_in = (const char *)strSignCertPropB64.c_str();
	size_t data_len_in = strlen(strSignCertPropB64.c_str());

	size_t data_len_out = modp_b64_decode_len(data_len_in);
	char * data_value_out = (char * )malloc(data_len_out);

	memset(data_value_out, 0, data_len_out);

	data_len_out = modp_b64_decode(data_value_out,data_value_in, data_len_in);

	pCertProp = (SK_CERT_DESC_PROPERTY *)data_value_out;

	ulRet = 0; //::WTF_VerifyPINByCertPropertyForHengBao(pCertProp, 1, GetEncryptPIN, pArgs, &ulRetry);

	std::wstringstream msg;
	if (ulRet){
		msg << L"验证密码失败，剩余次数:" << ulRetry;
	} 
	else {
		msg << L"验证密码成功！";
	}

	Json::Value result;

	result["success"] = ulRet?FALSE:TRUE;
	result["msg"] = utf8_encode(msg.str());
	result["retryCount"] = ulRetry;
	result["ulRet"] = ulRet;

	if (pCertProp)
	{
		free(pCertProp);
	}

	return result.toStyledString();
}

extern unsigned int __stdcall UI_ShowCert(SK_CERT_CONTENT * pCertContent);

string WTF_ShowCert(const std::string strCertContentB64)
{
	unsigned int ulRetry = 0;
	unsigned int ulRet = 0;

	SK_CERT_CONTENT * pCertContent = NULL;

	// b64 fomat decode certcontent

	const char * data_value_in = (const char *)strCertContentB64.c_str();
	size_t data_len_in = strlen(strCertContentB64.c_str());

	size_t data_len_out = modp_b64_decode_len(data_len_in);
	char * data_value_out = (char * )malloc(data_len_out);

	memset(data_value_out, 0, data_len_out);

	data_len_out = modp_b64_decode(data_value_out,data_value_in, data_len_in);

	pCertContent = (SK_CERT_CONTENT *)data_value_out;

	switch(pCertContent->stProperty.nType)
	{
		case CERT_ALG_RSA_FLAG:
			WTF_UIDlgViewContext((BYTE *)pCertContent+sizeof(SK_CERT_CONTENT),pCertContent->nValueLen);
			break;
		case CERT_ALG_SM2_FLAG:
			UI_ShowCert(pCertContent);
			break;
		default:
			break;
	}

	Json::Value result;

	result["success"] = ulRet?FALSE:TRUE;
	result["msg"] = "";

	if (pCertContent)
	{
		free(pCertContent);
	}

	return result.toStyledString();
}

string WTF_ListSKFDriver(list<string> strSKFList)
{
	unsigned int ulRet = 0;

	list<string>::iterator i;

	Json::Value values;

	char version[64] = {0};

	BOOL bCspDriver = FALSE;

#if 1        // for cmbc
	if (0 < cspKeyCount)
	{
		Json::Value value;
		Json::Reader reader;

		BOOL bFlag = reader.parse(g_CurrentCerts, value);

		if (bFlag)
		{
			if (value.isArray())
			{
				int i = 0;
				bCspDriver = FALSE;
				for (i;!value[i].isNull(); i++)
				{
					if (value[i]["devFrom"] == "csp")
					{
						bCspDriver = TRUE;
						break;
					}
				}
			}
			else
			{
				bCspDriver = TRUE;
			}
		}	
		else
		{
			bCspDriver = TRUE;
		}
	}
	else
	{
		bCspDriver = TRUE;
	}

#endif

	for (i = strSKFList.begin(); i != strSKFList.end(); ++i)
	{
		Json::Value item;

		memset(version,0, 64);

		ulRet = WTF_FindSKFDriver(i->c_str(),version);

		item["skf_name"] = *i;
		item["skf_state"] = ulRet? FALSE:TRUE;

		if(FALSE == bCspDriver)
		{
			item["skf_state"] = bCspDriver;
		}

		item["skf_version"] = version;

		values.append(item);
	}




	return values.toStyledString();
}

extern "C" unsigned long OPF_Str2Bin(const char *ain_data_value,unsigned long ain_data_len,unsigned char *aout_data_value,unsigned long * aout_data_len);

// 证书使用者密钥标示
string WTF_CheckCertChain(list<string> strListRootCertKeyIDHex, unsigned int ulFlag, unsigned int ulAlgType)
{
	unsigned int ulRet = 0;
	unsigned int ulOutLen = 0;
	CERT_PUBLIC_KEY_INFO certPublicKeyInfo = {0};
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT certContext_CA = NULL;
	list<string>::iterator i;
	unsigned char data_value_keyid[BUFFER_LEN_1K] = {0};
	unsigned long data_len_keyid = BUFFER_LEN_1K;

	CERT_ID id;

	Json::Value item;

	for(i = strListRootCertKeyIDHex.begin();  i != strListRootCertKeyIDHex.end(); ++i)
	{
		std::string strRootCertKeyIDHex = i->c_str();

		id.dwIdChoice = CERT_ID_KEY_IDENTIFIER;
		OPF_Str2Bin(strRootCertKeyIDHex.c_str(),strRootCertKeyIDHex.size(), data_value_keyid,&data_len_keyid);
		id.KeyId.pbData = data_value_keyid;
		id.KeyId.cbData = data_len_keyid;

		item["chain_root_state"] = "not found";
		item["sec_level"] = TYPE_SEC_EXCEPT;
		item["success"] = FALSE;

		// 创建存储区
		ulRet = SMC_CertCreateSMCStores();

		if(TRUE != ulRet)
		{
			ulRet = EErr_SMC_CREATE_STORE;
			goto err;
		}

		switch(ulAlgType)
		{
		case CERT_ALG_RSA_FLAG:
			{
				// Other common system stores include "Root", "Trust", and "Ca".
				// 打开存储�?		
				hCertStore = CertOpenStore(
					CERT_STORE_PROV_SYSTEM,          // The store provider type
					0,                               // The encoding type is
					// not needed
					NULL,                            // Use the default HCRYPTPROV
					CERT_SYSTEM_STORE_CURRENT_USER,  // Set the store location in a
					// registry location
					L"Ca"                            // The store name as a Unicode 
					// string
					);
			}
			break;
		case CERT_ALG_SM2_FLAG:
			{
				// 打开存储区
				hCertStore = SMC_CertOpenStore(0,CERT_SYSTEM_STORE_CURRENT_USER, DEFAULT_SMC_STORE_SM2_ROOT_ID);
			}
			break;
		default:
			break;
		}

		if (NULL == hCertStore)
		{
			ulRet = EErr_SMC_OPEN_STORE;
			goto err;
		}

		switch(ulAlgType)
		{
		case CERT_ALG_RSA_FLAG:
			{	
				certContext_CA = CertFindCertificateInStore(hCertStore,X509_ASN_ENCODING,0,CERT_FIND_CERT_ID,&id,NULL);
			}
			break;
		case CERT_ALG_SM2_FLAG:
			{
				certContext_CA = SMC_CertFindCertificateInStore(hCertStore,X509_ASN_ENCODING,CERT_FIND_CERT_ID,&id,NULL);
			}
			break;
		default:
			break;
		}

		if (NULL == certContext_CA)
		{
			ulRet = EErr_SMC_NO_CERT_CHAIN;
			goto err;
		}

		if (ulFlag)
		{
			// 验证	CA
			ulRet = WTF_VerifyCert(ulFlag,ulAlgType,certContext_CA->pbCertEncoded, certContext_CA->cbCertEncoded);

			if (ulRet)
			{
				item["chain_root_state"] = "verify fail";
			}
			else
			{
				item["chain_root_state"] = "success";
				item["sec_level"] = TYPE_SEC_NORMAL;
				item["success"] = TRUE;
			}

		}
	}
err:
	// 释放上下文
	if(certContext_CA)
	{
		SMC_CertFreeCertificateContext(certContext_CA);
	}

	if (hCertStore)
	{
		// 关闭存储区
		::SMC_CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
	}

	return item.toStyledString();
}

string WTF_InstallCaCert(list<string> strListCaCertPath, int ulFlag)
{
	// 读取本地证书并导入根证书
	
	unsigned char pbCaCert[BUFFER_LEN_1K * 4] = {0};
	unsigned int ulCaCertLen = BUFFER_LEN_1K * 4;
	unsigned int ulRet = 0;
	Json::Value item;
	unsigned int ulAlgType;
	list<string>::iterator i;

	for (i = strListCaCertPath.begin(); i != strListCaCertPath.end(); ++i)
	{
		std::fstream _file;

		item["success"] = FALSE;
		item["flag"] = ulFlag;

		item["file_path"] = i->c_str();

		_file.open(i->c_str(),ios::binary | ios::in);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,i->c_str());

		if(_file)
		{
			std::ios::pos_type length;

			// get length of file:
			_file.seekg (0, ios::end);
			length = _file.tellg();
			_file.seekg (0, ios::beg);

			// read data as a block:
			_file.read ((char *)pbCaCert,length);
			_file.close();

			FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"ulCaCertLen");
			FILE_LOG_FMT(file_log_name, "%s %d %d", __FUNCTION__, __LINE__,ulCaCertLen);

			ulRet = WTF_ImportCaCert(pbCaCert, ulCaCertLen, & ulAlgType);

			item["success"] = ulRet ? FALSE:TRUE;
			item["algType"] = ulAlgType;

			if(0 == ulRet)
			{
				item["msg"] = ulAlgType==CERT_ALG_SM2_FLAG? utf8_encode(L"安装SM2证书文件成功"):utf8_encode(L"安装RSA证书文件成功");
			}
			else  if (EErr_SMC_NO_RIGHT == ulRet)
			{
				item["msg"] = utf8_encode(L"未取得安装证书权限");
				goto err;
			}
			else
			{
				item["msg"] = utf8_encode(L"安装证书文件失败，请卸载后重新安装客户端");
				goto err;
			}

		}
		else
		{
			item["success"] = FALSE;
			item["msg"] = utf8_encode(L"证书文件不存在，请卸载后重新安装客户端");
			goto err;
		}
	}

err:
	return item.toStyledString();
}


std::string WTF_ReadCurrentCerts(int Expire)
{
#if defined(MIX_SHUNDE_BANK)
	Json::Value All = Json::Value(Json::arrayValue);

	// 通过设备获取证书
	void * data_value = NULL;
	unsigned int data_len = 0;
	SK_CERT_CONTENT * pCertContent = NULL;
	int i = 0;

	DWORD       cbName;  
	DWORD       dwType;  
	DWORD       dwIndex=0;  
	char        pszName[BUFFER_LEN_1K];   
	
	while(CryptEnumProviders(  
		dwIndex,     // in -- dwIndex  
		NULL,        // in -- pdwReserved- set to NULL  
		0,           // in -- dwFlags -- set to zero  
		&dwType,     // out -- pdwProvType  
		NULL,        // out -- pszProvName -- NULL on the first call  
		&cbName      // in, out -- pcbProvName  
		))  
	{  
		//--------------------------------------------------------------------  
		//  Get the provider name.  

		if (CryptEnumProviders(  
			dwIndex++,  
			NULL,  
			0,  
			&dwType,  
			pszName,  
			&cbName     // pcbProvName -- size of pszName  
			))  
		{  
			HCRYPTPROV	hCryptProv = NULL;

			DWORD dwErrCode = 0;

			if (!CryptAcquireContext(&hCryptProv, NULL,
				pszName, PROV_RSA_FULL, CRYPT_SILENT))
			{
				dwErrCode = GetLastError();
			}
			else
			{
				HCRYPTKEY hKey = NULL;
				DWORD dwKeyType = AT_KEYEXCHANGE;

				//DWORD dwKeyType = AT_SIGNATURE;

				for (; dwKeyType <= AT_SIGNATURE; dwKeyType++)
				{
					// 获取容器中的密钥
					if (!CryptGetUserKey(hCryptProv, dwKeyType, &hKey))
					{
						dwErrCode = GetLastError();

						if (NTE_BAD_KEY == dwErrCode)
						{
							continue;
						}
						else
						{
							continue;
						}
					}

					ULONG ulCertLen = 4096;
					// 导出容器中的证书
					if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &ulCertLen, 0))
					{
						dwErrCode = GetLastError();

						// 销毁密钥句柄
						CryptDestroyKey(hKey);
						continue;
					}
					else
					{
						if(AT_KEYEXCHANGE == dwKeyType)
						{

						}
						else
						{

						}

						char * szdata = new char[ulCertLen];
						memset(szdata, 0, ulCertLen);
						BOOL bFlag = CryptGetKeyParam(hKey, KP_CERTIFICATE, (BYTE *)szdata, &ulCertLen, 0);
						if (!bFlag)
						{
							dwErrCode = GetLastError();

						}

						// add to list as usb_old
						{
							Json::Value itemDev;
							Json::Value itemDevInfo;
							Json::Value itemDevCerts = Json::Value(Json::arrayValue); // 1 device's certs
							Json::Value item;
							char data_info_value[1024] = {0};
							int data_info_len = 0;

							// 证书的属性
							WT_SetMyCert((unsigned char *)szdata,ulCertLen);

							memset(data_info_value, 0, 1024);
							WT_GetCertInfo(CERT_SERIALNUMBER, 0, data_info_value, &data_info_len);
							item["serialNumber"] = data_info_value;

							memset(data_info_value, 0, 1024);
							WT_GetCertInfo(CERT_ISSUER_DN, NID_COMMONNAME, data_info_value, &data_info_len);
							item["issuer"] = data_info_value;

							memset(data_info_value, 0, 1024);
							WT_GetCertInfo(CERT_SUBJECT_DN, NID_COMMONNAME, data_info_value, &data_info_len);
							item["subject"] = data_info_value;

							item["commonName"] =  strstr(item["subject"].asCString(),"=")+1 == 0 ?  item["subject"]: strstr(item["subject"].asCString(),"=")+1;

							memset(data_info_value, 0, 1024);
							WT_GetCertInfo(CERT_NOTBEFORE, 0, data_info_value, &data_info_len);
							item["notBefore"] = data_info_value;

							memset(data_info_value, 0, 1024);
							WT_GetCertInfo(CERT_NOTAFTER, 0, data_info_value, &data_info_len);
							item["notAfter"] = data_info_value;

							item["signType"] = TRUE; // 签名

							switch(WTF_VerifyCert(CERT_VERIFY_TIME_FLAG | CERT_VERIFY_CHAIN_FLAG | CERT_VERIFY_CRL_FLAG,CERT_ALG_RSA_FLAG,(unsigned char *)szdata,ulCertLen)){
							case 0:
								item["verify"] = CERT_VERIFY_RESULT_FLAG_OK;   // 未校验
								break;
							case EErr_SMC_VERIFY_TIME:
								item["verify"] = CERT_VERIFY_RESULT_TIME_INVALID;
								break;
							case EErr_SMC_NO_CERT_CHAIN:
								item["verify"] = CERT_VERIFY_RESULT_CHAIN_INVALID;
								break;
							case EErr_SMC_VERIFY_CERT:
								item["verify"] = CERT_VERIFY_RESULT_SIGN_INVALID;	
								break;
							default:
								item["verify"] = CERT_VERIFY_RESULT_CHAIN_INVALID;
								break;
							}

							item["type"] = CERT_ALG_RSA_FLAG;     // RSA

							WT_ClearCert();

							// b64 fomat encode certcontent
							{
								char * data_value_in = (char * )malloc(sizeof(SK_CERT_CONTENT) + ulCertLen);
								size_t data_len_in = sizeof(SK_CERT_CONTENT) + ulCertLen;

								size_t data_len_out = modp_b64_encode_len(data_len_in);
								char * data_value_out = (char * )malloc(data_len_out);

								((SK_CERT_CONTENT*)data_value_in)->stProperty.nType = 1; // RSA
								((SK_CERT_CONTENT*)data_value_in)->nValueLen = ulCertLen;
								memcpy(data_value_in+sizeof(SK_CERT_CONTENT),szdata,ulCertLen);

								memset(data_value_out, 0, data_len_out);

								data_len_out = modp_b64_encode(data_value_out,data_value_in, data_len_in);

								item["certContentB64String"] = data_value_out;

								free(data_value_out);
								free(data_value_in);
							}

							itemDevInfo["devNickName"] = item["commonName"];
							itemDevInfo["devFrom"] = "csp";
							itemDevInfo["serialNumber"] = "unknow";

							itemDevCerts.append(item); 
							itemDev = itemDevInfo;
							itemDev["certs"] = itemDevCerts;

							All.append(itemDev);
						}

						delete szdata;

						// 销毁密钥句柄
						CryptDestroyKey(hKey);
					}
				}

				// CryptReleaseContext
				if (!CryptReleaseContext(hCryptProv, 0))
				{
					;
				}
				else
				{

				}
			}
		}  
		else  
		{  
 
		}   

	} // End of while loop 

	//MessageBoxA(NULL,All.toStyledString().c_str(), "提示", MB_ICONEXCLAMATION|MB_YESNO);

	g_CurrentCerts = All.toStyledString();
	
	return All.toStyledString();
#elif defined(MIX_JILIN_BANK)
	Json::Value All = Json::Value(Json::arrayValue);
	const char * ptrDevOri; // 原始DEV

	// 通过设备获取证书
	void * data_value = NULL;
	unsigned int data_len = 0;
	SK_CERT_CONTENT * pCertContent = NULL;
	int i = 0;
	unsigned int ulRet;

	DEVINFO * pDevInfo = (DEVINFO*)malloc(sizeof(DEVINFO) + 8);

	data_value = malloc(BUFFER_LEN_1K * BUFFER_LEN_1K);
	data_len = BUFFER_LEN_1K * BUFFER_LEN_1K;
	
	ulRet = WTF_EnumCertInternal("JLBANKi3csp11", data_value, &data_len,
		CERT_ALG_RSA_FLAG | CERT_ALG_SM2_FLAG, // RSA SM2
		CERT_SIGN_FLAG | CERT_EX_FLAG, // 签名加密
		CERT_VERIFY_TIME_FLAG | CERT_VERIFY_CHAIN_FLAG | CERT_VERIFY_CRL_FLAG,
		CERT_FILTER_FLAG_FALSE);
	
	FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, ulRet);
	FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, data_len);

	//ulRet = WTF_EnumCert(devName, data_value, &data_len,
	//	CERT_ALG_RSA_FLAG | CERT_ALG_SM2_FLAG, // RSA SM2
	//	CERT_SIGN_FLAG | CERT_EX_FLAG, // 签名加密
	//	CERT_VERIFY_CHAIN_FLAG,
	//	CERT_FILTER_FLAG_FALSE);
	if(ulRet)
	{
		
	}
	else
	{
		for (pCertContent = (SK_CERT_CONTENT *)data_value;(char *)pCertContent < (char *)data_value + data_len;pCertContent=(SK_CERT_CONTENT*)((BYTE *)pCertContent+pCertContent->nValueLen+sizeof(SK_CERT_CONTENT)) )
		{
			Json::Value itemDev;
			Json::Value itemDevInfo;
			Json::Value itemDevCerts = Json::Value(Json::arrayValue); // 1 device's certs

			itemDevInfo["devNickName"] = pCertContent->stProperty.szCommonName;

			itemDevInfo["devFrom"] = "skf";

			memset(pDevInfo, 0, sizeof(DEVINFO));

			WTF_GetDevInfoByCertProperty(&(pCertContent->stProperty),pDevInfo);

			itemDevInfo["versionMajor"] = pDevInfo->Version.major;
			itemDevInfo["versionMinor"] = pDevInfo->Version.minor;

			itemDevInfo["manufacturer"] = pDevInfo->Manufacturer;
			itemDevInfo["issuer"] = pDevInfo->Issuer;
			itemDevInfo["label"] = pDevInfo->Label;
			itemDevInfo["serialNumber"] = pDevInfo->SerialNumber;

			itemDevInfo["hwVersionMajor"] = pDevInfo->HWVersion.major;
			itemDevInfo["hwVersionMinor"] = pDevInfo->HWVersion.minor;

			itemDevInfo["firmwareVersionMajor"] = pDevInfo->FirmwareVersion.major;
			itemDevInfo["firmwareVersionMinor"] = pDevInfo->FirmwareVersion.minor;

			itemDevInfo["algSymCap"] = (int)pDevInfo->AlgSymCap;
			itemDevInfo["algAsymCap"] = (int)pDevInfo->AlgAsymCap;
			itemDevInfo["algHashCap"] = (int)pDevInfo->AlgHashCap;
			itemDevInfo["devAuthAlgId"] = (int)pDevInfo->DevAuthAlgId;
			itemDevInfo["totalSpace"] = (int)pDevInfo->TotalSpace;
			itemDevInfo["freeSpace"] = (int)pDevInfo->FreeSpace;

			ptrDevOri = pCertContent->stProperty.szDeviceName;

			for (;(char *)pCertContent < (char *)data_value + data_len;pCertContent=(SK_CERT_CONTENT*)((BYTE *)pCertContent+pCertContent->nValueLen+sizeof(SK_CERT_CONTENT)) )
			{
				if ( 0 != strcmp(ptrDevOri,pCertContent->stProperty.szDeviceName))
				{
					break;
				}
				
				Json::Value item;

				item["skfName"] = pCertContent->stProperty.szSKFName;
				item["deviceName"] = pCertContent->stProperty.szDeviceName;
				item["applicationName"] = pCertContent->stProperty.szApplicationName;
				item["containerName"] = pCertContent->stProperty.szContainerName;

				// 证书的属性
				char data_info_value[1024] = {0};
				int data_info_len = 0;

				WT_SetMyCert(pCertContent->pbValue,pCertContent->nValueLen);

				memset(data_info_value, 0, 1024);
				WT_GetCertInfo(CERT_SERIALNUMBER, 0, data_info_value, &data_info_len);
				item["serialNumber"] = data_info_value;

				memset(data_info_value, 0, 1024);
				WT_GetCertInfo(CERT_ISSUER_DN, NID_COMMONNAME, data_info_value, &data_info_len);
				item["issuer"] = data_info_value;

				memset(data_info_value, 0, 1024);
				WT_GetCertInfo(CERT_SUBJECT_DN, NID_COMMONNAME, data_info_value, &data_info_len);
				item["subject"] = data_info_value;

				item["commonName"] = pCertContent->stProperty.szCommonName;

				memset(data_info_value, 0, 1024);
				WT_GetCertInfo(CERT_NOTBEFORE, 0, data_info_value, &data_info_len);
				item["notBefore"] = data_info_value;

				memset(data_info_value, 0, 1024);
				WT_GetCertInfo(CERT_NOTAFTER, 0, data_info_value, &data_info_len);
				item["notAfter"] = data_info_value;

				item["signType"] = pCertContent->stProperty.bSignType;
				item["verify"] = pCertContent->stProperty.ulVerify;
				item["type"] = pCertContent->stProperty.nType;

				WT_ClearCert();

				// b64 fomat encode certcontent
				{
					const char * data_value_in = (const char *)pCertContent;
					size_t data_len_in = sizeof(SK_CERT_CONTENT) + pCertContent->nValueLen;

					size_t data_len_out = modp_b64_encode_len(data_len_in);
					char * data_value_out = (char * )malloc(data_len_out);

					memset(data_value_out, 0, data_len_out);

					data_len_out = modp_b64_encode(data_value_out,data_value_in, data_len_in);

					item["certContentB64String"] = data_value_out;

					free(data_value_out);
				}

				if (0 == pCertContent->stProperty.ulVerify)
				{
					unsigned long long timeLocal = 0;
					unsigned long long daysLeft = 0;

					GetLocalTime_T(&timeLocal);

					daysLeft = (pCertContent->stProperty.ulNotAfter - timeLocal)/24/60/60;

					if (daysLeft < Expire)
					{
						std::wostringstream oss; 

						oss<< L"证书还有";

						oss<<(int)daysLeft;

						oss<< L"天过期，请进行证书更新！";

						item["expire_msg"] = utf8_encode(oss.str()); 
						item["expiration_status"] = EXPIRATION_STATUS_LEFT_IN_EXPIRE;
					}
					else
					{
						item["expire_msg"] = utf8_encode(L"证书有效！");
						item["expiration_status"] = EXPIRATION_STATUS_IN;
					}
				}
				else
				{
					item["expire_msg"] =  utf8_encode(L"证书不在有效期！");
					item["expiration_status"] = EXPIRATION_STATUS_OUT;
				}

				itemDevCerts.append(item);  	
			}

			itemDev = itemDevInfo;
			itemDev["certs"] = itemDevCerts;
			
			All.append(itemDev);
			/*cert["notAfter"] = pCertContent->stProperty.ulNotAfter;
			cert["notBefore"] = pCertContent->stProperty.ulNotBefore;*/
		}

		WTF_ClearStore(DEFAULT_SMC_STORE_SM2_USER_ID);

		for (pCertContent = (SK_CERT_CONTENT *)data_value;(char *)pCertContent < (char *)data_value + data_len;pCertContent=(SK_CERT_CONTENT*)((BYTE *)pCertContent+pCertContent->nValueLen+sizeof(SK_CERT_CONTENT)) )
		{
			//regist sm2 signcert to store
			/*if ((pCertContent->stProperty.bSignType == TRUE) && (pCertContent->stProperty.nType == CERT_ALG_SM2_FLAG))*/
			//regist sm2 certpair to store
			if (pCertContent->stProperty.nType == CERT_ALG_SM2_FLAG)
			{
				SMC_ImportUserCert((BYTE*)pCertContent+sizeof(SK_CERT_CONTENT),pCertContent->nValueLen,&(pCertContent->stProperty));
			}
		}

	}

	
	DWORD       cbName;  
	DWORD       dwType;  
	DWORD       dwIndex=0;  
	char        pszName[BUFFER_LEN_1K];   

	while(CryptEnumProviders(  
		dwIndex,     // in -- dwIndex  
		NULL,        // in -- pdwReserved- set to NULL  
		0,           // in -- dwFlags -- set to zero  
		&dwType,     // out -- pdwProvType  
		NULL,        // out -- pszProvName -- NULL on the first call  
		&cbName      // in, out -- pcbProvName  
		))  
	{  
		//--------------------------------------------------------------------  
		//  Get the provider name.  

		if (CryptEnumProviders(  
			dwIndex++,  
			NULL,  
			0,  
			&dwType,  
			pszName,  
			&cbName     // pcbProvName -- size of pszName  
			))  
		{  
			HCRYPTPROV	hCryptProv = NULL;

			DWORD dwErrCode = 0;

			if (!CryptAcquireContext(&hCryptProv, NULL,
				pszName, PROV_RSA_FULL, CRYPT_SILENT))
			{
				dwErrCode = GetLastError();
			}
			else
			{
				HCRYPTKEY hKey = NULL;
				DWORD dwKeyType = AT_KEYEXCHANGE;

				//DWORD dwKeyType = AT_SIGNATURE;

				for (; dwKeyType <= AT_SIGNATURE; dwKeyType++)
				{
					// 获取容器中的密钥
					if (!CryptGetUserKey(hCryptProv, dwKeyType, &hKey))
					{
						dwErrCode = GetLastError();

						if (NTE_BAD_KEY == dwErrCode)
						{
							continue;
						}
						else
						{
							continue;
						}
					}

					ULONG ulCertLen = 4096;
					// 导出容器中的证书
					if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &ulCertLen, 0))
					{
						dwErrCode = GetLastError();

						// 销毁密钥句柄
						CryptDestroyKey(hKey);
						continue;
					}
					else
					{
						if(AT_KEYEXCHANGE == dwKeyType)
						{

						}
						else
						{

						}

						char * szdata = new char[ulCertLen];
						memset(szdata, 0, ulCertLen);
						BOOL bFlag = CryptGetKeyParam(hKey, KP_CERTIFICATE, (BYTE *)szdata, &ulCertLen, 0);
						if (!bFlag)
						{
							dwErrCode = GetLastError();

						}

						// add to list as usb_old
						{
							Json::Value itemDev;
							Json::Value itemDevInfo;
							Json::Value itemDevCerts = Json::Value(Json::arrayValue); // 1 device's certs
							Json::Value item;
							char data_info_value[1024] = {0};
							int data_info_len = 0;

							// 证书的属性
							WT_SetMyCert((unsigned char *)szdata,ulCertLen);

							memset(data_info_value, 0, 1024);
							WT_GetCertInfo(CERT_SERIALNUMBER, 0, data_info_value, &data_info_len);
							item["serialNumber"] = data_info_value;

							memset(data_info_value, 0, 1024);
							WT_GetCertInfo(CERT_ISSUER_DN, NID_COMMONNAME, data_info_value, &data_info_len);
							item["issuer"] = data_info_value;

							memset(data_info_value, 0, 1024);
							WT_GetCertInfo(CERT_SUBJECT_DN, NID_COMMONNAME, data_info_value, &data_info_len);
							item["subject"] = data_info_value;

							item["commonName"] =  strstr(item["subject"].asCString(),"=")+1 == 0 ?  item["subject"]: strstr(item["subject"].asCString(),"=")+1;

							memset(data_info_value, 0, 1024);
							WT_GetCertInfo(CERT_NOTBEFORE, 0, data_info_value, &data_info_len);
							item["notBefore"] = data_info_value;

							memset(data_info_value, 0, 1024);
							WT_GetCertInfo(CERT_NOTAFTER, 0, data_info_value, &data_info_len);
							item["notAfter"] = data_info_value;

							item["signType"] = TRUE; // 签名

							switch(WTF_VerifyCert(CERT_VERIFY_TIME_FLAG | CERT_VERIFY_CHAIN_FLAG | CERT_VERIFY_CRL_FLAG,CERT_ALG_RSA_FLAG,(unsigned char *)szdata,ulCertLen)){
							case 0:
								item["verify"] = CERT_VERIFY_RESULT_FLAG_OK;   // 未校验
								break;
							case EErr_SMC_VERIFY_TIME:
								item["verify"] = CERT_VERIFY_RESULT_TIME_INVALID;
								break;
							case EErr_SMC_NO_CERT_CHAIN:
								item["verify"] = CERT_VERIFY_RESULT_CHAIN_INVALID;
								break;
							case EErr_SMC_VERIFY_CERT:
								item["verify"] = CERT_VERIFY_RESULT_SIGN_INVALID;	
								break;
							default:
								item["verify"] = CERT_VERIFY_RESULT_CHAIN_INVALID;
								break;
							}

							item["type"] = CERT_ALG_RSA_FLAG;     // RSA

							WT_ClearCert();

							// b64 fomat encode certcontent
							{
								char * data_value_in = (char * )malloc(sizeof(SK_CERT_CONTENT) + ulCertLen);
								size_t data_len_in = sizeof(SK_CERT_CONTENT) + ulCertLen;

								size_t data_len_out = modp_b64_encode_len(data_len_in);
								char * data_value_out = (char * )malloc(data_len_out);

								((SK_CERT_CONTENT*)data_value_in)->stProperty.nType = 1; // RSA
								((SK_CERT_CONTENT*)data_value_in)->nValueLen = ulCertLen;
								memcpy(data_value_in+sizeof(SK_CERT_CONTENT),szdata,ulCertLen);

								memset(data_value_out, 0, data_len_out);

								data_len_out = modp_b64_encode(data_value_out,data_value_in, data_len_in);

								item["certContentB64String"] = data_value_out;

								free(data_value_out);
								free(data_value_in);
							}

							itemDevInfo["devNickName"] = item["commonName"];
							itemDevInfo["devFrom"] = "csp";
							itemDevInfo["serialNumber"] = "unknow";

							itemDevCerts.append(item); 
							itemDev = itemDevInfo;
							itemDev["certs"] = itemDevCerts;

							All.append(itemDev);
						}

						delete szdata;

						// 销毁密钥句柄
						CryptDestroyKey(hKey);
					}
				}

				// CryptReleaseContext
				if (!CryptReleaseContext(hCryptProv, 0))
				{
					;
				}
				else
				{

				}
			}
		}  
		else  
		{  

		}   

	} 

	free(data_value);

	if (pDevInfo)
	{
		free(pDevInfo);
	}

	g_CurrentCerts = All.toStyledString();
	
	return All.toStyledString();
#else

	Json::Value All = Json::Value(Json::arrayValue);
	const char * ptrDevOri; // 原始DEV

	// 通过设备获取证书
	void * data_value = NULL;
	unsigned int data_len = 0;
	SK_CERT_CONTENT * pCertContent = NULL;
	int i = 0;
	unsigned int ulRet;

	DEVINFO * pDevInfo = (DEVINFO*)malloc(sizeof(DEVINFO) + 8);

	data_value = malloc(BUFFER_LEN_1K * BUFFER_LEN_1K);
	data_len = BUFFER_LEN_1K * BUFFER_LEN_1K;
	
	ulRet = WTF_EnumCertInternal("hbcmbc", data_value, &data_len,
		CERT_ALG_RSA_FLAG | CERT_ALG_SM2_FLAG, // RSA SM2
		CERT_SIGN_FLAG | CERT_EX_FLAG, // 签名加密
		CERT_VERIFY_TIME_FLAG | CERT_VERIFY_CHAIN_FLAG | CERT_VERIFY_CRL_FLAG,
		CERT_FILTER_FLAG_FALSE);
	
	FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, ulRet);
	FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, data_len);

	//ulRet = WTF_EnumCert(devName, data_value, &data_len,
	//	CERT_ALG_RSA_FLAG | CERT_ALG_SM2_FLAG, // RSA SM2
	//	CERT_SIGN_FLAG | CERT_EX_FLAG, // 签名加密
	//	CERT_VERIFY_CHAIN_FLAG,
	//	CERT_FILTER_FLAG_FALSE);
	if(ulRet)
	{
		
	}
	else
	{
		for (pCertContent = (SK_CERT_CONTENT *)data_value;(char *)pCertContent < (char *)data_value + data_len;pCertContent=(SK_CERT_CONTENT*)((BYTE *)pCertContent+pCertContent->nValueLen+sizeof(SK_CERT_CONTENT)) )
		{
			Json::Value itemDev;
			Json::Value itemDevInfo;
			Json::Value itemDevCerts = Json::Value(Json::arrayValue); // 1 device's certs

			itemDevInfo["devNickName"] = pCertContent->stProperty.szCommonName;

			itemDevInfo["devFrom"] = "skf";

			memset(pDevInfo, 0, sizeof(DEVINFO));

			WTF_GetDevInfoByCertProperty(&(pCertContent->stProperty),pDevInfo);

			itemDevInfo["versionMajor"] = pDevInfo->Version.major;
			itemDevInfo["versionMinor"] = pDevInfo->Version.minor;

			itemDevInfo["manufacturer"] = pDevInfo->Manufacturer;
			itemDevInfo["issuer"] = pDevInfo->Issuer;
			itemDevInfo["label"] = pDevInfo->Label;
			itemDevInfo["serialNumber"] = pDevInfo->SerialNumber;

			itemDevInfo["hwVersionMajor"] = pDevInfo->HWVersion.major;
			itemDevInfo["hwVersionMinor"] = pDevInfo->HWVersion.minor;

			itemDevInfo["firmwareVersionMajor"] = pDevInfo->FirmwareVersion.major;
			itemDevInfo["firmwareVersionMinor"] = pDevInfo->FirmwareVersion.minor;

			itemDevInfo["algSymCap"] = (int)pDevInfo->AlgSymCap;
			itemDevInfo["algAsymCap"] = (int)pDevInfo->AlgAsymCap;
			itemDevInfo["algHashCap"] = (int)pDevInfo->AlgHashCap;
			itemDevInfo["devAuthAlgId"] = (int)pDevInfo->DevAuthAlgId;
			itemDevInfo["totalSpace"] = (int)pDevInfo->TotalSpace;
			itemDevInfo["freeSpace"] = (int)pDevInfo->FreeSpace;

			ptrDevOri = pCertContent->stProperty.szDeviceName;

			for (;(char *)pCertContent < (char *)data_value + data_len;pCertContent=(SK_CERT_CONTENT*)((BYTE *)pCertContent+pCertContent->nValueLen+sizeof(SK_CERT_CONTENT)) )
			{
				if ( 0 != strcmp(ptrDevOri,pCertContent->stProperty.szDeviceName))
				{
					break;
				}
				
				Json::Value item;

				item["skfName"] = pCertContent->stProperty.szSKFName;
				item["deviceName"] = pCertContent->stProperty.szDeviceName;
				item["applicationName"] = pCertContent->stProperty.szApplicationName;
				item["containerName"] = pCertContent->stProperty.szContainerName;

				// 证书的属性
				char data_info_value[1024] = {0};
				int data_info_len = 0;

				WT_SetMyCert(pCertContent->pbValue,pCertContent->nValueLen);

				memset(data_info_value, 0, 1024);
				WT_GetCertInfo(CERT_SERIALNUMBER, 0, data_info_value, &data_info_len);
				item["serialNumber"] = data_info_value;

				memset(data_info_value, 0, 1024);
				WT_GetCertInfo(CERT_ISSUER_DN, NID_COMMONNAME, data_info_value, &data_info_len);
				item["issuer"] = data_info_value;

				memset(data_info_value, 0, 1024);
				WT_GetCertInfo(CERT_SUBJECT_DN, NID_COMMONNAME, data_info_value, &data_info_len);
				item["subject"] = data_info_value;

				item["commonName"] = pCertContent->stProperty.szCommonName;

				memset(data_info_value, 0, 1024);
				WT_GetCertInfo(CERT_NOTBEFORE, 0, data_info_value, &data_info_len);
				item["notBefore"] = data_info_value;

				memset(data_info_value, 0, 1024);
				WT_GetCertInfo(CERT_NOTAFTER, 0, data_info_value, &data_info_len);
				item["notAfter"] = data_info_value;

				item["signType"] = pCertContent->stProperty.bSignType;
				item["verify"] = pCertContent->stProperty.ulVerify;
				item["type"] = pCertContent->stProperty.nType;

				WT_ClearCert();

				// b64 fomat encode certcontent
				{
					const char * data_value_in = (const char *)pCertContent;
					size_t data_len_in = sizeof(SK_CERT_CONTENT) + pCertContent->nValueLen;

					size_t data_len_out = modp_b64_encode_len(data_len_in);
					char * data_value_out = (char * )malloc(data_len_out);

					memset(data_value_out, 0, data_len_out);

					data_len_out = modp_b64_encode(data_value_out,data_value_in, data_len_in);

					item["certContentB64String"] = data_value_out;

					free(data_value_out);
				}

				if (0 == pCertContent->stProperty.ulVerify)
				{
					unsigned long long timeLocal = 0;
					unsigned long long daysLeft = 0;

					GetLocalTime_T(&timeLocal);

					daysLeft = (pCertContent->stProperty.ulNotAfter - timeLocal)/24/60/60;

					if (daysLeft < Expire)
					{
						std::wostringstream oss; 

						oss<< L"证书还有";

						oss<<(int)daysLeft;

						oss<< L"天过期，请进行证书更新！";

						item["expire_msg"] = utf8_encode(oss.str()); 
						item["expiration_status"] = EXPIRATION_STATUS_LEFT_IN_EXPIRE;
					}
					else
					{
						item["expire_msg"] = utf8_encode(L"证书有效！");
						item["expiration_status"] = EXPIRATION_STATUS_IN;
					}
				}
				else
				{
					item["expire_msg"] =  utf8_encode(L"证书不在有效期！");
					item["expiration_status"] = EXPIRATION_STATUS_OUT;
				}

				itemDevCerts.append(item);  	
			}

			itemDev = itemDevInfo;
			itemDev["certs"] = itemDevCerts;
			
			All.append(itemDev);
			/*cert["notAfter"] = pCertContent->stProperty.ulNotAfter;
			cert["notBefore"] = pCertContent->stProperty.ulNotBefore;*/
		}

		WTF_ClearStore(DEFAULT_SMC_STORE_SM2_USER_ID);

		for (pCertContent = (SK_CERT_CONTENT *)data_value;(char *)pCertContent < (char *)data_value + data_len;pCertContent=(SK_CERT_CONTENT*)((BYTE *)pCertContent+pCertContent->nValueLen+sizeof(SK_CERT_CONTENT)) )
		{
			//regist sm2 signcert to store
			/*if ((pCertContent->stProperty.bSignType == TRUE) && (pCertContent->stProperty.nType == CERT_ALG_SM2_FLAG))*/
			//regist sm2 certpair to store
			if (pCertContent->stProperty.nType == CERT_ALG_SM2_FLAG)
			{
				SMC_ImportUserCert((BYTE*)pCertContent+sizeof(SK_CERT_CONTENT),pCertContent->nValueLen,&(pCertContent->stProperty));
			}
		}

	}

	// this is rsa suit
	{
		HCRYPTPROV	hCryptProv = NULL;

		DWORD dwErrCode = 0;

		if (!CryptAcquireContext(&hCryptProv, NULL,
			"CMBC CSP V1.0", PROV_RSA_FULL, CRYPT_SILENT))
		{
			dwErrCode = GetLastError();
		}
		else
		{
			HCRYPTKEY hKey = NULL;
			/*DWORD dwKeyType = AT_KEYEXCHANGE;*/

			DWORD dwKeyType = AT_SIGNATURE;

			for (; dwKeyType <= AT_SIGNATURE; dwKeyType++)
			{
				// 获取容器中的密钥
				if (!CryptGetUserKey(hCryptProv, dwKeyType, &hKey))
				{
					dwErrCode = GetLastError();

					if (NTE_BAD_KEY == dwErrCode)
					{
						continue;
					}
					else
					{
						continue;
					}
				}

				ULONG ulCertLen = 4096;
				// 导出容器中的证书
				if (!CryptGetKeyParam(hKey, KP_CERTIFICATE, NULL, &ulCertLen, 0))
				{
					dwErrCode = GetLastError();

					// 销毁密钥句柄
					CryptDestroyKey(hKey);
					continue;
				}
				else
				{
					if(AT_KEYEXCHANGE == dwKeyType)
					{

					}
					else
					{

					}

					char * szdata = new char[ulCertLen];
					memset(szdata, 0, ulCertLen);
					BOOL bFlag = CryptGetKeyParam(hKey, KP_CERTIFICATE, (BYTE *)szdata, &ulCertLen, 0);
					if (!bFlag)
					{
						dwErrCode = GetLastError();

					}

					// add to list as usb_old
					{
						Json::Value itemDev;
						Json::Value itemDevInfo;
						Json::Value itemDevCerts = Json::Value(Json::arrayValue); // 1 device's certs
						Json::Value item;
						char data_info_value[1024] = {0};
						int data_info_len = 0;

						// 证书的属性
						WT_SetMyCert((unsigned char *)szdata,ulCertLen);

						memset(data_info_value, 0, 1024);
						WT_GetCertInfo(CERT_SERIALNUMBER, 0, data_info_value, &data_info_len);
						item["serialNumber"] = data_info_value;

						memset(data_info_value, 0, 1024);
						WT_GetCertInfo(CERT_ISSUER_DN, NID_COMMONNAME, data_info_value, &data_info_len);
						item["issuer"] = data_info_value;

						memset(data_info_value, 0, 1024);
						WT_GetCertInfo(CERT_SUBJECT_DN, NID_COMMONNAME, data_info_value, &data_info_len);
						item["subject"] = data_info_value;

						item["commonName"] =  strstr(item["subject"].asCString(),"=")+1 == 0 ?  item["subject"]: strstr(item["subject"].asCString(),"=")+1;

						memset(data_info_value, 0, 1024);
						WT_GetCertInfo(CERT_NOTBEFORE, 0, data_info_value, &data_info_len);
						item["notBefore"] = data_info_value;

						memset(data_info_value, 0, 1024);
						WT_GetCertInfo(CERT_NOTAFTER, 0, data_info_value, &data_info_len);
						item["notAfter"] = data_info_value;

						item["signType"] = TRUE; // 签名

						switch(WTF_VerifyCert(CERT_VERIFY_TIME_FLAG | CERT_VERIFY_CHAIN_FLAG | CERT_VERIFY_CRL_FLAG,CERT_ALG_RSA_FLAG,(unsigned char *)szdata,ulCertLen)){
						case 0:
							item["verify"] = CERT_VERIFY_RESULT_FLAG_OK;   // 未校验
							break;
						case EErr_SMC_VERIFY_TIME:
							item["verify"] = CERT_VERIFY_RESULT_TIME_INVALID;
							break;
						case EErr_SMC_NO_CERT_CHAIN:
							item["verify"] = CERT_VERIFY_RESULT_CHAIN_INVALID;
							break;
						case EErr_SMC_VERIFY_CERT:
							item["verify"] = CERT_VERIFY_RESULT_SIGN_INVALID;	
							break;
						default:
							item["verify"] = CERT_VERIFY_RESULT_CHAIN_INVALID;
							break;
						}

						item["type"] = CERT_ALG_RSA_FLAG;     // RSA

						WT_ClearCert();

						// b64 fomat encode certcontent
						{
							char * data_value_in = (char * )malloc(sizeof(SK_CERT_CONTENT) + ulCertLen);
							size_t data_len_in = sizeof(SK_CERT_CONTENT) + ulCertLen;

							size_t data_len_out = modp_b64_encode_len(data_len_in);
							char * data_value_out = (char * )malloc(data_len_out);

							((SK_CERT_CONTENT*)data_value_in)->stProperty.nType = 1; // RSA
							((SK_CERT_CONTENT*)data_value_in)->nValueLen = ulCertLen;
							memcpy(data_value_in+sizeof(SK_CERT_CONTENT),szdata,ulCertLen);

							memset(data_value_out, 0, data_len_out);
							
							data_len_out = modp_b64_encode(data_value_out,data_value_in, data_len_in);

							item["certContentB64String"] = data_value_out;

							free(data_value_out);
							free(data_value_in);
						}

						itemDevInfo["devNickName"] = item["commonName"];
						itemDevInfo["devFrom"] = "csp";
						itemDevInfo["serialNumber"] = "unknow";

						itemDevCerts.append(item); 
						itemDev = itemDevInfo;
						itemDev["certs"] = itemDevCerts;

						All.append(itemDev);
					}

					delete szdata;

					// 销毁密钥句柄
					CryptDestroyKey(hKey);
				}
			}

			// CryptReleaseContext
			if (!CryptReleaseContext(hCryptProv, 0))
			{
				;
			}
			else
			{

			}

		}
	}

	free(data_value);

	if (pDevInfo)
	{
		free(pDevInfo);
	}

	g_CurrentCerts = All.toStyledString();
	
	return All.toStyledString();
#endif
}

std::string WTF_GetCurrentCerts(int Expire)
{
	if(g_CurrentCerts.size() == 0)
	{
		return WTF_ReadCurrentCerts(Expire);
	}
	else
	{
//		{
//			unsigned long ulRet = 0;
//			PCCERT_CONTEXT certContext_OUT = NULL;
//			HCERTSTORE hCertStore = NULL;
//
//			// 创建存储区
//			ulRet = SMC_CertCreateSMCStores();
//
//			if (!ulRet)
//			{
//				ulRet = EErr_SMC_CREATE_STORE;
//				goto err;
//			}
//
//			// 打开存储区
//			hCertStore = SMC_CertOpenStore(0,CERT_SYSTEM_STORE_CURRENT_USER, DEFAULT_SMC_STORE_SM2_USER_ID);
//
//			if (NULL == hCertStore)
//			{
//				ulRet = EErr_SMC_OPEN_STORE;
//				goto err;
//			}
//
//			// 枚举证书
//			do 
//			{
//				unsigned int ulOutLen = 0;
//				// 从第一个开始
//				certContext_OUT = SMC_CertEnumCertificatesInStore(hCertStore, certContext_OUT);
//
//				// 获取ATTR
//				if (NULL != certContext_OUT)
//				{
//					SK_CERT_DESC_PROPERTY * descProperty_OUT = NULL;
//
//					ulRet = SMC_CertGetCertificateContextProperty(certContext_OUT, CERT_DESC_PROP_ID, NULL,&ulOutLen);
//
//					descProperty_OUT = (SK_CERT_DESC_PROPERTY * )malloc(ulOutLen);
//
//					ulRet = SMC_CertGetCertificateContextProperty(certContext_OUT, CERT_DESC_PROP_ID, descProperty_OUT,&ulOutLen);
//
//					if (descProperty_OUT->bSignType == TRUE)
//					{
//						unsigned char digest[32] = {0};
//						ECCSIGNATUREBLOB blob;
//						OPST_HANDLE_ARGS args;
//
//						do 
//						{
//							ulRet = WTF_SM2SignDigestProcessV2(descProperty_OUT,digest,sizeof(digest),&blob);
//
//							if (0 != ulRet)
//							{
//								char bufferShow[1024] = {0};
//
//								sprintf(bufferShow,"签名失败错误码：%x！，是否重新签名？",ulRet);
//
//								if (IDYES == MessageBoxA(NULL,bufferShow, "提示", MB_ICONEXCLAMATION|MB_YESNO))
//								{
//
//								}
//								else
//								{
//									break;
//								}
//							}
//							else
//							{
//								char bufferShow[1024] = {0};
//
//								sprintf(bufferShow,"签名成功！，是否重新签名？");
//
//								if (IDYES == MessageBoxA(NULL,bufferShow, "提示", MB_ICONEXCLAMATION|MB_YESNO))
//								{
//
//								}
//								else
//								{
//									break;
//								}
//							}
//						} while (1);
//					}
//					
//					free(descProperty_OUT);
//
//				}
//			}while(certContext_OUT);
//
//			ulRet = 0;
//err:
//			if (hCertStore)
//			{
//				// 关闭存储区
//				ulRet = SMC_CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
//			}
//		}

		return g_CurrentCerts;
	}
}
