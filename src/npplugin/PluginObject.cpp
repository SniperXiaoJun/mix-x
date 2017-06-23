#include "PluginObject.h"

#include <string>
#include <sstream>
#include <Windows.h>
#include <fstream>
#include "plugin.h"
#include "FILE_LOG.h"
#include "Dbt.h"
#include "mix-mutex.h"
#include "encode_switch.h"
#include "modp_b64.h"

// json library
#include <json/json.h>

// 证书相关的头文件和库
#include "EBankSystemDetect.h" /*系统检测头文件*/

#include "smb_cs.h"
#include "smb_dev.h"
#include "smb_qtui.h"

#define NPVARIANT_TO_INT32(_v) (NPVARIANT_IS_INT32(_v)?(_v).value.intValue:(_v).value.doubleValue)

// 1 声明 Javascript 可以调用的方法名
const char* kChangeUkeyPassword = "changeUkeyPassword";
const char* kReadUkeyInfo = "readUkeyInfo";
const char* kReadUkeyCertInfo = "readUkeyCertInfo";
const char* kDetectSystem = "detectSystem";
const char* kDetectTime = "detectTime";
const char* kDetectAntivirus = "detectAntivirus";
const char* kDetectFireWall = "detectFireWall";
const char* kDetectTrustUrl = "detectTrustUrl";
const char* kDetectUntrustUrl = "detectUntrustUrl";
const char* kDetectBankWebsite = "detectBankWebsite";
const char* kDetectSystemUpdates = "detectSystemUpdates";
const char* kDetectHost = "detectHost";

const char* kDetectLocalIPAddress = "detectLocalIPAddress";
const char* kDetectNetworkIPAddress = "detectNetworkIPAddress";
const char* kDetectMACAddress = "detectMACAddress";
const char* kDetectProcessLikeRunState = "detectProcessLikeRunState";
const char* kDetectWebsiteWithTimeout = "detectWebsiteWithTimeout";
const char* kCalculateDigest = "calculateDigest";


const char* kRunApplication = "runApplication";
const char* kReadUkeyCertInfoWithExpire = "readUkeyCertInfoWithExpire";


const char* kShowCert = "showCert";

const char* kInstallApp = "installApp";					// 安装应用程序
const char* kInstallCaCert = "installCaCert";			// 安装CA证书
const char* kInstallCaCertRSA = "installCaCertRSA";			// 安装CA证书
const char* kInstallCaCertSM2 = "installCaCertSM2";			// 安装CA证书
const char* kRepairHostFile = "repairHostFile";			// 修复HOST文件
const char* kRepairLocalTime = "repairLocalTime";		// 修复本地时间
const char* kListSKFDriver = "listSKFDriver";				// 获取驱动安装信息
const char* kListCSPDriver = "listCSPDriver";				// 获取驱动安装信息
const char* kGetLocalFileVersion = "getLocalFileVersion";   // 本地文件版本信息
const char* kGetWebFileVersion = "getWebFileVersion";		// 网络文件版本信息
const char* kCheckCertChain = "checkCertChain";				// 检测证书链安装信息
const char* kVerifyDevPassword = "verifyDevPassword";		// 验证设备密码

const char* kVerifyDevPasswordHengBao = "verifyDevPasswordHengBao";		// 验证设备密码

const char* kVerifyDevPasswordSync = "verifyDevPasswordSync";		// 验证设备密码（同步）
const char* kAddListenerSync = "addListenerSync";
const char* kRemoveListenerSync = "removeListenerSync";

//const char* kOnInstallApp = "onInstallApp";					// 安装应用程序
//const char* kOnInstallCaCert = "onInstallCaCert";			// 安装CA证书
//const char* kOnInstallCaCertRSA = "onInstallCaCertRSA";			// 安装CA证书
//const char* kOnInstallCaCertSM2 = "onInstallCaCertSM2";			// 安装CA证书
//const char* kOnListSystemControl = "onListSystemControl";
//const char* kOnRepairHostFile = "onRepairHostFile";			// 修复HOST文件
//const char* kOnRepairLocalTime = "onRepairLocalTime";		// 修复本地时间
//const char* kOnListSKFDriver = "onListSKFDriver";				// 获取驱动安装信息
//const char* kOnGetLocalFileVersion = "onGetLocalFileVersion";   // 本地文件版本信息
//const char* kOnGetWebFileVersion = "onGetWebFileVersion";		// 网络文件版本信息
//const char* kOnCheckCertChain = "onCheckCertChain";				// 检测证书链安装信息
//const char* kOnVerifyDevPassword = "onVerifyDevPassword";		// 验证设备密码

//const char* kOnChangeUkeyPasswordComplete = "onChangeUkeyPasswordComplete";
//const char* kOnReadUkeyInfoComplete = "onReadUkeyInfoComplete";
//const char* kOnReadUkeyCertInfoComplete = "onReadUkeyCertInfoComplete";
//const char* kOnDetectSystemUpdates = "onDetectSystemUpdates";
//const char* kOnDetectHost = "onDetectHost";
//const char* kOnDetectTime = "onDetectTime";
//const char* kOnDetectBankWebsite = "onDetectBankWebsite";

const char* kOnUKeyOn = "onUKeyOn";
const char* kOnUKeyOff = "onUKeyOff";

HINSTANCE g_hInstance;
std::vector<PluginObject *> g_plgnObjVector;


int g_CMBCKeyCount = 0;
int GetCMBCKeyCount(int *piCount);


extern NPNetscapeFuncs NPNFuncs;

class ParamThread
{
public:
	PluginObject * pluginObj;
	std::map<std::string,std::string> paramThreadStringMap;
	std::map<std::string,int> paramThreadIntMap;
	NPObject* paramCallback;			// 获取驱动安装信息
	NPObject* paramCallbackGetEncryptPIN;			// 获取驱动安装信息

	ParamThread()
	{
		paramCallback = NULL;
		paramCallbackGetEncryptPIN = NULL;
	}
	
	virtual ~ParamThread()
	{
		if (paramCallback)
		{
			NPN_ReleaseObject(paramCallback);
		}
		if (paramCallbackGetEncryptPIN)
		{
			NPN_ReleaseObject(paramCallbackGetEncryptPIN);
		}
		
	}
};

namespace {
	void splitdou(string s,list<string>& ret)  
	{  
		size_t last = 0;
		size_t index=s.find_first_of(',',last);
		while (index!=std::string::npos)
		{
			ret.push_back(s.substr(last,index-last));
			last=index+1;
			index=s.find_first_of(',',last);
		}
		if (index-last>0)
		{
			ret.push_back(s.substr(last,index-last));
		}
	}

	DWORD WINAPI RepairHostFileThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_file");

		ParamThread* paramThread= (ParamThread*)lparam;

		if (paramThread==NULL)
			return false;

		std::string strHostOrIP = paramThread->paramThreadStringMap["HostOrIP"];

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_RepairHostFile("",strHostOrIP)));

		
		//FreeThreadParamItem(paramThread);


		return true;
	}

	DWORD WINAPI RepairLocalTimeThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_socket");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_RepairLocalTime()));

		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI ListSKFDriverThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_skf");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strSKFName = paramThread->paramThreadStringMap["SKFName"];

		std::list<std::string> strSKFNameList;

		splitdou(strSKFName,strSKFNameList);

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_ListSKFDriver(strSKFNameList)));


		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI ListCSPDriverThread(LPVOID lparam) {
		UseMixMutex share_mutex("share_mutex_skf");

		ParamThread* paramThread = (ParamThread*)lparam;
		if (paramThread == NULL)
			return false;

		std::string strCSPName = paramThread->paramThreadStringMap["CSPName"];

		std::list<std::string> strCSPNameList;

		splitdou(strCSPName, strCSPNameList);

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_ListCSPDriver(strCSPNameList)));


		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI GetLocalFileVersionThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_file");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strFilePath = paramThread->paramThreadStringMap["FilePath"];

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_GetLocalFileVersion(strFilePath)) );

		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI GetWebFileVersionThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_socket");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strWebFile = paramThread->paramThreadStringMap["WebFile"];
		std::string strSite = paramThread->paramThreadStringMap["Site"];
		std::string strSubSite = paramThread->paramThreadStringMap["SubSite"];
		unsigned int nPort =  paramThread->paramThreadIntMap["Port"];

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_GetWebFileVersion(strWebFile ,strSite, strSubSite,nPort)) );

		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI CheckCertChainThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strSecondCertKeyId = paramThread->paramThreadStringMap["SecondCertKeyId"];
		int ulAlgType =  paramThread->paramThreadIntMap["AlgType"];


		std::list<std::string> strSecondCertKeyIdList;

		splitdou(strSecondCertKeyId,strSecondCertKeyIdList);

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_CheckCertChain(strSecondCertKeyIdList ,CERT_VERIFY_TIME_FLAG|CERT_VERIFY_CHAIN_FLAG|CERT_VERIFY_CRL_FLAG, ulAlgType)) );

		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI InstallAppThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_file");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strAppPath = paramThread->paramThreadStringMap["AppPath"];
		std::string strAppArgs = paramThread->paramThreadStringMap["AppArgs"];
		int iFlag = paramThread->paramThreadIntMap["Flag"];

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_InstallApp(strAppPath,strAppArgs, 20 * 60 * 1000, iFlag)) );

		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI RunApplicationThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_file");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strAppPath = paramThread->paramThreadStringMap["AppPath"];
		std::string strAppArgs = paramThread->paramThreadStringMap["AppArgs"];
		int iFlag = paramThread->paramThreadIntMap["Flag"];

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_RunApplication(strAppPath,strAppArgs, iFlag)) );

		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI CalculateDigestThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_file");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strAppPath = paramThread->paramThreadStringMap["AppPath"];

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_CalculateDigest(strAppPath, 4)) ); //4 is md5

		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI DetectProcessLikeRunStateThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_process");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strAppPath = paramThread->paramThreadStringMap["AppPath"];

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_DetectProcessLikeRunState(strAppPath, 0)) ); //4 is md5

		//FreeThreadParamItem(paramThread);

		return true;
	}

	
	


	DWORD WINAPI InstallCaCertThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_file");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strCaCertPath = paramThread->paramThreadStringMap["CaCertPath"];
		int iFlag = paramThread->paramThreadIntMap["Flag"];

		std::list<std::string> strCaCertPathList;

		splitdou(strCaCertPath,strCaCertPathList);

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_InstallCaCert(strCaCertPathList, iFlag)));

		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI InstallCaCertRSAThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_file");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strCaCertPath = paramThread->paramThreadStringMap["CaCertPath"];
		int iFlag = paramThread->paramThreadIntMap["Flag"];

		std::list<std::string> strCaCertPathList;

		splitdou(strCaCertPath,strCaCertPathList);

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_InstallCaCert(strCaCertPathList, iFlag)));

		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI InstallCaCertSM2Thread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_file");

		ParamThread* paramThread = (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strCaCertPath = paramThread->paramThreadStringMap["CaCertPath"];
		int iFlag = paramThread->paramThreadIntMap["Flag"];

		std::list<std::string> strCaCertPathList;

		splitdou(strCaCertPath,strCaCertPathList);

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
			WTF_InstallCaCert(strCaCertPathList, iFlag)));

		//FreeThreadParamItem(paramThread);

		return true;


	}


	DWORD WINAPI VerifyDevPasswordBySignCertPropB64Thread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strPassword = paramThread->paramThreadStringMap["Password"];
		std::string strDeviceB64 = paramThread->paramThreadStringMap["deviceName"];

		//paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
		//	WTF_VerifyDevPasswordBySignCertPropB64(strDeviceB64,strPassword)) );

		//FreeThreadParamItem(paramThread);

		return true;
	}


	unsigned int CfcaGetEncryptPIN(void * param,unsigned char *pbRandom,unsigned int uiRandomLen, unsigned char *pbEncryptPIN,unsigned int *puiEncryptPINLen)
	{
		ParamThread* paramThread= (ParamThread*)param;
		if (paramThread==NULL)
			return false;

		//char buffer_b64[BUFFER_LEN_1K] = {0};

		//int buffer_b64_len = modp_b64_encode(buffer_b64, (const char *)pbRandom,uiRandomLen);

		std::string encryptPinB64 = paramThread->pluginObj->ExecuteJSCallbackGetEncrytPIN(paramThread->paramCallbackGetEncryptPIN,string((char *)pbRandom,(char *)pbRandom+uiRandomLen));

		std::string encryptPin = modp_b64_decode(encryptPinB64);


		strcpy((char *)pbEncryptPIN,encryptPinB64.c_str());
		*puiEncryptPINLen = encryptPinB64.size();

		return 0;
	}

	// 5. 用多线程定义一个异步调用的方法
	DWORD WINAPI ChangeUkeyPasswordThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strOldPassword = paramThread->paramThreadStringMap["oldPassword"];
		std::string strNewPassword = paramThread->paramThreadStringMap["newPassword"];
		std::string strDeviceB64 = paramThread->paramThreadStringMap["deviceName"];

		//paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(
		//	WTF_ChangeDevPasswordBySignCertPropB64(strDeviceB64,strOldPassword,strNewPassword)) );

		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI ReadUkeyInfoThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;
		
		//paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_GetDevSignCert(NULL)) );
		
		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI ReadUkeyCertInfoThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;
		
		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_GetDevAllCerts(NULL, 30)) );
		
		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI ReadUkeyCertInfoWithExpireThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex");

		ParamThread* paramThread= (ParamThread*)lparam;

		int Expire = paramThread->paramThreadIntMap["Expire"];

		if (paramThread==NULL)
			return false;

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_GetDevAllCerts(NULL, Expire)) );

		//FreeThreadParamItem(paramThread);

		return true;
	}

	

	DWORD WINAPI detectSystemUpdatesThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_socket");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		//// 0: 操作系统
		//paramThread->pluginObj->ExecuteJSCallback(pluginObj->mOnReadUkeyCertComplete, utf8_decode(WTF_GetSystemInfo()) );

		//// 1: 时间
		//paramThread->pluginObj->ExecuteJSCallback(pluginObj->mOnReadUkeyCertComplete, utf8_decode(WTF_GetTime()) );

		//// 2: 杀毒软件
		//paramThread->pluginObj->ExecuteJSCallback(pluginObj->mOnReadUkeyCertComplete, utf8_decode(WTF_GetAntivirusInfo()) );

		//// 3: 防火墙
		//paramThread->pluginObj->ExecuteJSCallback(pluginObj->mOnReadUkeyCertComplete, utf8_decode(WTF_GetFireWallInfo()) );

		//// 4: 信任站点
		//paramThread->pluginObj->ExecuteJSCallback(pluginObj->mOnReadUkeyCertComplete, utf8_decode(WTF_GetTrustUrl(true)) );

		//// 5: 非信任站点
		//paramThread->pluginObj->ExecuteJSCallback(pluginObj->mOnReadUkeyCertComplete, utf8_decode(WTF_GetTrustUrl(false)) );

		//// 6: 网银链接
		//paramThread->pluginObj->ExecuteJSCallback(pluginObj->mOnReadUkeyCertComplete, utf8_decode(WTF_CheckWebSite("per.cmbc.com.cn","pweb/static/login.html", 443)) );

		// 7: 系统更新
		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_CheckSystemUpdateState()));

		//FreeThreadParamItem(paramThread);

		return true;
	}  

	DWORD WINAPI detectTimeThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_socket");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		// 1: 时间
		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_GetTime()));    

		//FreeThreadParamItem(paramThread);

		return true;
	}


	DWORD WINAPI DetectMACAddressThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_socket");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		// 1: 时间
		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_DetectMACAddress()));    

		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI DetectLocalIPAddressThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_socket");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		// 1: 时间
		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_DetectLocalIPAddress()));    

		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI DetectNetworkIPAddressThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_socket");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		// 1: 时间
		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_DetectNetworkIPAddress()));    

		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI detectBankWebsiteThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_socket");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;
		// 6: 网银链接

		std::string strSite = paramThread->paramThreadStringMap["Site"];
		std::string strSubSite = paramThread->paramThreadStringMap["SubSite"];
		int Port = paramThread->paramThreadIntMap["Port"];

		//paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_CheckWebSite("per.cmbc.com.cn","pweb/static/login.html", 443)));
		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_CheckWebSite(strSite,strSubSite, Port, 10)));
		//FreeThreadParamItem(paramThread);

		return true;
	}

	DWORD WINAPI detectWebsiteWithTimeoutThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_socket");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;
		// 6: 网银链接

		std::string strSite = paramThread->paramThreadStringMap["Site"];
		std::string strSubSite = paramThread->paramThreadStringMap["SubSite"];
		int Port = paramThread->paramThreadIntMap["Port"];
		int Timeout = paramThread->paramThreadIntMap["Timeout"];

		//paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_CheckWebSite("per.cmbc.com.cn","pweb/static/login.html", 443)));
		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_CheckWebSite(strSite,strSubSite, Port, (unsigned int)Timeout)));
		//FreeThreadParamItem(paramThread);

		return true;
	}

	

	DWORD WINAPI detectHostThread(LPVOID lparam){
		UseMixMutex share_mutex("share_mutex_file");

		ParamThread* paramThread= (ParamThread*)lparam;
		if (paramThread==NULL)
			return false;

		std::string strHostOrIP = paramThread->paramThreadStringMap["strHostOrIP"];

		// 8: 检查Host文件
		// paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_CheckHostFile("cmbc.com.cn")));    

		paramThread->pluginObj->ExecuteJSCallback(paramThread->paramCallback, utf8_decode(WTF_CheckHostFile(strHostOrIP)));  

		//FreeThreadParamItem(paramThread);

		return true;
	}
}// end fo namespace


std::string WTF_ReadCurrentCerts(int Expire);

LRESULT CALLBACK WndProc (HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	
	switch(message)
	{
		// Maybe WinCE OS does not support PNP.
		// When you use the PNP notifications, please make sure the WinCE OS supports it.
	case WM_DEVICECHANGE:
		if(wParam == DBT_DEVICEARRIVAL || wParam == DBT_DEVICEREMOVECOMPLETE)
		{
			UseMixMutex share_mutex("share_mutex");
			UseMixMutex share_mutex_PluginObject("share_mutex_PluginObject");
			int iRet = 0;
			string strRes;

			int i =0;
			int tmpCMBCKeyCount = 0;
			
			Sleep(500);

			GetCMBCKeyCount(&tmpCMBCKeyCount);

			if (tmpCMBCKeyCount > g_CMBCKeyCount)
			{
				WTF_ReadCurrentCerts(30);

				for (i = 0; i < g_plgnObjVector.size(); i++)
				{
					(g_plgnObjVector[i])->ExecuteJSCallback((g_plgnObjVector[i])->mOnUKeyOn, utf8_decode(strRes));
				}
			}
			else if(tmpCMBCKeyCount < g_CMBCKeyCount)
			{
				WTF_ReadCurrentCerts(30);

				for (i = 0; i < g_plgnObjVector.size(); i++)
				{
					(g_plgnObjVector[i])->ExecuteJSCallback((g_plgnObjVector[i])->mOnUKeyOff, utf8_decode(strRes));
				}
			}
			else
			{
				// nothing need do
			}

			g_CMBCKeyCount = tmpCMBCKeyCount;
		}

		break;
	default:
		break;
	}

	return DefWindowProc (hWnd, message, wParam, lParam) ;
}

DWORD __stdcall CreateDlg(IN void* pParam)
{
	// add first GetCMBCKeyCount
	{
		GetCMBCKeyCount(&g_CMBCKeyCount);
	}

	static TCHAR szAppName[] = TEXT("CYSD_CSPUPI_DLG_NAME_A581FDC3-B26E-4809-A037-F8901D84B57D") ;
	HWND         hWnd ;
	MSG          msg ;
	WNDCLASS     wndClass;
	BOOL bRet;

	wndClass.style         = CS_HREDRAW | CS_VREDRAW ;
	wndClass.lpfnWndProc   = WndProc ;
	wndClass.cbClsExtra    = 0 ;
	wndClass.cbWndExtra    = 0 ;
	wndClass.hInstance     = g_hInstance ;
#ifdef _WIN32_WCE	// WinCE
	wndClass.hIcon         = NULL;
#else				// Windows
	wndClass.hIcon         = LoadIcon (NULL, IDI_APPLICATION) ;
#endif
	wndClass.hCursor       = LoadCursor (NULL, IDC_ARROW) ;
	wndClass.hbrBackground = (HBRUSH) GetStockObject (WHITE_BRUSH) ;
	wndClass.lpszMenuName  = NULL ;
	wndClass.lpszClassName = szAppName ;

	if (! RegisterClass (&wndClass))
	{
		return FALSE;
	}
	hWnd = CreateWindow (szAppName,					 // window class name
		TEXT (""),					 // window caption
		(WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX),	//WS_OVERLAPPEDWINDOW,		 // window style
		CW_USEDEFAULT,				 // initial x position
		CW_USEDEFAULT,				 // initial y position
		CW_USEDEFAULT,				 // initial x size
		CW_USEDEFAULT,				 // initial y size
		NULL,						 // parent window handle
		NULL,						 // window menu handle
		g_hInstance,				 // program instance handle
		NULL) ;					 // creation parameters

	ShowWindow (hWnd, SW_HIDE) ;
	UpdateWindow (hWnd);
	while ((bRet=GetMessage (&msg, hWnd, 0, 0))!=0)
	{
		if(bRet==-1)
		{
			return FALSE;
		}
		else
		{
			TranslateMessage (&msg) ;
			DispatchMessage (&msg) ;
		}
	}

	return TRUE;
}

			

DWORD ulThreadID = 0; // 监视设备插拔线程句柄

void __stdcall CreateDlgThread()
{
	UseMixMutex share_mutex("share_mutex_CreateDlgThread");
	if (0 == ulThreadID)
	{
		HANDLE hMonitorHandle=NULL; // 监视设备插拔线程句柄

		DWORD ulSysVer;
		SECURITY_ATTRIBUTES sa;
		SECURITY_DESCRIPTOR sd;
		memset(&sa,0x00,sizeof(SECURITY_ATTRIBUTES));
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle = TRUE;

		ulSysVer=GetVersion();

		//if (!(ulSysVer & 0x80000000))	// win2K,XP,2003
		//{		
		InitializeSecurityDescriptor(&sd,SECURITY_DESCRIPTOR_REVISION);
		SetSecurityDescriptorDacl(&sd, TRUE, 0, FALSE);		
		sa.lpSecurityDescriptor = &sd;		
		//}
		hMonitorHandle=CreateThread(&sa,0, CreateDlg,NULL,0,&ulThreadID);

		//AddThreadItem(hMonitorHandle);

		FILE_LOG_FMT(file_log_name, "%s %d %s", __FUNCTION__, __LINE__,"");

		if(hMonitorHandle)
			CloseHandle(hMonitorHandle);
	}
}

HMODULE GetSelfModuleHandle()  
{  
	MEMORY_BASIC_INFORMATION mbi;  
	return ((::VirtualQuery(GetSelfModuleHandle, &mbi, sizeof(mbi)) != 0) ? (HMODULE) mbi.AllocationBase : NULL);  
}  

//-----------------------------------------------------------------------------
// 开始修改方法
//-----------------------------------------------------------------------------

// 2. 初始化回调引用
PluginObject::PluginObject(NPP npp):
	npp(npp),
	hThread(0), mOnUKeyOn(0), mOnUKeyOff(0)
{
	char buffer[1024] = {0};

	GetModuleFileNameA(NULL, buffer, 1024);

	//FILE_WRITE_FMT(file_log_name, "func=%s thread=%d line=%d %s", __FUNCTION__, GetCurrentThreadId(), __LINE__, buffer);

	CreateDlgThread();
}

// 3. 析构方法
void PluginObject::deallocate(){
	//UseMixMutex share_mutex("share_mutex_thread");
	// 减少引用计数
	if(mOnUKeyOn != NULL){
		NPN_ReleaseObject(mOnUKeyOn); 
	}
	if(mOnUKeyOff != NULL){
		NPN_ReleaseObject(mOnUKeyOff);  
	}

	{

		UseMixMutex share_mutex("share_mutex_PluginObject");

		std::vector<PluginObject *>::const_iterator it;

		it = g_plgnObjVector.begin();

		while (it != g_plgnObjVector.end())
		{
			if (*it == this)
			{
				g_plgnObjVector.erase(it);

				break;
			}

			it++;
		}
	}
	
	std::vector<HANDLE>::const_iterator it;

	it = g_ThreadVector.begin();
	
	while(it != g_ThreadVector.end() )
	{
		DWORD dwExitCode = 0;
		
		bool bRes = GetExitCodeThread(
			*it,      // handle to the thread
			&dwExitCode   // address to receive termination status
			);
		
		if (bRes && (dwExitCode == STILL_ACTIVE))
		{
			//WaitForSingleObject( *it, INFINITE );
			TerminateThread(*it, 0);
			CloseHandle(*it);
		}
		else
		{
			
		}
		
		g_ThreadVector.erase(it);
	}
#if 0 // must not free
	it = g_ThreadParamVector.begin();
	while (it != g_ThreadParamVector.end())
	{
		delete (*it);
		g_ThreadParamVector.erase(it);
		it++;
	}
#endif

}

// 4.1 告诉JS本插件可以调用的属性
bool PluginObject::hasProperty(NPIdentifier propertyName){
	bool bRev = false;
	NPUTF8 *pName = NPNFuncs.utf8fromidentifier(propertyName);

	if (pName!=NULL){
		if (strcmp(pName, kOnUKeyOn ) == 0 || strcmp(pName, kOnUKeyOff ) == 0){
			return true;
		}
	}
	return bRev;
}

// 4.2 返回给JS某个属性
bool PluginObject::getProperty(NPIdentifier propertyName, NPVariant *result){
	return false;
}

// 4.3 通过JS设置某个属性
bool PluginObject::setProperty(NPIdentifier name,const NPVariant *value){
	bool bRev = false;

	if (name == NPN_GetStringIdentifier(kOnUKeyOn) ){
		mOnUKeyOn = NPN_RetainObject(NPVARIANT_TO_OBJECT(*value));  
		bRev = true;
	}
	else if (name == NPN_GetStringIdentifier(kOnUKeyOff) ){
		mOnUKeyOff = NPN_RetainObject(NPVARIANT_TO_OBJECT(*value));  
		bRev = true;
	}


	return bRev;
}

// 4.1 告诉JS本插件可以调用的方法
bool PluginObject::hasMethod(NPIdentifier methodName){
	bool bRev = false;
	NPUTF8 *pName = NPNFuncs.utf8fromidentifier(methodName);

	if (strcmp(pName, kChangeUkeyPassword)==0 
		|| strcmp(pName, kReadUkeyInfo)==0 
		|| strcmp(pName, kReadUkeyCertInfo)==0
		|| strcmp(pName, kReadUkeyCertInfoWithExpire)==0
		|| strcmp(pName, kDetectSystem)==0 
		|| strcmp(pName, kDetectTime)==0 
		|| strcmp(pName, kDetectAntivirus)==0 
		|| strcmp(pName, kDetectFireWall)==0 
		|| strcmp(pName, kDetectTrustUrl)==0 
		|| strcmp(pName, kDetectUntrustUrl)==0 
		|| strcmp(pName, kDetectBankWebsite)==0 
		|| strcmp(pName, kDetectLocalIPAddress)==0 
		|| strcmp(pName, kDetectNetworkIPAddress)==0 
		|| strcmp(pName, kDetectMACAddress)==0 
		|| strcmp(pName, kDetectWebsiteWithTimeout)==0 
		|| strcmp(pName, kDetectSystemUpdates)==0
		|| strcmp(pName, kDetectHost)==0
		|| strcmp(pName, kShowCert)==0
		//add by liqiangqiang start
		|| strcmp(pName, kCalculateDigest) == 0
		|| strcmp(pName, kDetectProcessLikeRunState) == 0
		|| strcmp(pName, kRunApplication ) == 0
		|| strcmp(pName, kInstallApp ) == 0
		|| strcmp(pName, kInstallCaCert ) == 0
		|| strcmp(pName, kInstallCaCertRSA ) == 0
		|| strcmp(pName, kInstallCaCertSM2 ) == 0
		|| strcmp(pName, kRepairHostFile ) == 0
		|| strcmp(pName, kRepairLocalTime) == 0
		|| strcmp(pName, kListSKFDriver) == 0
		|| strcmp(pName, kListCSPDriver) == 0
		|| strcmp(pName, kGetLocalFileVersion ) == 0
		|| strcmp(pName, kGetWebFileVersion ) == 0
		|| strcmp(pName, kCheckCertChain) == 0
		|| strcmp(pName, kVerifyDevPassword ) == 0
		|| strcmp(pName, kVerifyDevPasswordHengBao ) == 0
		|| strcmp(pName, kVerifyDevPasswordSync ) == 0
		|| strcmp(pName, kAddListenerSync) == 0
		|| strcmp(pName, kRemoveListenerSync) == 0
		//add by liqiangqiang end

		){
			return true;
	}
	else {
		return false;
	}
}

// 4.2 通过JS调用方法的入口 
bool PluginObject::invoke(NPIdentifier methodName,
	const NPVariant* args, uint32_t argCount, NPVariant* result) { 

		char* name = NPNFuncs.utf8fromidentifier(methodName);
		bool ret_val = false;
		std::string outString;

		if (!name) {
			return ret_val;
		}
		if (strcmp(name, kChangeUkeyPassword)==0 ) {
			ret_val = true; 

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString device(NPVARIANT_TO_STRING(args[0])); 
			NPString oldPassword(NPVARIANT_TO_STRING(args[1]));
			NPString newPassword(NPVARIANT_TO_STRING(args[2]));
			std::string strDevice(device.UTF8Characters, device.UTF8Length);
			std::string strOldPassword(oldPassword.UTF8Characters, oldPassword.UTF8Length);
			std::string strNewPassword(newPassword.UTF8Characters, newPassword.UTF8Length);

			// change password
			paramThread->paramThreadStringMap["deviceName"]=strDevice;
			paramThread->paramThreadStringMap["oldPassword"]=strOldPassword;
			paramThread->paramThreadStringMap["newPassword"]=strNewPassword;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[3]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, ChangeUkeyPasswordThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			

			outString = "Change ukey password async.";
		}
		// ADD BY 李强强START
		else if (strcmp(name, kVerifyDevPasswordSync)==0 ) {
			ret_val = true; 
			NPString device(NPVARIANT_TO_STRING(args[0])); 
			NPString Password(NPVARIANT_TO_STRING(args[1]));
			std::string strDevice(device.UTF8Characters, device.UTF8Length);
			std::string strPassword(Password.UTF8Characters, Password.UTF8Length);

			// 线程参数
			//outString = WTF_VerifyDevPasswordBySignCertPropB64(strDevice,strPassword);

		}
		else if (strcmp(name, kAddListenerSync )==0 ) {
			ret_val = true; 
			UseMixMutex share_mutex("share_mutex_PluginObject");
			std::vector<PluginObject *>::const_iterator it;

			it = g_plgnObjVector.begin();

			while (it != g_plgnObjVector.end())
			{
				if (*it == this)
				{
					g_plgnObjVector.erase(it);

					break;
				}

				it++;
			}

			g_plgnObjVector.push_back(this);

			outString = "";
		}
		else if (strcmp(name, kRemoveListenerSync )==0 ) {
			ret_val = true; 
			UseMixMutex share_mutex("share_mutex_PluginObject");
			std::vector<PluginObject *>::const_iterator it;

			it = g_plgnObjVector.begin();

			while (it != g_plgnObjVector.end())
			{
				if (*it == this)
				{
					g_plgnObjVector.erase(it);

					break;
				}

				it++;
			}

			outString = "";
		}
		else if(strcmp(name,kVerifyDevPassword) == 0)
		{
			ret_val = true; 

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString device(NPVARIANT_TO_STRING(args[0])); 
			NPString Password(NPVARIANT_TO_STRING(args[1]));
			std::string strDevice(device.UTF8Characters, device.UTF8Length);
			std::string strPassword(Password.UTF8Characters, Password.UTF8Length);

			// 线程参数
			paramThread->paramThreadStringMap["deviceName"]=strDevice;
			paramThread->paramThreadStringMap["Password"]=strPassword;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[2]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, VerifyDevPasswordBySignCertPropB64Thread, paramThread, 0, NULL);
			AddThreadItem(hThread);
			
			outString = "Verify ukey password async.";
		}
		else if(strcmp(name,kInstallApp) == 0)
		{
			ret_val = true; 

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString AppPath(NPVARIANT_TO_STRING(args[0])); 
			NPString AppArgs(NPVARIANT_TO_STRING(args[1]));

			std::string strAppPath(AppPath.UTF8Characters, AppPath.UTF8Length);
			std::string strAppArgs(AppArgs.UTF8Characters, AppArgs.UTF8Length);
			int iFlag =  NPVARIANT_TO_INT32(args[2]);

			//strAppPath = UTF8ToGBK(strAppPath);

			// 线程参数
			paramThread->paramThreadStringMap["AppPath"]=strAppPath;
			paramThread->paramThreadStringMap["AppArgs"]=strAppArgs;
			paramThread->paramThreadIntMap["Flag"] = iFlag; 

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[3]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, InstallAppThread, paramThread, 0, NULL);
			AddThreadItem(hThread);
			
			outString = "Install App async.";
		}
		else if(strcmp(name,kRunApplication) == 0)
		{
			ret_val = true; 

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString AppPath(NPVARIANT_TO_STRING(args[0])); 
			NPString AppArgs(NPVARIANT_TO_STRING(args[1]));

			std::string strAppPath(AppPath.UTF8Characters, AppPath.UTF8Length);
			std::string strAppArgs(AppArgs.UTF8Characters, AppArgs.UTF8Length);
			int iFlag =  NPVARIANT_TO_INT32(args[2]);

			//strAppPath = UTF8ToGBK(strAppPath);

			// 线程参数
			paramThread->paramThreadStringMap["AppPath"]=strAppPath;
			paramThread->paramThreadStringMap["AppArgs"]=strAppArgs;
			paramThread->paramThreadIntMap["Flag"] = iFlag; 

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[3]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, RunApplicationThread, paramThread, 0, NULL);
			AddThreadItem(hThread);

			outString = "Install App async.";
		}
		else if(strcmp(name,kCalculateDigest) == 0)
		{
			ret_val = true; 

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString AppPath(NPVARIANT_TO_STRING(args[0])); 

			std::string strAppPath(AppPath.UTF8Characters, AppPath.UTF8Length);

			// 线程参数
			paramThread->paramThreadStringMap["AppPath"]=strAppPath;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[1]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, CalculateDigestThread, paramThread, 0, NULL);
			AddThreadItem(hThread);

			outString = "CalculateDigestThread async.";
		}
		else if(strcmp(name,kDetectProcessLikeRunState) == 0)
		{
			ret_val = true; 

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString AppPath(NPVARIANT_TO_STRING(args[0])); 

			std::string strAppPath(AppPath.UTF8Characters, AppPath.UTF8Length);

			// 线程参数
			paramThread->paramThreadStringMap["AppPath"]=strAppPath;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[1]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, DetectProcessLikeRunStateThread, paramThread, 0, NULL);
			AddThreadItem(hThread);

			outString = "DetectProcessLikeRunStateThread async.";
		}
		
		else if (strcmp(name,kInstallCaCert) == 0)
		{
			ret_val = true; 

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString CaCertPath(NPVARIANT_TO_STRING(args[0])); 
			std::string strCaCertPath(CaCertPath.UTF8Characters, CaCertPath.UTF8Length);

			int iFlag =  NPVARIANT_TO_INT32(args[1]);

			//strCaCertPath = UTF8ToGBK(strCaCertPath);
			// 线程参数
			paramThread->paramThreadStringMap["CaCertPath"]=strCaCertPath;
			paramThread->paramThreadIntMap["Flag"] = iFlag; 


			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[2]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, InstallCaCertThread, paramThread, 0, NULL);
			AddThreadItem(hThread);
			
			outString = "Install CaCert common async.";
		}
		else if (strcmp(name,kInstallCaCertRSA) == 0)
		{
			ret_val = true; 

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString CaCertPath(NPVARIANT_TO_STRING(args[0])); 
			std::string strCaCertPath(CaCertPath.UTF8Characters, CaCertPath.UTF8Length);
			//strCaCertPath = UTF8ToGBK(strCaCertPath);
			// 线程参数
			paramThread->paramThreadStringMap["CaCertPath"]=strCaCertPath;
			paramThread->paramThreadIntMap["Flag"] = 1; 

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[1]));  
			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, InstallCaCertRSAThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			
			outString = "Install CaCert RSA async.";
		}
		else if (strcmp(name,kInstallCaCertSM2) == 0)
		{
			ret_val = true;

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString CaCertPath(NPVARIANT_TO_STRING(args[0])); 
			std::string strCaCertPath(CaCertPath.UTF8Characters, CaCertPath.UTF8Length);
			//strCaCertPath = UTF8ToGBK(strCaCertPath);
			// 线程参数
			paramThread->paramThreadStringMap["CaCertPath"]=strCaCertPath;
			paramThread->paramThreadIntMap["Flag"] = 2; 

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[1]));  
			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, InstallCaCertSM2Thread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			
			outString = "Install CaCert SM2 async.";
		}
		else if (strcmp(name,kCheckCertChain) == 0)
		{
			ret_val = true; 
			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;
			NPString SecondCertKeyId(NPVARIANT_TO_STRING(args[0])); 
			std::string strSecondCertKeyId(SecondCertKeyId.UTF8Characters, SecondCertKeyId.UTF8Length);
			int ulAlgType =  NPVARIANT_TO_INT32(args[1]);

			// 线程参数
			paramThread->paramThreadStringMap["SecondCertKeyId"]=strSecondCertKeyId;
			paramThread->paramThreadIntMap["AlgType"] = ulAlgType; 

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[2]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, CheckCertChainThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			
			outString = "Check Cert Chain async.";
		}
		else if (strcmp(name,kGetWebFileVersion) == 0)
		{
			ret_val = true; 

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString WebFile(NPVARIANT_TO_STRING(args[0])); 
			std::string strWebFile(WebFile.UTF8Characters, WebFile.UTF8Length);

			NPString Site(NPVARIANT_TO_STRING(args[1])); 
			std::string strSite(Site.UTF8Characters, Site.UTF8Length);

			NPString SubSite(NPVARIANT_TO_STRING(args[2])); 
			std::string strSubSite(SubSite.UTF8Characters, SubSite.UTF8Length);

			int Port =  NPVARIANT_TO_INT32(args[3]);

			// 线程参数
			paramThread->paramThreadStringMap["WebFile"] = strWebFile;
			paramThread->paramThreadStringMap["Site"] = strSite;
			paramThread->paramThreadStringMap["SubSite"] = strSubSite;
			paramThread->paramThreadIntMap["Port"] = Port;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[4])); 

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, GetWebFileVersionThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			
			outString = "Get Web File Version async.";
		}
		else if (strcmp(name,kGetLocalFileVersion) == 0)
		{
			ret_val = true; 

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString FilePath(NPVARIANT_TO_STRING(args[0])); 
			std::string strFilePath(FilePath.UTF8Characters, FilePath.UTF8Length);

			//strFilePath = UTF8ToGBK(strFilePath);

			// 线程参数
			paramThread->paramThreadStringMap["FilePath"] = strFilePath;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[1]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, GetLocalFileVersionThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			
			outString = "Get Local File Version async.";
		}
		else if (strcmp(name,kListSKFDriver) == 0)
		{
			ret_val = true; 

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString SKFName(NPVARIANT_TO_STRING(args[0])); 
			std::string strSKFName(SKFName.UTF8Characters, SKFName.UTF8Length);

			// 线程参数
			paramThread->paramThreadStringMap["SKFName"] = strSKFName;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[1]));  
			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, ListSKFDriverThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			
			outString = "List SKF Driver async.";
		}
		else if (strcmp(name, kListCSPDriver) == 0)
		{
			ret_val = true;

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString CSPName(NPVARIANT_TO_STRING(args[0]));
			std::string strCSPName(CSPName.UTF8Characters, CSPName.UTF8Length);

			// 线程参数
			paramThread->paramThreadStringMap["CSPName"] = strCSPName;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[1]));
			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, ListCSPDriverThread, paramThread, 0, NULL);

			AddThreadItem(hThread);

			outString = "List CSP Driver async.";
		}
		else if (strcmp(name,kRepairLocalTime) == 0)
		{
			ret_val = true; 

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[0]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, RepairLocalTimeThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			
			outString = "Repair Local Time async.";
		}

		else if (strcmp(name,kRepairHostFile) == 0)
		{
			ret_val = true; 
			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString HostOrIP(NPVARIANT_TO_STRING(args[0])); 
			std::string strHostOrIP(HostOrIP.UTF8Characters, HostOrIP.UTF8Length);

			// 线程参数
			paramThread->paramThreadStringMap["strHostOrIP"] = strHostOrIP;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[1]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, RepairHostFileThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			
			outString = "Repair Host File async.";
		}
		// ADD BY 李强强END



		else if (strcmp(name, kReadUkeyInfo)==0 ) {
			ret_val = true;
			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[0]));  
			
			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, ReadUkeyInfoThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			
			outString = "Read ukey info async.";
		}
		else if (strcmp(name, kReadUkeyCertInfo)==0 ) {
			ret_val = true;

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[0]));  
			
			AddThreadParamItem(paramThread);

			// read cert info
			hThread = CreateThread(NULL, 0, ReadUkeyCertInfoThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			
			outString = "Read ukey and cert info async.";
		} 
		else if (strcmp(name, kReadUkeyCertInfoWithExpire)==0 ) {
			ret_val = true;

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			int Expire =  NPVARIANT_TO_INT32(args[0]);

			paramThread->paramThreadIntMap["Expire"] = Expire;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[1]));  

			AddThreadParamItem(paramThread);

			// read cert info
			hThread = CreateThread(NULL, 0, ReadUkeyCertInfoWithExpireThread, paramThread, 0, NULL);

			AddThreadItem(hThread);

			outString = "Read ukey and cert info async.";
		} 
		else if (strcmp(name, kDetectSystem)==0 ) {
			ret_val = true;
			outString = WTF_GetSystemInfo();
		} 
		else if (strcmp(name, kDetectTime)==0 ) {
			ret_val = true;

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[0]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, detectTimeThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			
			outString = "detect Time async.";
		} 
		else if (strcmp(name, kDetectAntivirus)==0 ) {
			ret_val = true;
			outString = WTF_GetAntivirusInfo();
		} 
		else if (strcmp(name, kDetectFireWall)==0 ) {
			ret_val = true;
			outString = WTF_GetFireWallInfo();
		} 
		else if (strcmp(name, kDetectTrustUrl)==0 ) {
			ret_val = true;
			outString = WTF_GetTrustUrl(true);
		} 
		else if (strcmp(name, kDetectUntrustUrl)==0 ) {
			ret_val = true;
			outString = WTF_GetTrustUrl(false);
		} 
		else if (strcmp(name, kDetectNetworkIPAddress)==0 ) {
			ret_val = true;

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[0]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, DetectNetworkIPAddressThread, paramThread, 0, NULL);

			AddThreadItem(hThread);

			outString = "detect DetectNetworkIPAddress async.";
		} 
		else if (strcmp(name, kDetectLocalIPAddress)==0 ) {
			ret_val = true;

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[0]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, DetectLocalIPAddressThread, paramThread, 0, NULL);

			AddThreadItem(hThread);

			outString = "detect kDetectLocalIPAddress async.";
		} 
		else if (strcmp(name, kDetectMACAddress)==0 ) {
			ret_val = true;

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[0]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, DetectMACAddressThread, paramThread, 0, NULL);

			AddThreadItem(hThread);

			outString = "detect DetectMACAddressThread async.";
		} 
		else if (strcmp(name, kDetectBankWebsite)==0 ) {
			ret_val = true;

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString Site(NPVARIANT_TO_STRING(args[0])); 
			std::string strSite(Site.UTF8Characters, Site.UTF8Length);

			NPString SubSite(NPVARIANT_TO_STRING(args[1])); 
			std::string strSubSite(SubSite.UTF8Characters, SubSite.UTF8Length);

			int Port =  NPVARIANT_TO_INT32(args[2]);

			// 线程参数
			paramThread->paramThreadStringMap["Site"] = strSite;
			paramThread->paramThreadStringMap["SubSite"] = strSubSite;
			paramThread->paramThreadIntMap["Port"] = Port;


			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[3]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, detectBankWebsiteThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			
			outString = "detect bank website async.";
		} 
		else if (strcmp(name, kDetectWebsiteWithTimeout)==0 ) {
			ret_val = true;

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString Site(NPVARIANT_TO_STRING(args[0])); 
			std::string strSite(Site.UTF8Characters, Site.UTF8Length);

			NPString SubSite(NPVARIANT_TO_STRING(args[1])); 
			std::string strSubSite(SubSite.UTF8Characters, SubSite.UTF8Length);

			int Port =  NPVARIANT_TO_INT32(args[2]);
			int Timeout =  NPVARIANT_TO_INT32(args[3]);

			// 线程参数
			paramThread->paramThreadStringMap["Site"] = strSite;
			paramThread->paramThreadStringMap["SubSite"] = strSubSite;
			paramThread->paramThreadIntMap["Port"] = Port;
			paramThread->paramThreadIntMap["Timeout"] = Timeout;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[4]));  

			AddThreadParamItem(paramThread);

			hThread = CreateThread(NULL, 0, detectWebsiteWithTimeoutThread, paramThread, 0, NULL);

			AddThreadItem(hThread);

			outString = "detectWebsiteWithTimeoutThread async.";
		} 
		
		else if (strcmp(name, kDetectSystemUpdates)==0 ) {
			ret_val = true;

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[0]));  

			AddThreadParamItem(paramThread);

			// detect system updates
			hThread = CreateThread(NULL, 0, detectSystemUpdatesThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			

			outString = "detect system updates async.";
		}
		else if (strcmp(name, kDetectHost)==0 ) {
			ret_val = true;

			ParamThread * paramThread = new ParamThread();
			paramThread->pluginObj = this;

			NPString HostOrIP(NPVARIANT_TO_STRING(args[0])); 
			std::string strHostOrIP(HostOrIP.UTF8Characters, HostOrIP.UTF8Length);

			// 线程参数
			paramThread->paramThreadStringMap["strHostOrIP"] = strHostOrIP;

			paramThread->paramCallback = NPN_RetainObject(NPVARIANT_TO_OBJECT(args[1]));  

			AddThreadParamItem(paramThread);

			// detect system host file
			hThread = CreateThread(NULL, 0, detectHostThread, paramThread, 0, NULL);

			AddThreadItem(hThread);
			
			outString = "detect system host configuration.";
		} 
		else if (strcmp(name, kShowCert)==0 ) {
			ret_val = true;
			// show cert
			NPString certData(NPVARIANT_TO_STRING(args[0])); 
			std::string strCert(certData.UTF8Characters, certData.UTF8Length);
			WTF_ShowCert(strCert);
			outString = "detect system updates async.";
		} 
		else {
			// Exception handling. 
			outString = "Called an invalid method.";
		}
		char* npOutString = (char *)NPNFuncs.memalloc(outString.length() + 1);
		if (!npOutString)
			return false;
		strcpy_s(npOutString, outString.length()+1, outString.c_str());
		STRINGZ_TO_NPVARIANT(npOutString, *result);

		NPNFuncs.memfree(name);
		return ret_val;
}

// 4.3 本插件异步回调JS的方法
void PluginObject::ExecuteJSCallback(NPObject* callback, std::wstring msg){
	int iRev = 0;
	std::string msgUTF8 = utf8_encode(msg);

	if (callback != NULL){
		// 转换参数列表
		NPVariant relements[1];
		STRINGZ_TO_NPVARIANT(msgUTF8.c_str(), relements[0]);

		// 调用JS函数
		NPVariant jsResult; 
		NPN_InvokeDefault(npp, callback, relements, 1, &jsResult);

		if (NPVARIANT_IS_STRING(jsResult)){
			NPString rString = NPVARIANT_TO_STRING(jsResult);
			char revBuf[255] = {0};
			memcpy(revBuf, rString.UTF8Characters, rString.UTF8Length);
		}

		// 释放结果变量 当从浏览器那获取的结果
		NPN_ReleaseVariantValue(&jsResult);

		if (callback == mOnUKeyOn || mOnUKeyOff == callback)
		{
			
		}
		else
		{
			
			FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d %s", __FUNCTION__, GetCurrentThreadId(), __LINE__, msgUTF8.c_str());
			
			
		}
	}

	

	return;
}


// 4.3 本插件异步回调JS的方法
std::string PluginObject::ExecuteJSCallbackGetEncrytPIN(NPObject* callback, std::string msg){
	int iRev = 0;
	std::string msgUTF8 = msg;
	char revBuf[255] = {0};

	if (callback != NULL){
		// 转换参数列表
		NPVariant relements[1];
		STRINGN_TO_NPVARIANT(msgUTF8.c_str(),msgUTF8.size(),relements[0]);

		// 调用JS函数
		NPVariant jsResult; 
		NPN_InvokeDefault(npp, callback, relements, 1, &jsResult);

		if (NPVARIANT_IS_STRING(jsResult)){
			NPString rString = NPVARIANT_TO_STRING(jsResult);
			memcpy(revBuf, rString.UTF8Characters, rString.UTF8Length);
		}

		// 释放结果变量 当从浏览器那获取的结果
		NPN_ReleaseVariantValue(&jsResult);

		if (callback == mOnUKeyOn || mOnUKeyOff == callback)
		{

		}
		else
		{

		}
	}

	return revBuf;
}


//-----------------------------------------------------------------------------
//    下面的方法一般不需要修改
//-----------------------------------------------------------------------------

PluginObject::~PluginObject(void)
{

}

void PluginObject::invalidate(){}

bool PluginObject::invokeDefault(const NPVariant *args, uint32_t argCount, NPVariant *result){
	return true;
}

bool PluginObject::removeProperty(NPIdentifier name){
	return true;
}

bool PluginObject::enumerate(NPIdentifier **identifier,uint32_t *count){
	return false;
}

bool PluginObject::construct(const NPVariant *args,uint32_t argCount, NPVariant *result){
	return true;
}

// ========================================静态函数===============================================================

NPObject *PluginObject::_allocate(NPP npp,NPClass *aClass){
	return new PluginObject(npp);
}

#include "FILE_LOG.h"

void PluginObject::_deallocate(NPObject *npobj){
	
	((PluginObject*)npobj)->deallocate();
	if(npobj){
		delete npobj;
	}
}

void PluginObject::_invalidate(NPObject *npobj)
{
	((PluginObject*)npobj)->invalidate();
}

bool PluginObject::_hasMethod(NPObject* obj, NPIdentifier methodName)
{
	return ((PluginObject*)obj)->hasMethod(methodName);
}

bool PluginObject::_invokeDefault(NPObject *obj, const NPVariant *args, uint32_t argCount, NPVariant *result)
{
	return ((PluginObject*)obj)->invokeDefault(args,argCount,result);
}

bool PluginObject::_invoke(NPObject* obj, NPIdentifier methodName, const NPVariant *args, uint32_t argCount, NPVariant *result)
{
	return ((PluginObject*)obj)->invoke(methodName,args,argCount,result);
}

bool PluginObject::_hasProperty(NPObject *obj, NPIdentifier propertyName)
{
	return ((PluginObject*)obj)->hasProperty(propertyName);
}

bool PluginObject::_getProperty(NPObject *obj, NPIdentifier propertyName, NPVariant *result)
{
	return ((PluginObject*)obj)->getProperty(propertyName,result);
}

bool PluginObject::_setProperty(NPObject *npobj, NPIdentifier name,const NPVariant *value)
{
	return ((PluginObject*)npobj)->setProperty(name,value);
}

bool PluginObject::_removeProperty(NPObject *npobj, NPIdentifier name)
{
	return ((PluginObject*)npobj)->removeProperty(name);
}

bool PluginObject::_enumerate(NPObject *npobj, NPIdentifier **identifier,uint32_t *count)
{
	return ((PluginObject*)npobj)->enumerate(identifier,count);
}

bool PluginObject::_construct(NPObject *npobj, const NPVariant *args,uint32_t argCount, NPVariant *result)
{
	return ((PluginObject*)npobj)->construct(args,argCount,result);
}


void PluginObject::FreeThreadParamItem(HANDLE pParamThread)
{
	//UseMixMutex share_mutex("share_mutex_thread");

	std::vector<HANDLE>::const_iterator it;

	it = g_ThreadParamVector.begin();

	while (it != g_ThreadParamVector.end())
	{
		if (*it == pParamThread)
		{
			g_ThreadParamVector.erase(it);

			break;
		}

		it++;
	}

	delete pParamThread;
}

void PluginObject::AddThreadParamItem(HANDLE pParamThread)
{
	//UseMixMutex share_mutex("share_mutex_thread");
	g_ThreadParamVector.push_back(pParamThread);
}

void PluginObject::AddThreadItem(HANDLE pThread)
{
	//UseMixMutex share_mutex("share_mutex_thread");
	g_ThreadVector.push_back(pThread);
}