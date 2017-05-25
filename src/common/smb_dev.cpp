#include "smb_dev.h"

#include <map>
#include <string>

#include "openssl_func_def.h"

std::map<std::string, OPST_HANDLE_ARGS> g_currentArgs;



#define FUNC_NAME_DECLARE(FUNC_NAME_PREFIX,FUNC_NAME,FUNC_NAME_SUFFIX) \
	pSKF_##FUNC_NAME FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX=NULL

#define FUNC_NAME_INIT(FUNC_NAME_PREFIX,FUNC_NAME,FUNC_NAME_SUFFIX) (##FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX) = (pSKF_##FUNC_NAME)GetProcAddress(ghInst,"SKF_"#FUNC_NAME); \
	if(!##FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX) \
{ \
	ulRet = EErr_SMB_DLL_PATH; \
	goto err; \
}\
	else \
{ \
} 

#define FUNC_NAME_INIT_GetContainerType(FUNC_NAME_PREFIX,FUNC_NAME,FUNC_NAME_SUFFIX) \
	(##FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX) = (pSKF_##FUNC_NAME)GetProcAddress(ghInst,"SKF_"#FUNC_NAME); \
	if (!##FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX) \
{\
	(##FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX) = (pSKF_##FUNC_NAME)GetProcAddress(ghInst,"SKF_GetContianerType"); \
}\
	if(!##FUNC_NAME_PREFIX##FUNC_NAME##FUNC_NAME_SUFFIX) \
{ \
	ulRet = EErr_SMB_DLL_PATH; \
	goto err; \
}\
	else \
{ \
} 

typedef ULONG(DEVAPI *pSKF_EnumDev)(BOOL bPresent, LPSTR szNameList, ULONG *puiSize);
typedef ULONG(DEVAPI *pSKF_ConnectDev)(LPSTR szName, DEVHANDLE *phDev);
typedef ULONG(DEVAPI *pSKF_DisConnectDev)(DEVHANDLE hDev);
typedef ULONG(DEVAPI *pSKF_ChangePIN)(HAPPLICATION hApplication, ULONG ulPINType, LPSTR szOldPin, LPSTR szNewPin, ULONG *puiRetryCount);
typedef ULONG(DEVAPI *pSKF_OpenApplication)(DEVHANDLE hDev, LPSTR szAppName, HAPPLICATION *phApplication);
typedef ULONG(DEVAPI *pSKF_CloseApplication)(HAPPLICATION hApplication);
typedef ULONG(DEVAPI *pSKF_EnumApplication)(DEVHANDLE hDev, LPSTR szAppName, ULONG *puiSize);
typedef ULONG(DEVAPI *pSKF_EnumContainer)(HAPPLICATION hApplication, LPSTR szContainerName, ULONG *puiSize);
typedef ULONG(DEVAPI *pSKF_OpenContainer)(HAPPLICATION hApplication, LPSTR szContainerName, HCONTAINER *phContainer);
typedef ULONG(DEVAPI *pSKF_CloseContainer)(HCONTAINER hContainer);
typedef ULONG(DEVAPI *pSKF_VerifyPIN)(HAPPLICATION hApplication, ULONG  ulPINType, LPSTR szPIN, ULONG *puiRetryCount);
typedef ULONG(DEVAPI *pSKF_ExportCertificate)(HCONTAINER hContainer, BOOL bSignFlag, BYTE* pbCert, ULONG *puiCertLen);
typedef ULONG(DEVAPI *pSKF_GetContainerType)(HCONTAINER hContainer, ULONG *puiContainerType);
typedef ULONG(DEVAPI *pSKF_ECCSignData)(HCONTAINER hContainer, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature);
typedef ULONG(DEVAPI *pSKF_ECCVerify)(DEVHANDLE hDev, ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature);
typedef ULONG(DEVAPI *pSKF_ExtECCVerify)(DEVHANDLE hDev, ECCPUBLICKEYBLOB*  pECCPubKeyBlob, BYTE* pbData, ULONG ulDataLen, PECCSIGNATUREBLOB pSignature);
typedef ULONG(DEVAPI *pSKF_GetDevInfo)(DEVHANDLE hDev, DEVINFO *pDevInfo);
typedef ULONG(DEVAPI *pSKF_LockDev)(DEVHANDLE hDev, ULONG ulTimeOut);
typedef ULONG(DEVAPI *pSKF_UnlockDev)(DEVHANDLE hDev);
typedef ULONG(DEVAPI *pSKF_GenRandom)(DEVHANDLE hDev, BYTE *pbRandom, ULONG ulRandomLen);
typedef ULONG(DEVAPI *pSKF_Transmit)(DEVHANDLE hDev, BYTE* pbCommand, ULONG ulCommandLen, BYTE* pbData, ULONG* pulDataLen);
typedef ULONG(DEVAPI *pSKF_GenerateAgreementDataWithECC)(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob, BYTE* pbID, ULONG ulIDLen, HANDLE *phAgreementHandle);
typedef ULONG(DEVAPI *pSKF_GenerateAgreementDataWithECCEx)(HCONTAINER hContainer, ULONG ulAlgId, ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob, BYTE* pbID, ULONG ulIDLen, HANDLE *phAgreementHandle);
typedef ULONG(DEVAPI *pSKF_GenerateAgreementDataAndKeyWithECCEx)(HANDLE hContainer, ULONG ulAlgId,
	ECCPUBLICKEYBLOB*  pSponsorECCPubKeyBlob, ECCPUBLICKEYBLOB*  pSponsorTempECCPubKeyBlob,
	ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
	BYTE* pbID, ULONG ulIDLen, BYTE *pbSponsorID, ULONG ulSponsorIDLen,
	BYTE *pbAgreementKey,
	ULONG *pulAgreementKeyLen);
typedef ULONG(DEVAPI *pSKF_GenerateKeyWithECCEx)(HANDLE hAgreementHandle,
	ECCPUBLICKEYBLOB*  pECCPubKeyBlob,
	ECCPUBLICKEYBLOB*  pTempECCPubKeyBlob,
	BYTE* pbID, ULONG ulIDLen,
	BYTE *pbAgreementKey, ULONG *pulAgreementKeyLen);

unsigned int SMB_DEV_ArgsGet(SMB_CS_CertificateAttr *pCertAttr, OPST_HANDLE_ARGS *args)
{
	OPST_HANDLE_ARGS tmpArgs = { 0 };

	for (std::map<std::string, OPST_HANDLE_ARGS>::iterator iter = g_currentArgs.begin(); iter != g_currentArgs.end(); iter++)
	{
		if (0 == strcmp(iter->first.c_str(), (char *)pCertAttr->stDeviceName.data))
		{
			tmpArgs = g_currentArgs[(char *)pCertAttr->stDeviceName.data];
			break;
		}
	}

	memcpy(args, &tmpArgs, sizeof(OPST_HANDLE_ARGS));

	//{
	//	char bufferShow[1024] = {0};

	//	sprintf(bufferShow,"PID=%d --- %d %d %d %d", GetCurrentProcessId(), args->ghInst, args->hAPP, args->hCon, args->hDev);

	//	if (IDYES == MessageBoxA(NULL,bufferShow, "SMB_DEV_ArgsGet", MB_ICONEXCLAMATION))
	//	{

	//	}
	//	else
	//	{
	//		
	//	}
	//}


	return 0;
}

unsigned int SMB_DEV_ArgsPut(SMB_CS_CertificateAttr *pCertAttr, OPST_HANDLE_ARGS *args)
{
	OPST_HANDLE_ARGS tmpArgs = { 0 };

	memcpy(&tmpArgs, args, sizeof(OPST_HANDLE_ARGS));

	g_currentArgs[(char *)pCertAttr->stDeviceName.data] = tmpArgs;

	//{
	//	char bufferShow[1024] = {0};

	//	sprintf(bufferShow,"PID=%d --- %d %d %d %d", GetCurrentProcessId(), args->ghInst, args->hAPP, args->hCon, args->hDev);

	//	if (IDYES == MessageBoxA(NULL,bufferShow, "SMB_DEV_ArgsPut", MB_ICONEXCLAMATION))
	//	{

	//	}
	//	else
	//	{

	//	}
	//}

	return 0;
}

unsigned int SMB_DEV_ArgsClr()
{
	g_currentArgs.clear();

	return 0;
}

std::map<std::string, HINSTANCE> g_currentInst;

HINSTANCE SMB_DEV_LoadLibrary(char *pszDllPath)
{
	HINSTANCE ghInst = NULL;

	for (std::map<std::string, HINSTANCE>::iterator iter = g_currentInst.begin(); iter != g_currentInst.end(); iter++)
	{
		if (0 == strcmp(iter->first.c_str(), pszDllPath))
		{
			ghInst = g_currentInst[pszDllPath];
			break;
		}
	}

	if (NULL == ghInst)
	{
		ghInst = LoadLibraryA(pszDllPath);
		g_currentInst[pszDllPath] = ghInst;
	}

	return ghInst;
}


unsigned int SMB_DEV_ChangePINByCertAttr(SMB_CS_CertificateAttr *pCertAttr, unsigned int ulPINType, char *pszOldPin, char *pszNewPin, ULONG *puiRetryCount)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev, );
	FUNC_NAME_DECLARE(func_, ConnectDev, );
	FUNC_NAME_DECLARE(func_, DisConnectDev, );
	FUNC_NAME_DECLARE(func_, ChangePIN, );
	FUNC_NAME_DECLARE(func_, OpenApplication, );
	FUNC_NAME_DECLARE(func_, CloseApplication, );
	FUNC_NAME_DECLARE(func_, EnumApplication, );
	FUNC_NAME_DECLARE(func_, ExportCertificate, );
	FUNC_NAME_DECLARE(func_, EnumContainer, );
	FUNC_NAME_DECLARE(func_, OpenContainer, );
	FUNC_NAME_DECLARE(func_, CloseContainer, );
	FUNC_NAME_DECLARE(func_, VerifyPIN, );
	FUNC_NAME_DECLARE(func_, GetContainerType, );
	FUNC_NAME_DECLARE(func_, ECCSignData, );
	FUNC_NAME_DECLARE(func_, ECCVerify, );
	FUNC_NAME_DECLARE(func_, ExtECCVerify, );
	FUNC_NAME_DECLARE(func_, GetDevInfo, );
	FUNC_NAME_DECLARE(func_, LockDev, );
	FUNC_NAME_DECLARE(func_, UnlockDev, );

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = 0;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;

	ulRet = SMB_CS_ReadSKFPath((const char *)pCertAttr->stSKFName.data, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev, );
	FUNC_NAME_INIT(func_, ConnectDev, );
	FUNC_NAME_INIT(func_, DisConnectDev, );
	FUNC_NAME_INIT(func_, ChangePIN, );
	FUNC_NAME_INIT(func_, OpenApplication, );
	FUNC_NAME_INIT(func_, CloseApplication, );
	FUNC_NAME_INIT(func_, EnumApplication, );
	FUNC_NAME_INIT(func_, ExportCertificate, );
	FUNC_NAME_INIT(func_, EnumContainer, );
	FUNC_NAME_INIT(func_, OpenContainer, );
	FUNC_NAME_INIT(func_, CloseContainer, );
	FUNC_NAME_INIT(func_, VerifyPIN, );
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType, );
	FUNC_NAME_INIT(func_, LockDev, );
	FUNC_NAME_INIT(func_, UnlockDev, );

	{
		ulRet = func_ConnectDev((char *)pCertAttr->stDeviceName.data, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if (ulRet = SDSCWaitMutex(mutex_buffer, INFINITE, &hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev, 0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		ulRet = func_OpenApplication(hDev, (char *)pCertAttr->stApplicationName.data, &hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_ChangePIN(hAPP, ulPINType, pszOldPin, pszNewPin, puiRetryCount);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_CloseApplication(hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif

		ulRet = func_DisConnectDev(hDev); hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}
	}

err:

	if (hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev); hDev = NULL;
	}

	if (ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}


	return ulRet;
}

unsigned int SMB_DEV_GetDevInfoByCertProperty(SMB_CS_CertificateAttr *pCertAttr, DEVINFO *pDevInfo)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev, );
	FUNC_NAME_DECLARE(func_, ConnectDev, );
	FUNC_NAME_DECLARE(func_, DisConnectDev, );
	FUNC_NAME_DECLARE(func_, ChangePIN, );
	FUNC_NAME_DECLARE(func_, OpenApplication, );
	FUNC_NAME_DECLARE(func_, CloseApplication, );
	FUNC_NAME_DECLARE(func_, EnumApplication, );
	FUNC_NAME_DECLARE(func_, ExportCertificate, );
	FUNC_NAME_DECLARE(func_, EnumContainer, );
	FUNC_NAME_DECLARE(func_, OpenContainer, );
	FUNC_NAME_DECLARE(func_, CloseContainer, );
	FUNC_NAME_DECLARE(func_, VerifyPIN, );
	FUNC_NAME_DECLARE(func_, GetContainerType, );
	FUNC_NAME_DECLARE(func_, ECCSignData, );
	FUNC_NAME_DECLARE(func_, ECCVerify, );
	FUNC_NAME_DECLARE(func_, ExtECCVerify, );
	FUNC_NAME_DECLARE(func_, GetDevInfo, );
	FUNC_NAME_DECLARE(func_, LockDev, );
	FUNC_NAME_DECLARE(func_, UnlockDev, );

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = 0;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;

	// 读取路径
	ulRet = SMB_CS_ReadSKFPath((char *)pCertAttr->stSKFName.data, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev, );
	FUNC_NAME_INIT(func_, ConnectDev, );
	FUNC_NAME_INIT(func_, DisConnectDev, );
	FUNC_NAME_INIT(func_, ChangePIN, );
	FUNC_NAME_INIT(func_, OpenApplication, );
	FUNC_NAME_INIT(func_, CloseApplication, );
	FUNC_NAME_INIT(func_, EnumApplication, );
	FUNC_NAME_INIT(func_, ExportCertificate, );
	FUNC_NAME_INIT(func_, EnumContainer, );
	FUNC_NAME_INIT(func_, OpenContainer, );
	FUNC_NAME_INIT(func_, CloseContainer, );
	FUNC_NAME_INIT(func_, VerifyPIN, );
	FUNC_NAME_INIT(func_, GetDevInfo, );
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType, );
	FUNC_NAME_INIT(func_, LockDev, );
	FUNC_NAME_INIT(func_, UnlockDev, );

	// 获取设备信息
	{


		ulRet = func_ConnectDev((char *)pCertAttr->stDeviceName.data, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if (ulRet = SDSCWaitMutex(mutex_buffer, INFINITE, &hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev, 0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		ulRet = func_GetDevInfo(hDev, pDevInfo);
		if (0 != ulRet)
		{
			goto err;
		}

		if (hDev)
		{
#if USE_SELF_MUTEX
			SDSCReleaseMutex(hMutex);
#else
			func_UnlockDev(hDev);
#endif
			ulRet = func_DisConnectDev(hDev); hDev = NULL;
		}
	}


err:

	if (hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev); hDev = NULL;
	}

	if (ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}

	return ulRet;
}


unsigned int SMB_DEV_VerifyPINByCertProperty(SMB_CS_CertificateAttr *pCertAttr, unsigned int ulPINType, char *pszPin, ULONG *puiRetryCount)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev, );
	FUNC_NAME_DECLARE(func_, ConnectDev, );
	FUNC_NAME_DECLARE(func_, DisConnectDev, );
	FUNC_NAME_DECLARE(func_, ChangePIN, );
	FUNC_NAME_DECLARE(func_, OpenApplication, );
	FUNC_NAME_DECLARE(func_, CloseApplication, );
	FUNC_NAME_DECLARE(func_, EnumApplication, );
	FUNC_NAME_DECLARE(func_, ExportCertificate, );
	FUNC_NAME_DECLARE(func_, EnumContainer, );
	FUNC_NAME_DECLARE(func_, OpenContainer, );
	FUNC_NAME_DECLARE(func_, CloseContainer, );
	FUNC_NAME_DECLARE(func_, VerifyPIN, );
	FUNC_NAME_DECLARE(func_, GetContainerType, );
	FUNC_NAME_DECLARE(func_, ECCSignData, );
	FUNC_NAME_DECLARE(func_, ECCVerify, );
	FUNC_NAME_DECLARE(func_, ExtECCVerify, );
	FUNC_NAME_DECLARE(func_, GetDevInfo, );
	FUNC_NAME_DECLARE(func_, LockDev, );
	FUNC_NAME_DECLARE(func_, UnlockDev, );

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = 0;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;

	ulRet = SMB_CS_ReadSKFPath((char *)pCertAttr->stSKFName.data, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev, );
	FUNC_NAME_INIT(func_, ConnectDev, );
	FUNC_NAME_INIT(func_, DisConnectDev, );
	FUNC_NAME_INIT(func_, ChangePIN, );
	FUNC_NAME_INIT(func_, OpenApplication, );
	FUNC_NAME_INIT(func_, CloseApplication, );
	FUNC_NAME_INIT(func_, EnumApplication, );
	FUNC_NAME_INIT(func_, ExportCertificate, );
	FUNC_NAME_INIT(func_, EnumContainer, );
	FUNC_NAME_INIT(func_, OpenContainer, );
	FUNC_NAME_INIT(func_, CloseContainer, );
	FUNC_NAME_INIT(func_, VerifyPIN, );
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType, );
	FUNC_NAME_INIT(func_, LockDev, );
	FUNC_NAME_INIT(func_, UnlockDev, );

	{


		ulRet = func_ConnectDev((char *)pCertAttr->stDeviceName.data, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if (ulRet = SDSCWaitMutex(mutex_buffer, INFINITE, &hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev, 0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		ulRet = func_OpenApplication(hDev, (char *)pCertAttr->stApplicationName.data, &hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_VerifyPIN(hAPP, ulPINType, pszPin, puiRetryCount);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_CloseApplication(hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif

		ulRet = func_DisConnectDev(hDev); hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}
	}

err:

	if (hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev); hDev = NULL;
	}

	if (ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}

	return ulRet;
}


unsigned int SMB_DEV_SM2SignDigest(
	SMB_CS_CertificateAttr *pCertAttr,
	char *pszPIN,
	BYTE *pbDigest, unsigned int uiDigestLen,
	BYTE *pbData, unsigned int uiDataLen,
	PECCSIGNATUREBLOB pSignature, ULONG *puiRetryCount)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev, );
	FUNC_NAME_DECLARE(func_, ConnectDev, );
	FUNC_NAME_DECLARE(func_, DisConnectDev, );
	FUNC_NAME_DECLARE(func_, ChangePIN, );
	FUNC_NAME_DECLARE(func_, OpenApplication, );
	FUNC_NAME_DECLARE(func_, CloseApplication, );
	FUNC_NAME_DECLARE(func_, EnumApplication, );
	FUNC_NAME_DECLARE(func_, ExportCertificate, );
	FUNC_NAME_DECLARE(func_, EnumContainer, );
	FUNC_NAME_DECLARE(func_, OpenContainer, );
	FUNC_NAME_DECLARE(func_, CloseContainer, );
	FUNC_NAME_DECLARE(func_, VerifyPIN, );
	FUNC_NAME_DECLARE(func_, GetContainerType, );
	FUNC_NAME_DECLARE(func_, ECCSignData, );
	FUNC_NAME_DECLARE(func_, ECCVerify, );
	FUNC_NAME_DECLARE(func_, ExtECCVerify, );
	FUNC_NAME_DECLARE(func_, GetDevInfo, );
	FUNC_NAME_DECLARE(func_, LockDev, );
	FUNC_NAME_DECLARE(func_, UnlockDev, );

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = 0;


	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = { 0 };

	unsigned int signTypeLen = BUFFER_LEN_1K;
	char signTypeValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;

	ulRet = SMB_CS_ReadSKFPath((char *)pCertAttr->stSKFName.data, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

	// there may be fail, so don't judge return value
	SMB_CS_ReadSKFSignType((char *)pCertAttr->stSKFName.data, signTypeValue, &signTypeLen);

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev, );
	FUNC_NAME_INIT(func_, ConnectDev, );
	FUNC_NAME_INIT(func_, DisConnectDev, );
	FUNC_NAME_INIT(func_, ChangePIN, );
	FUNC_NAME_INIT(func_, OpenApplication, );
	FUNC_NAME_INIT(func_, CloseApplication, );
	FUNC_NAME_INIT(func_, EnumApplication, );
	FUNC_NAME_INIT(func_, ExportCertificate, );
	FUNC_NAME_INIT(func_, EnumContainer, );
	FUNC_NAME_INIT(func_, OpenContainer, );
	FUNC_NAME_INIT(func_, CloseContainer, );
	FUNC_NAME_INIT(func_, VerifyPIN, );
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType, );
	FUNC_NAME_INIT(func_, ECCSignData, );
	FUNC_NAME_INIT(func_, LockDev, );
	FUNC_NAME_INIT(func_, UnlockDev, );

	{
		ulRet = func_ConnectDev((char *)pCertAttr->stDeviceName.data, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}


		ulRet = func_OpenApplication(hDev, (char *)pCertAttr->stApplicationName.data, &hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_VerifyPIN(hAPP, 1, pszPIN, puiRetryCount);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_OpenContainer(hAPP, (char *)pCertAttr->stContainerName.data, &hCon);
		if (0 != ulRet)
		{
			goto err;
		}

		if (0 == memcmp("data", signTypeValue, 4))
		{
			ulRet = func_ECCSignData(hCon, pbData, uiDataLen, pSignature);
		}
		else
		{
			ulRet = func_ECCSignData(hCon, pbDigest, uiDigestLen, pSignature);
		}

		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_CloseContainer(hCon);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_CloseApplication(hAPP);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_DisConnectDev(hDev); hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}
	}

err:

	if (hDev)
	{
		func_DisConnectDev(hDev); hDev = NULL;
	}

	if (ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}

	return ulRet;
}


unsigned int SMB_DEV_FindEnCertificateByCertAttr(
	_In_ SMB_CS_CertificateAttr *pCertAttr, _Out_ unsigned char *pbCert, _Inout_ unsigned int *pulCertLen
)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev, );
	FUNC_NAME_DECLARE(func_, ConnectDev, );
	FUNC_NAME_DECLARE(func_, DisConnectDev, );
	FUNC_NAME_DECLARE(func_, ChangePIN, );
	FUNC_NAME_DECLARE(func_, OpenApplication, );
	FUNC_NAME_DECLARE(func_, CloseApplication, );
	FUNC_NAME_DECLARE(func_, EnumApplication, );
	FUNC_NAME_DECLARE(func_, ExportCertificate, );
	FUNC_NAME_DECLARE(func_, EnumContainer, );
	FUNC_NAME_DECLARE(func_, OpenContainer, );
	FUNC_NAME_DECLARE(func_, CloseContainer, );
	FUNC_NAME_DECLARE(func_, VerifyPIN, );
	FUNC_NAME_DECLARE(func_, GetContainerType, );
	FUNC_NAME_DECLARE(func_, ECCSignData, );
	FUNC_NAME_DECLARE(func_, ECCVerify, );
	FUNC_NAME_DECLARE(func_, ExtECCVerify, );
	FUNC_NAME_DECLARE(func_, GetDevInfo, );
	FUNC_NAME_DECLARE(func_, LockDev, );
	FUNC_NAME_DECLARE(func_, UnlockDev, );

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = -1;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;

	ulRet = SMB_CS_ReadSKFPath((char *)pCertAttr->stSKFName.data, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev, );
	FUNC_NAME_INIT(func_, ConnectDev, );
	FUNC_NAME_INIT(func_, DisConnectDev, );
	FUNC_NAME_INIT(func_, ChangePIN, );
	FUNC_NAME_INIT(func_, OpenApplication, );
	FUNC_NAME_INIT(func_, CloseApplication, );
	FUNC_NAME_INIT(func_, EnumApplication, );
	FUNC_NAME_INIT(func_, ExportCertificate, );
	FUNC_NAME_INIT(func_, EnumContainer, );
	FUNC_NAME_INIT(func_, OpenContainer, );
	FUNC_NAME_INIT(func_, CloseContainer, );
	FUNC_NAME_INIT(func_, VerifyPIN, );
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType, );
	FUNC_NAME_INIT(func_, ECCSignData, );
	FUNC_NAME_INIT(func_, LockDev, );
	FUNC_NAME_INIT(func_, UnlockDev, );


	ulRet = func_ConnectDev((char *)pCertAttr->stDeviceName.data, &hDev);
	if (0 != ulRet)
	{
		goto err;
	}

#if USE_SELF_MUTEX
	if (ulRet = SDSCWaitMutex(mutex_buffer, INFINITE, &hMutex))
	{
		goto err;
	}
#else
	ulRet = func_LockDev(hDev, 0xFFFFFFFF);
	if (0 != ulRet)
	{
		goto err;
	}
#endif

	ulRet = func_OpenApplication(hDev, (char *)pCertAttr->stApplicationName.data, &hAPP);
	if (0 != ulRet)
	{
		goto err;
	}

	ulRet = func_OpenContainer(hAPP, (char *)pCertAttr->stContainerName.data, &hCon);
	if (0 != ulRet)
	{
		goto err;
	}

	ulRet = func_ExportCertificate(hCon, FALSE, pbCert, (ULONG *)pulCertLen);

	ulRet = func_CloseContainer(hCon);
	if (0 != ulRet)
	{
		goto err;
	}

	ulRet = func_CloseApplication(hAPP);
	if (0 != ulRet)
	{
		goto err;
	}
#if USE_SELF_MUTEX
	SDSCReleaseMutex(hMutex);
#else
	func_UnlockDev(hDev);
#endif
	ulRet = func_DisConnectDev(hDev); hDev = NULL;
	if (0 != ulRet)
	{
		goto err;
	}

err:
	if (hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev); hDev = NULL;
	}

	if (ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}


	return ulRet;
}

unsigned int SMB_DEV_SM2VerifyDigest(ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature)
{
	unsigned int ulRet = 0;

	unsigned int sigLen = SM2_BYTES_LEN *2;
	unsigned char sigValue[SM2_BYTES_LEN *2] = { 0 };

	memcpy(sigValue, pSignature->r + SM2_BYTES_LEN, SM2_BYTES_LEN);
	memcpy(sigValue + SM2_BYTES_LEN, pSignature->s + SM2_BYTES_LEN, SM2_BYTES_LEN);

	ulRet = OpenSSL_Initialize();
	if (ulRet)
	{
		ulRet = -1;
		goto err;
	}

	ulRet = OpenSSL_SM2VerifyDigest(pbData, ulDataLen,
		sigValue, sigLen,
		pECCPubKeyBlob->XCoordinate + SM2_BYTES_LEN, SM2_BYTES_LEN,
		pECCPubKeyBlob->YCoordinate + SM2_BYTES_LEN, SM2_BYTES_LEN);

	if (ulRet)
	{
		// error;
	}
err:

	OpenSSL_Finalize();

	return ulRet;
}


unsigned int SMB_DEV_EnumCertBySKF(const char *pszSKFName, void *pvCertsValue, unsigned int *puiCertsLen, unsigned int ulKeyFlag, unsigned int ulSignFlag, unsigned int ulVerifyFlag, unsigned int ulFilterFlag)
{
	HINSTANCE ghInst = NULL;

	/*
	SKF函数地址
	*/

	FUNC_NAME_DECLARE(func_, EnumDev, );
	FUNC_NAME_DECLARE(func_, ConnectDev, );
	FUNC_NAME_DECLARE(func_, DisConnectDev, );
	FUNC_NAME_DECLARE(func_, ChangePIN, );
	FUNC_NAME_DECLARE(func_, OpenApplication, );
	FUNC_NAME_DECLARE(func_, CloseApplication, );
	FUNC_NAME_DECLARE(func_, EnumApplication, );
	FUNC_NAME_DECLARE(func_, ExportCertificate, );
	FUNC_NAME_DECLARE(func_, EnumContainer, );
	FUNC_NAME_DECLARE(func_, OpenContainer, );
	FUNC_NAME_DECLARE(func_, CloseContainer, );
	FUNC_NAME_DECLARE(func_, VerifyPIN, );
	FUNC_NAME_DECLARE(func_, GetContainerType, );
	FUNC_NAME_DECLARE(func_, ECCSignData, );
	FUNC_NAME_DECLARE(func_, ECCVerify, );
	FUNC_NAME_DECLARE(func_, ExtECCVerify, );
	FUNC_NAME_DECLARE(func_, GetDevInfo, );
	FUNC_NAME_DECLARE(func_, LockDev, );
	FUNC_NAME_DECLARE(func_, UnlockDev, );

	FUNC_NAME_DECLARE(func_, GenerateKeyWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECC, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_DECLARE(func_, GenerateAgreementDataAndKeyWithECCEx, );

	unsigned int ulRet = 0;
	int i = 0; // certs

	char *data_value = NULL;
	char *pTmp = NULL;

	unsigned int dllPathLen = BUFFER_LEN_1K;
	char dllPathValue[BUFFER_LEN_1K] = { 0 };

	char szConNames[BUFFER_LEN_1K] = { 0 };
	ULONG ulConSize = BUFFER_LEN_1K;

	HAPPLICATION hAPP = NULL;
	char szAppNames[BUFFER_LEN_1K] = { 0 };
	ULONG ulAppsSize = BUFFER_LEN_1K;

	char szDevs[BUFFER_LEN_1K];
	ULONG ulDevSize = BUFFER_LEN_1K;

	char *ptrContainer = NULL;
	char *ptrApp = NULL;
	char *ptrDev = NULL;

	unsigned int ulOutLen = 0;

	SMB_CS_CertificateContext *pCertCtx = NULL;

	DEVHANDLE hDev = NULL;

	char buffer_zero[BUFFER_LEN_1K] = { 0 };


	pTmp = (char *)malloc(BUFFER_LEN_1K *4);
	data_value = (char *)malloc(BUFFER_LEN_1K *BUFFER_LEN_1K);

	ulRet = SMB_CS_ReadSKFPath(pszSKFName, dllPathValue, &dllPathLen);

	if (0 != ulRet)
	{
		ulRet = EErr_SMB_DLL_REG_PATH;
		goto err;
	}

#if defined(USE_LOAD_LIBRARY)
	ghInst = LoadLibraryA(dllPathValue);//动态加载Dll
#else
	ghInst = SMB_DEV_LoadLibrary(dllPathValue);
#endif

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, EnumDev, );
	FUNC_NAME_INIT(func_, ConnectDev, );
	FUNC_NAME_INIT(func_, DisConnectDev, );
	FUNC_NAME_INIT(func_, ChangePIN, );
	FUNC_NAME_INIT(func_, OpenApplication, );
	FUNC_NAME_INIT(func_, CloseApplication, );
	FUNC_NAME_INIT(func_, EnumApplication, );
	FUNC_NAME_INIT(func_, ExportCertificate, );
	FUNC_NAME_INIT(func_, EnumContainer, );
	FUNC_NAME_INIT(func_, OpenContainer, );
	FUNC_NAME_INIT(func_, CloseContainer, );
	FUNC_NAME_INIT(func_, VerifyPIN, );
	FUNC_NAME_INIT_GetContainerType(func_, GetContainerType, );
	FUNC_NAME_INIT(func_, GetDevInfo, );
	FUNC_NAME_INIT(func_, LockDev, );
	FUNC_NAME_INIT(func_, UnlockDev, );


	pCertCtx = (SMB_CS_CertificateContext *)data_value;
	i = 0;
	ulOutLen = 0;
	ulRet = func_EnumDev(TRUE, szDevs, &ulDevSize);
	if (0 != ulRet)
	{
		goto err;
	}

	for (ptrDev = szDevs; (ptrDev < szDevs + ulDevSize) && *ptrDev != 0;)
	{
		DEVINFO devInfo;
		hDev = NULL;

		ulRet = func_ConnectDev(ptrDev, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		if (ulRet = SDSCWaitMutex(mutex_buffer, INFINITE, &hMutex))
		{
			goto err;
		}
#else
		ulRet = func_LockDev(hDev, 0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		//ulRet = func_GetDevInfo(hDev,&devInfo);
		//if (0 != ulRet)
		//{
		//	goto err;
		//}

		ulAppsSize = BUFFER_LEN_1K;

		ulRet = func_EnumApplication(hDev, szAppNames, &ulAppsSize);

		if (0 != ulRet)
		{
			goto err;
		}

		for (ptrApp = szAppNames; (ptrApp < szAppNames + ulAppsSize) && *ptrApp != 0;)
		{
			ulConSize = BUFFER_LEN_1K;

			ulRet = func_OpenApplication(hDev, ptrApp, &hAPP);

			if (0 != ulRet)
			{
				goto err;
			}

			ulRet = func_EnumContainer(hAPP, szConNames, &ulConSize);

			//while (ulRet == 0 && 0 == memcmp(buffer_zero,szConNames,ulConSize > BUFFER_LEN_1K? BUFFER_LEN_1K:ulConSize))
			//{
			//	ulConSize = BUFFER_LEN_1K;
			//	ulRet = func_EnumContainer(hAPP,szConNames,&ulConSize);
			//}

			if (0 != ulRet)
			{
				goto err;
			}

			if (0 == ulConSize)
			{
				ulRet = EErr_SMB_DLL_PATH;
				goto err;
			}

			for (ptrContainer = szConNames; (ptrContainer < szConNames + ulConSize) && *ptrContainer != 0; )
			{
				HCONTAINER hCon = NULL;
				ULONG ulContainerType = 0;



				ulRet = func_OpenContainer(hAPP, ptrContainer, &hCon);
				if (ulRet)
				{
					goto err;
				}

				//1表示为RSA容器，为2表示为ECC容器
				ulRet = func_GetContainerType(hCon, &ulContainerType);
				if (ulRet)
				{
					goto err;
				}

				if (!(ulKeyFlag & ulContainerType))
				{
					// next Container
					ptrContainer += strlen(ptrContainer);
					ptrContainer += 1;
					continue;
				}

				if (CERT_SIGN_FLAG & ulSignFlag)
				{
					ULONG nValueLen = BUFFER_LEN_1K *4;

					nValueLen = BUFFER_LEN_1K *4;

					ulRet = func_ExportCertificate(hCon, TRUE, pTmp, &nValueLen);

					if ((0 == ulRet) && (nValueLen != 0))
					{
						if (ulVerifyFlag)
						{
							ulRet = SMB_DEV_VerifyCert(ulVerifyFlag, ulContainerType, pTmp, nValueLen);

							if (ulRet)
							{
								// next Container
								if (CERT_FILTER_FLAG_TRUE == ulFilterFlag)
								{
									ptrContainer += strlen(ptrContainer);
									ptrContainer += 1;

									continue;
								}
								else
								{
									switch (ulRet) {
									case EErr_SMB_VERIFY_TIME:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_TIME_INVALID;
										break;
									case EErr_SMB_NO_CERT_CHAIN:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_CHAIN_INVALID;
										break;
									case EErr_SMB_VERIFY_CERT:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_SIGN_INVALID;
										break;
									default:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_CHAIN_INVALID;
										break;
									}
								}

							}
							else
							{
								pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_FLAG_OK;
							}

						}

						ulOutLen += nValueLen + sizeof(SMB_CS_CertificateContext);

						pCertCtx->nValueLen = nValueLen;

						pCertCtx->pbValue = (BYTE *)pCertCtx + sizeof(SMB_CS_CertificateContext);

						memcpy(pCertCtx->pbValue, pTmp, nValueLen);

						strcpy(pCertCtx->stProperty.szSKFName, pszSKFName);

						strcpy(pCertCtx->stProperty.szDeviceName, ptrDev);

						strcpy(pCertCtx->stProperty.szApplicationName, ptrApp);

						strcpy(pCertCtx->stProperty.szContainerName, ptrContainer);

						pCertCtx->stProperty.bSignType = TRUE;

						pCertCtx->stProperty.nType = ulContainerType;

						pCertCtx = (BYTE*)pCertCtx + nValueLen + sizeof(SMB_CS_CertificateContext);

						i++;
					}
					else if (0x0A00001C == ulRet)
					{
						// 证书未发现
						ulRet = 0;
					}
					else
					{

					}
				}

				if (CERT_EX_FLAG & ulSignFlag)
				{
					ULONG nValueLen = BUFFER_LEN_1K *4;

					nValueLen = BUFFER_LEN_1K *4;

					ulRet = func_ExportCertificate(hCon, FALSE, pTmp, &nValueLen);

					if ((0 == ulRet) && (nValueLen != 0))
					{
						if (ulVerifyFlag)
						{
							ulRet = SMB_DEV_VerifyCert(ulVerifyFlag, ulContainerType, pTmp, nValueLen);

							if (ulRet)
							{
								// next Container
								if (CERT_FILTER_FLAG_TRUE == ulFilterFlag)
								{
									ptrContainer += strlen(ptrContainer);
									ptrContainer += 1;

									continue;
								}
								else
								{
									switch (ulRet) {
									case EErr_SMB_VERIFY_TIME:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_TIME_INVALID;
										break;
									case EErr_SMB_NO_CERT_CHAIN:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_CHAIN_INVALID;
										break;
									case EErr_SMB_VERIFY_CERT:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_SIGN_INVALID;
										break;
									default:
										pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_CHAIN_INVALID;
										break;
									}
								}

							}
							else
							{
								pCertCtx->stProperty.ulVerify = CERT_VERIFY_RESULT_FLAG_OK;
							}
						}

						ulOutLen += nValueLen + sizeof(SMB_CS_CertificateContext);

						pCertCtx->nValueLen = nValueLen;

						pCertCtx->pbValue = (BYTE *)pCertCtx + sizeof(SMB_CS_CertificateContext);

						memcpy(pCertCtx->pbValue, pTmp, nValueLen);

						strcpy(pCertCtx->stProperty.szSKFName, pszSKFName);

						strcpy(pCertCtx->stProperty.szDeviceName, ptrDev);

						strcpy(pCertCtx->stProperty.szApplicationName, ptrApp);

						strcpy(pCertCtx->stProperty.szContainerName, ptrContainer);

						pCertCtx->stProperty.bSignType = FALSE;

						pCertCtx->stProperty.nType = ulContainerType;

						pCertCtx = (BYTE*)pCertCtx + nValueLen + sizeof(SMB_CS_CertificateContext);

						i++;
					}
					else if (0x0A00001C == ulRet)
					{
						// 证书未发现
						ulRet = 0;
					}
					else
					{

					}
				}

				ulRet = func_CloseContainer(hCon);
				if (ulRet)
				{
					goto err;
				}

				// next Container
				ptrContainer += strlen(ptrContainer);
				ptrContainer += 1;
			}

			ulRet = func_CloseApplication(hAPP);
			if (0 != ulRet)
			{
				goto err;
			}

			// next Application
			ptrApp += strlen(ptrApp);
			ptrApp += 1;
		}


#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		ulRet = func_DisConnectDev(hDev); hDev = NULL;
		if (0 != ulRet)
		{
			goto err;
		}

		ptrDev += strlen(ptrDev);
		ptrDev += 1;
	}

	ulRet = -1;

	if (NULL == pvCertsValue)
	{
		*puiCertsLen = ulOutLen;

		ulRet = 0;

		goto err;
	}
	else if (*puiCertsLen < ulOutLen)
	{
		*puiCertsLen = ulOutLen;

		ulRet = EErr_SMB_MEM_LES;

		goto err;
	}
	else
	{
		memcpy(pvCertsValue, data_value, ulOutLen);

		for (pCertCtx = (SMB_CS_CertificateContext *)pvCertsValue; (char *)pCertCtx < (char *)pvCertsValue + ulOutLen;)
		{
			pCertCtx->pbValue = (BYTE *)pCertCtx + sizeof(SMB_CS_CertificateContext);

			SMB_DEV_CertGetProperty(pCertCtx->pbValue, pCertCtx->nValueLen, &(pCertCtx->stProperty));

			pCertCtx = (BYTE *)pCertCtx + pCertCtx->nValueLen + sizeof(SMB_CS_CertificateContext);
		}

		*puiCertsLen = ulOutLen;
		ulRet = 0;
	}

err:
	if (hDev)
	{
#if USE_SELF_MUTEX
		SDSCReleaseMutex(hMutex);
#else
		func_UnlockDev(hDev);
#endif
		func_DisConnectDev(hDev); hDev = NULL;
	}

	if (ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}


	if (pTmp)
	{
		free(pTmp);
	}

	if (data_value)
	{
		free(data_value);
		data_value = NULL;
	}

	return ulRet;
}

