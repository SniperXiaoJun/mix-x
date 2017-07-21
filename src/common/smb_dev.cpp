#include "smb_dev.h"
#include "smb_cs_inner.h"
#include <map>
#include <string>

#include "time.h"
#include "openssl_func_def.h"
#include "o_all_func_def.h"
#include "smcert.h"
#include "FILE_LOG.h"
#include "SKFError.h"
#include "certificate_items_parse.h"

#if USE_SELF_MUTEX
#include "mix-mutex.h"
static char mutex_buffer[25] = "mutex_smc_interface";
HANDLE hMutex = 0;
#endif

typedef struct _OPST_HANDLE_ARGS {
	void*ghInst;
	void*hDev;
	void*hAPP;
	void*hCon;
}OPST_HANDLE_ARGS;
COMMON_API unsigned int CALL_CONVENTION SMB_DEV_ArgsGet(SMB_CS_CertificateAttr*pCertAttr, OPST_HANDLE_ARGS*args);
COMMON_API unsigned int CALL_CONVENTION SMB_DEV_ArgsPut(SMB_CS_CertificateAttr*pCertAttr, OPST_HANDLE_ARGS*args);
COMMON_API unsigned int CALL_CONVENTION SMB_DEV_ArgsClr();
COMMON_API unsigned int CALL_CONVENTION SMB_DEV_SM2SignInitialize(SMB_CS_CertificateAttr*pCertAttr, OPST_HANDLE_ARGS *args);
COMMON_API unsigned int CALL_CONVENTION SMB_DEV_SM2SignFinalize(OPST_HANDLE_ARGS *args);
COMMON_API unsigned int CALL_CONVENTION SMB_DEV_SM2SignProcess(OPST_HANDLE_ARGS *args,
	SMB_CS_CertificateAttr *pCertAttr,
	char *pszPIN,
	BYTE *pbDigest, unsigned int uiDigestLen,
	BYTE *pbData, unsigned int uiDataLen,
	PECCSIGNATUREBLOB pSignature, ULONG *puiRetryCount);

COMMON_API HINSTANCE SMB_DEV_LoadLibrary(char*pszDllPath);

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

COMMON_API unsigned int CALL_CONVENTION SMB_DEV_ArgsGet(SMB_CS_CertificateAttr *pCertAttr, OPST_HANDLE_ARGS *args)
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

COMMON_API unsigned int CALL_CONVENTION SMB_DEV_ArgsPut(SMB_CS_CertificateAttr *pCertAttr, OPST_HANDLE_ARGS *args)
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

COMMON_API unsigned int CALL_CONVENTION SMB_DEV_ArgsClr()
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


COMMON_API unsigned int CALL_CONVENTION SMB_DEV_ChangePINByCertAttr(SMB_CS_CertificateAttr *pCertAttr, unsigned int ulPINType, char *pszOldPin, char *pszNewPin, ULONG *puiRetryCount)
{
	HINSTANCE ghInst = NULL;

#if USE_SELF_MUTEX
	UseMixMutex mutex("mutex_dev");
#endif

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

	char dllPathValue[BUFFER_LEN_1K] = { 0 };
	char signTypeValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;

	SMB_CS_SKF_NODE *pPtr = NULL;
	SMB_CS_SKF_NODE *pHeader = NULL;

	SMB_CS_EnumSKF(&pHeader);

	for (pPtr = pHeader; pPtr; pPtr = pPtr->ptr_next)
	{
		if (0 == memcmp(pPtr->ptr_data->stName.data, pCertAttr->stSKFName.data, pCertAttr->stSKFName.length>pPtr->ptr_data->stName.length ? pCertAttr->stSKFName.length - 1 : pPtr->ptr_data->stName.length - 1))
		{
			memcpy(dllPathValue, pPtr->ptr_data->stPath.data, pPtr->ptr_data->stPath.length);
			memcpy(signTypeValue, pPtr->ptr_data->stSignType.data, pPtr->ptr_data->stSignType.length);
			break;
		}
	}

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

	if (pHeader)
	{
		SMB_CS_FreeSKFLink(&pHeader);
	}


	return ulRet;
}

COMMON_API unsigned int CALL_CONVENTION SMB_DEV_GetDevInfoByCertAttr(SMB_CS_CertificateAttr *pCertAttr, DEVINFO *pDevInfo)
{
	HINSTANCE ghInst = NULL;

#if USE_SELF_MUTEX
	UseMixMutex mutex("mutex_dev");
#endif

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

	char dllPathValue[BUFFER_LEN_1K] = { 0 };
	char signTypeValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;

	// 读取路径
	SMB_CS_SKF_NODE *pPtr = NULL;
	SMB_CS_SKF_NODE *pHeader = NULL;

	SMB_CS_EnumSKF(&pHeader);

	for (pPtr = pHeader; pPtr; pPtr = pPtr->ptr_next)
	{
		if (0 == memcmp(pPtr->ptr_data->stName.data, pCertAttr->stSKFName.data, pCertAttr->stSKFName.length>pPtr->ptr_data->stName.length ? pCertAttr->stSKFName.length - 1 : pPtr->ptr_data->stName.length - 1))
		{
			memcpy(dllPathValue, pPtr->ptr_data->stPath.data, pPtr->ptr_data->stPath.length);
			memcpy(signTypeValue, pPtr->ptr_data->stSignType.data, pPtr->ptr_data->stSignType.length);
			break;
		}
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

	if (pHeader)
	{
		SMB_CS_FreeSKFLink(&pHeader);
	}

	return ulRet;
}


COMMON_API unsigned int CALL_CONVENTION SMB_DEV_VerifyPINByCertAttr(SMB_CS_CertificateAttr *pCertAttr, unsigned int ulPINType, char *pszPin, ULONG *puiRetryCount)
{
	HINSTANCE ghInst = NULL;

#if USE_SELF_MUTEX
	UseMixMutex mutex("mutex_dev");
#endif

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

	char dllPathValue[BUFFER_LEN_1K] = { 0 };
	char signTypeValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;

	SMB_CS_SKF_NODE *pPtr = NULL;
	SMB_CS_SKF_NODE *pHeader = NULL;

	SMB_CS_EnumSKF(&pHeader);

	for (pPtr = pHeader; pPtr; pPtr = pPtr->ptr_next)
	{
		if (0 == memcmp(pPtr->ptr_data->stName.data, pCertAttr->stSKFName.data, pCertAttr->stSKFName.length>pPtr->ptr_data->stName.length ? pCertAttr->stSKFName.length - 1 : pPtr->ptr_data->stName.length - 1))
		{
			memcpy(dllPathValue, pPtr->ptr_data->stPath.data, pPtr->ptr_data->stPath.length);
			memcpy(signTypeValue, pPtr->ptr_data->stSignType.data, pPtr->ptr_data->stSignType.length);
			break;
		}
	}

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

	if (pHeader)
	{
		SMB_CS_FreeSKFLink(&pHeader);
	}

	return ulRet;
}


COMMON_API unsigned int CALL_CONVENTION SMB_DEV_SM2SignProcess(OPST_HANDLE_ARGS *args,
	SMB_CS_CertificateAttr *pCertAttr,
	char *pszPIN,
	BYTE *pbDigest, unsigned int uiDigestLen,
	BYTE *pbData, unsigned int uiDataLen,
	PECCSIGNATUREBLOB pSignature, ULONG *puiRetryCount)
{
	HINSTANCE ghInst = NULL;
	unsigned int ulRet = 0;

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

	//FUNC_NAME_DECLARE(func_, GenRandom, );
	//FUNC_NAME_DECLARE(func_, Transmit, );


	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;

	char dllPathValue[BUFFER_LEN_1K] = { 0 };
	char signTypeValue[BUFFER_LEN_1K] = { 0 };
	char pinVerifyValue[BUFFER_LEN_1K] = { 0 };

	SMB_CS_SKF_NODE *pPtr = NULL;
	SMB_CS_SKF_NODE *pHeader = NULL;

	OPST_HANDLE_ARGS * handleArgs = args;

	if (handleArgs)
	{
		ghInst = (HINSTANCE)handleArgs->ghInst;
		hDev = handleArgs->hDev;
		hAPP = handleArgs->hAPP;
		hCon = handleArgs->hCon;
	}
	else
	{
		return EErr_SMB_FAIL;
	}

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	SMB_CS_EnumSKF(&pHeader);

	for (pPtr = pHeader; pPtr; pPtr = pPtr->ptr_next)
	{
		if (0 == memcmp(pPtr->ptr_data->stName.data, pCertAttr->stSKFName.data, pCertAttr->stSKFName.length>pPtr->ptr_data->stName.length ? pCertAttr->stSKFName.length - 1 : pPtr->ptr_data->stName.length - 1))
		{
			memcpy(dllPathValue, pPtr->ptr_data->stPath.data, pPtr->ptr_data->stPath.length);
			memcpy(signTypeValue, pPtr->ptr_data->stSignType.data, pPtr->ptr_data->stSignType.length);
			memcpy(pinVerifyValue, pPtr->ptr_data->stPinVerify.data, pPtr->ptr_data->stPinVerify.length);
			break;
		}
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

	FUNC_NAME_INIT(func_, ECCSignData, );

	//FUNC_NAME_INIT(func_, GenRandom, );
	//FUNC_NAME_INIT(func_, Transmit, );

#if USE_SELF_MUTEX

#else
	ulRet = func_LockDev(hDev, 0xFFFFFFFF);
	if (0 != ulRet)
	{
		goto err;
	}
#endif

	{
		if (hCon)
		{

			//  "0" || "" ：标准PIN有效使用
			//	"1"：无需调用校验PIN接口
			//	"2"：PIN无效，但需调用校验PIN接口
			if (0 == memcmp("2", pinVerifyValue, 1))
			{
				ulRet = func_VerifyPIN(hAPP, 1, pszPIN, puiRetryCount);
				if (0 != ulRet)
				{
					goto err;
				}
			}
			else if (0 == memcmp("1", pinVerifyValue, 1))
			{

			}
			else if (0 == memcmp("0", pinVerifyValue, 1))
			{
				ulRet = func_VerifyPIN(hAPP, 1, pszPIN, puiRetryCount);
				if (0 != ulRet)
				{
					goto err;
				}
			}
			else if (0 == memcmp("", pinVerifyValue, 1))
			{
				ulRet = func_VerifyPIN(hAPP, 1, pszPIN, puiRetryCount);
				if (0 != ulRet)
				{
					goto err;
				}
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
		}
		else
		{
			ulRet = EErr_SMB_FAIL;
		}
	}

err:

	if (pHeader)
	{
		SMB_CS_FreeSKFLink(&pHeader);
	}

	if (hDev)
	{
#if USE_SELF_MUTEX

#else
		func_UnlockDev(hDev);
#endif
	}


	return ulRet;
}


COMMON_API unsigned int CALL_CONVENTION SMB_DEV_SM2SignByCertAttr(
	SMB_CS_CertificateAttr *pCertAttr,
	char *pszPIN,
	BYTE *pbDigest, unsigned int uiDigestLen,
	BYTE *pbData, unsigned int uiDataLen,
	PECCSIGNATUREBLOB pSignature, ULONG *puiRetryCount)
{
	OPST_HANDLE_ARGS args = { 0 };
	OPST_HANDLE_ARGS argsZERO = { 0 };
	unsigned int ulRet = 0;

	ulRet = SMB_DEV_ArgsGet(pCertAttr, &args);
	if (0 != ulRet)
	{
		goto err;
	}

	if (0 == memcmp(&args, &argsZERO, sizeof(OPST_HANDLE_ARGS)))
	{
		ulRet = SMB_DEV_SM2SignInitialize(pCertAttr, &args);

		SMB_DEV_ArgsPut(pCertAttr, &args);

		if (0 != ulRet)
		{
			goto err;
		}
	}

	ulRet = SMB_DEV_SM2SignProcess(&args, pCertAttr, pszPIN, pbDigest, uiDigestLen, pbData, uiDataLen, pSignature, puiRetryCount);
	if (SAR_FAIL == ulRet)
	{
		SMB_DEV_SM2SignFinalize(&args);
		memcpy(&args, &argsZERO, sizeof(OPST_HANDLE_ARGS));
		ulRet = SMB_DEV_SM2SignInitialize(pCertAttr, &args);

		SMB_DEV_ArgsPut(pCertAttr, &args);

		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = SMB_DEV_SM2SignProcess(&args, pCertAttr, pszPIN, pbDigest, uiDigestLen, pbData, uiDataLen, pSignature, puiRetryCount);

		if (0 != ulRet)
		{
			goto err;
		}
	}

err:
	if (ulRet)
	{
		SMB_DEV_SM2SignFinalize(&args);
		SMB_DEV_ArgsClr();
	}

	return ulRet;
}

COMMON_API unsigned int CALL_CONVENTION SMB_DEV_FindEnCertificateByCertAttr(
	IN SMB_CS_CertificateAttr *pCertAttr, OUT unsigned char *pbCert, IN OUT unsigned int *pulCertLen
)
{
	HINSTANCE ghInst = NULL;

#if USE_SELF_MUTEX
	UseMixMutex mutex("mutex_dev");
#endif

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

	char dllPathValue[BUFFER_LEN_1K] = { 0 };
	char signTypeValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;

	SMB_CS_SKF_NODE *pPtr = NULL;
	SMB_CS_SKF_NODE *pHeader = NULL;

	SMB_CS_EnumSKF(&pHeader);

	for (pPtr = pHeader; pPtr; pPtr = pPtr->ptr_next)
	{
		if (0 == memcmp(pPtr->ptr_data->stName.data, pCertAttr->stSKFName.data, pCertAttr->stSKFName.length>pPtr->ptr_data->stName.length ? pCertAttr->stSKFName.length-1 : pPtr->ptr_data->stName.length-1))
		{
			memcpy(dllPathValue, pPtr->ptr_data->stPath.data, pPtr->ptr_data->stPath.length);
			memcpy(signTypeValue, pPtr->ptr_data->stSignType.data, pPtr->ptr_data->stSignType.length);
			break;
		}
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

	if (pHeader)
	{
		SMB_CS_FreeSKFLink(&pHeader);
	}


	return ulRet;
}

COMMON_API unsigned int CALL_CONVENTION SMB_DEV_SM2VerifyDigest(ECCPUBLICKEYBLOB* pECCPubKeyBlob, BYTE *pbData, ULONG  ulDataLen, PECCSIGNATUREBLOB pSignature)
{
	unsigned int ulRet = 0;

	unsigned int sigLen = SM2_BYTES_LEN * 2;
	unsigned char sigValue[SM2_BYTES_LEN * 2] = { 0 };

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


COMMON_API unsigned int CALL_CONVENTION SMB_DEV_EnumCertBySKF(const char *pszSKFName, SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader, unsigned int uiKeyFlag, unsigned int uiUsageFlag, unsigned int uiVerifyFlag, unsigned int uiFilterFlag)
{
	HINSTANCE ghInst = NULL;

#if USE_SELF_MUTEX
	UseMixMutex mutex("mutex_dev");
#endif

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

	BYTE *pTmp = NULL;

	char dllPathValue[BUFFER_LEN_1K] = { 0 };
	char signTypeValue[BUFFER_LEN_1K] = { 0 };

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

	SMB_CS_CertificateContext_NODE *pCtxNode = NULL;

	DEVHANDLE hDev = NULL;

	if (0 == ppCertCtxNodeHeader)
	{
		ulRet = EErr_SMB_INVALID_ARG;
		goto err;
	}

	pTmp = (BYTE *)malloc(BUFFER_LEN_1K * 4);

	SMB_CS_SKF_NODE *pPtr = NULL;
	SMB_CS_SKF_NODE *pHeader = NULL;

	SMB_CS_EnumSKF(&pHeader);

	for (pPtr = pHeader; pPtr; pPtr = pPtr->ptr_next)
	{
		if (0 == memcmp(pPtr->ptr_data->stName.data, pszSKFName, strlen(pszSKFName)))
		{
			memcpy(dllPathValue, pPtr->ptr_data->stPath.data, pPtr->ptr_data->stPath.length);
			memcpy(signTypeValue, pPtr->ptr_data->stSignType.data, pPtr->ptr_data->stSignType.length);
			break;
		}
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

	ulRet = func_EnumDev(TRUE, szDevs, &ulDevSize);
	if (0 != ulRet)
	{
		goto err;
	}

	for (ptrDev = szDevs; (ptrDev < szDevs + ulDevSize) && *ptrDev != 0;)
	{
		hDev = NULL;

		ulRet = func_ConnectDev(ptrDev, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		
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

				if (!(uiKeyFlag & ulContainerType))
				{
					// next Container
					ptrContainer += strlen(ptrContainer);
					ptrContainer += 1;
					continue;
				}

				if (SMB_CERT_USAGE_FLAG_SIGN & uiUsageFlag)
				{
					ULONG nValueLen = BUFFER_LEN_1K * 4;

					nValueLen = BUFFER_LEN_1K * 4;

					ulRet = func_ExportCertificate(hCon, TRUE, pTmp, &nValueLen);

					if ((0 == ulRet) && (nValueLen != 0))
					{
						if (uiVerifyFlag)
						{
							ulRet = SMB_CS_VerifyCert(uiVerifyFlag, pTmp, nValueLen);

							if (ulRet)
							{
								// next Container
								if (SMB_CERT_FILTER_FLAG_TRUE == uiFilterFlag)
								{
									ptrContainer += strlen(ptrContainer);
									ptrContainer += 1;

									continue;
								}
							}

						}

						{
							SMB_CS_CertificateContext *pCertCtx = (SMB_CS_CertificateContext *)malloc(sizeof(SMB_CS_CertificateContext));

							memset(pCertCtx, 0, sizeof(SMB_CS_CertificateContext));

							if (uiVerifyFlag)
							{
								switch (ulRet) {
								case 0:
									pCertCtx->stAttr.ulVerify = SMB_CERT_VERIFY_RESULT_FLAG_OK;
									break;
								case EErr_SMB_VERIFY_TIME:
									pCertCtx->stAttr.ulVerify = SMB_CERT_VERIFY_RESULT_FLAG_TIME_INVALID;
									break;
								case EErr_SMB_NO_CERT_CHAIN:
									pCertCtx->stAttr.ulVerify = SMB_CERT_VERIFY_RESULT_FLAG_CHAIN_INVALID;
									break;
								case EErr_SMB_VERIFY_CERT:
									pCertCtx->stAttr.ulVerify = SMB_CERT_VERIFY_RESULT_FLAG_SIGN_INVALID;
									break;
								default:
									pCertCtx->stAttr.ulVerify = SMB_CERT_VERIFY_RESULT_FLAG_CHAIN_INVALID;
									break;
								}
							}

							pCertCtx->stContent.length = nValueLen;
							pCertCtx->stContent.data = (unsigned char *)malloc(pCertCtx->stContent.length);
							memcpy(pCertCtx->stContent.data, pTmp, pCertCtx->stContent.length);

							pCertCtx->stAttr.stSKFName.length = strlen(pszSKFName) + 1;
							pCertCtx->stAttr.stSKFName.data = (unsigned char *)malloc(pCertCtx->stAttr.stSKFName.length);
							memcpy(pCertCtx->stAttr.stSKFName.data, pszSKFName, pCertCtx->stAttr.stSKFName.length);

							pCertCtx->stAttr.stDeviceName.length = strlen(ptrDev) + 1;
							pCertCtx->stAttr.stDeviceName.data = (unsigned char *)malloc(pCertCtx->stAttr.stDeviceName.length);
							memcpy(pCertCtx->stAttr.stDeviceName.data, ptrDev, pCertCtx->stAttr.stDeviceName.length);

							pCertCtx->stAttr.stApplicationName.length = strlen(ptrApp) + 1;
							pCertCtx->stAttr.stApplicationName.data = (unsigned char *)malloc(pCertCtx->stAttr.stApplicationName.length);
							memcpy(pCertCtx->stAttr.stApplicationName.data, ptrApp, pCertCtx->stAttr.stApplicationName.length);

							pCertCtx->stAttr.stContainerName.length = strlen(ptrContainer) + 1;
							pCertCtx->stAttr.stContainerName.data = (unsigned char *)malloc(pCertCtx->stAttr.stContainerName.length);
							memcpy(pCertCtx->stAttr.stContainerName.data, ptrContainer, pCertCtx->stAttr.stContainerName.length);

							pCertCtx->stAttr.ucCertUsageType = 1; //	签名加密

							pCertCtx->stAttr.ucCertAlgType = ulContainerType; // RSA SM2

							OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppCertCtxNodeHeader, (void *)pCertCtx);
						}

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

				if (SMB_CERT_USAGE_FLAG_EX & uiUsageFlag)
				{
					ULONG nValueLen = BUFFER_LEN_1K * 4;

					nValueLen = BUFFER_LEN_1K * 4;

					ulRet = func_ExportCertificate(hCon, FALSE, pTmp, &nValueLen);

					if ((0 == ulRet) && (nValueLen != 0))
					{
						if (uiVerifyFlag)
						{
							ulRet = SMB_CS_VerifyCert(uiVerifyFlag, pTmp, nValueLen);

							if (ulRet)
							{
								// next Container
								if (SMB_CERT_FILTER_FLAG_TRUE == uiFilterFlag)
								{
									ptrContainer += strlen(ptrContainer);
									ptrContainer += 1;

									continue;
								}
							}
						}

						{
							SMB_CS_CertificateContext *pCertCtx = (SMB_CS_CertificateContext *)malloc(sizeof(SMB_CS_CertificateContext));

							memset(pCertCtx, 0, sizeof(SMB_CS_CertificateContext));

							if (uiVerifyFlag)
							{
								switch (ulRet) {
								case 0:
									pCertCtx->stAttr.ulVerify = SMB_CERT_VERIFY_RESULT_FLAG_OK;
									break;
								case EErr_SMB_VERIFY_TIME:
									pCertCtx->stAttr.ulVerify = SMB_CERT_VERIFY_RESULT_FLAG_TIME_INVALID;
									break;
								case EErr_SMB_NO_CERT_CHAIN:
									pCertCtx->stAttr.ulVerify = SMB_CERT_VERIFY_RESULT_FLAG_CHAIN_INVALID;
									break;
								case EErr_SMB_VERIFY_CERT:
									pCertCtx->stAttr.ulVerify = SMB_CERT_VERIFY_RESULT_FLAG_SIGN_INVALID;
									break;
								default:
									pCertCtx->stAttr.ulVerify = SMB_CERT_VERIFY_RESULT_FLAG_CHAIN_INVALID;
									break;
								}
							}

							pCertCtx->stContent.length = nValueLen;
							pCertCtx->stContent.data = (unsigned char *)malloc(pCertCtx->stContent.length);
							memcpy(pCertCtx->stContent.data, pTmp, pCertCtx->stContent.length);

							pCertCtx->stAttr.stSKFName.length = strlen(pszSKFName) + 1;
							pCertCtx->stAttr.stSKFName.data = (unsigned char *)malloc(pCertCtx->stAttr.stSKFName.length);
							memcpy(pCertCtx->stAttr.stSKFName.data, pszSKFName, pCertCtx->stAttr.stSKFName.length);

							pCertCtx->stAttr.stDeviceName.length = strlen(ptrDev) + 1;
							pCertCtx->stAttr.stDeviceName.data = (unsigned char *)malloc(pCertCtx->stAttr.stDeviceName.length);
							memcpy(pCertCtx->stAttr.stDeviceName.data, ptrDev, pCertCtx->stAttr.stDeviceName.length);

							pCertCtx->stAttr.stApplicationName.length = strlen(ptrApp) + 1;
							pCertCtx->stAttr.stApplicationName.data = (unsigned char *)malloc(pCertCtx->stAttr.stApplicationName.length);
							memcpy(pCertCtx->stAttr.stApplicationName.data, ptrApp, pCertCtx->stAttr.stApplicationName.length);

							pCertCtx->stAttr.stContainerName.length = strlen(ptrContainer) + 1;
							pCertCtx->stAttr.stContainerName.data = (unsigned char *)malloc(pCertCtx->stAttr.stContainerName.length);
							memcpy(pCertCtx->stAttr.stContainerName.data, ptrContainer, pCertCtx->stAttr.stContainerName.length);

							pCertCtx->stAttr.ucCertUsageType = 2; //	签名加密

							pCertCtx->stAttr.ucCertAlgType = ulContainerType; // RSA SM2

							OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppCertCtxNodeHeader, (void *)pCertCtx);
						}
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

	for (pCtxNode = *ppCertCtxNodeHeader; pCtxNode; pCtxNode = pCtxNode->ptr_next)
	{
		SMB_CS_FillCertAttr(pCtxNode->ptr_data);
	}

	ulRet = 0;
err:
	if (hDev)
	{
#if USE_SELF_MUTEX
		
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

	if (pHeader)
	{
		SMB_CS_FreeSKFLink(&pHeader);
	}

	return ulRet;
}

COMMON_API unsigned int CALL_CONVENTION SMB_DEV_EnumCert(SMB_CS_CertificateContext_NODE **ppCertCtxNodeHeader, unsigned int uiKeyFlag, unsigned int uiUsageFlag, unsigned int uiVerifyFlag, unsigned int uiFilterFlag)
{
	unsigned int ulRet = 0;

	SMB_CS_SKF_NODE *pPtr = NULL;
	SMB_CS_SKF_NODE *pHeader = NULL;

	SMB_CS_EnumSKF(&pHeader);

	for (pPtr = pHeader; pPtr; pPtr = pPtr->ptr_next)
	{
		char data_skf[32] = { 0 };

		memcpy(data_skf, pPtr->ptr_data->stName.data, pPtr->ptr_data->stName.length);

		ulRet = SMB_DEV_EnumCertBySKF(data_skf, ppCertCtxNodeHeader, uiKeyFlag, uiUsageFlag, uiVerifyFlag, uiFilterFlag);

		if (ulRet)
		{
			continue;
		}
	}

	ulRet = 0;

	if (pHeader)
	{
		SMB_CS_FreeSKFLink(&pHeader);
	}

	return ulRet;
}


COMMON_API unsigned int CALL_CONVENTION SMB_DEV_SM2SignInitialize(SMB_CS_CertificateAttr * pCertAttr, OPST_HANDLE_ARGS * args)
{
	HINSTANCE ghInst = NULL;

#if USE_SELF_MUTEX
	UseMixMutex mutex("mutex_dev");
#endif

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

	//FUNC_NAME_DECLARE(func_, GenRandom, );
	//FUNC_NAME_DECLARE(func_, Transmit, );


	unsigned int ulRet = 0;

	char dllPathValue[BUFFER_LEN_1K] = { 0 };
	char signTypeValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;

	SMB_CS_SKF_NODE *pPtr = NULL;
	SMB_CS_SKF_NODE *pHeader = NULL;

	SMB_CS_EnumSKF(&pHeader);

	for (pPtr = pHeader; pPtr; pPtr = pPtr->ptr_next)
	{
		if (0 == memcmp(pPtr->ptr_data->stName.data, pCertAttr->stSKFName.data, pCertAttr->stSKFName.length>pPtr->ptr_data->stName.length ? pCertAttr->stSKFName.length - 1 : pPtr->ptr_data->stName.length - 1))
		{
			memcpy(dllPathValue, pPtr->ptr_data->stPath.data, pPtr->ptr_data->stPath.length);
			memcpy(signTypeValue, pPtr->ptr_data->stSignType.data, pPtr->ptr_data->stSignType.length);
			break;
		}
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

	FUNC_NAME_INIT(func_, ECCSignData, );

	//FUNC_NAME_INIT(func_, GenRandom, );
	//FUNC_NAME_INIT(func_, Transmit, );

	{
		unsigned char bufferRandom[8] = { 0 };
		ULONG bufferRandomLen = 8;

		unsigned char szEncrypPin[BUFFER_LEN_1K] = { 0 };
		unsigned int uiEncryptPinLen = BUFFER_LEN_1K;


		ulRet = func_ConnectDev((char *)pCertAttr->stDeviceName.data, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX
		
#else
		ulRet = func_LockDev(hDev, 0xFFFFFFFF);
		if (0 != ulRet)
		{
			goto err;
		}
#endif

		FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, ulRet);
		ulRet = func_OpenApplication(hDev, (char *)pCertAttr->stApplicationName.data, &hAPP);
		if (0 != ulRet)
		{
			goto err;
		}
		FILE_LOG_FMT(file_log_name, "func=%s thread=%d line=%d watch=%d", __FUNCTION__, GetCurrentThreadId(), __LINE__, ulRet);

		ulRet = func_OpenContainer(hAPP, (char *)pCertAttr->stContainerName.data, &hCon);
		if (0 != ulRet)
		{
			goto err;
		}
		else
		{
			OPST_HANDLE_ARGS * handleArgs = args;

			if (handleArgs)
			{
				handleArgs->ghInst = ghInst;
				handleArgs->hDev = hDev;
				handleArgs->hAPP = hAPP;
				handleArgs->hCon = hCon;

				if (hCon)
				{

				}
				else
				{
					ulRet = EErr_SMB_FAIL;
					goto err;
				}

			}
			else
			{
				ulRet = EErr_SMB_FAIL;
				goto err;
			}

			return 0;
		}

		if (hCon)
		{
			func_CloseContainer(hCon); hCon = NULL;
		}

		ulRet = func_CloseApplication(hAPP);
		if (0 != ulRet)
		{
			goto err;
	}

#if USE_SELF_MUTEX
		
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

	if (hCon)
	{
		func_CloseContainer(hCon); hCon = NULL;
	}

	if (hDev)
	{
#if USE_SELF_MUTEX
		
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

	if (pHeader)
	{
		SMB_CS_FreeSKFLink(&pHeader);
	}

	return ulRet;
	}


COMMON_API unsigned int CALL_CONVENTION SMB_DEV_SM2SignFinalize(OPST_HANDLE_ARGS * args)
{
	HINSTANCE ghInst = NULL;
	unsigned int ulRet = 0;

	FUNC_NAME_DECLARE(func_, DisConnectDev, );
	FUNC_NAME_DECLARE(func_, CloseApplication, );
	FUNC_NAME_DECLARE(func_, CloseContainer, );
	FUNC_NAME_DECLARE(func_, UnlockDev, );

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;

	OPST_HANDLE_ARGS * handleArgs = args;


	if (handleArgs)
	{
		ghInst = (HINSTANCE)handleArgs->ghInst;
		hDev = handleArgs->hDev;
		hAPP = handleArgs->hAPP;
		hCon = handleArgs->hCon;
	}
	else
	{
		return EErr_SMB_FAIL;
	}

	if (!ghInst)
	{
		ulRet = EErr_SMB_DLL_PATH;
		goto err;
	}

	FUNC_NAME_INIT(func_, DisConnectDev, );
	FUNC_NAME_INIT(func_, CloseApplication, );
	FUNC_NAME_INIT(func_, CloseContainer, );
	FUNC_NAME_INIT(func_, UnlockDev, );

err:

	if (hCon)
	{
		func_CloseContainer(hCon); hCon = NULL;
	}

	if (hAPP)
	{
		func_CloseApplication(hAPP); hAPP = NULL;
	}

	if (hDev)
	{
#if USE_SELF_MUTEX
		
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

#if (defined(WIN32) || defined(WINDOWS))
#include "Cryptuiapi.h"
COMMON_API unsigned int CALL_CONVENTION SMB_UI_ShowCert(BYTE* pbCert, unsigned int ulCertLen)
{
	//2.获取CertContext
	PCCERT_CONTEXT pCertContext = NULL;
	unsigned int ulRet = 0;

	pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pbCert, ulCertLen);

	if (NULL == pCertContext)
	{
		ulRet = EErr_SMB_CREATE_CERT_CONTEXT;
		goto err;
	}

	CryptUIDlgViewContext(CERT_STORE_CERTIFICATE_CONTEXT, pCertContext, GetForegroundWindow(), NULL, 0, NULL);

err:
	if (pCertContext)
	{
		CertFreeCertificateContext(pCertContext);
	}

	return ulRet;
}
#endif

COMMON_API unsigned int CALL_CONVENTION SMB_DEV_SM2GetAgreementKeyByCertAttr(
	IN SMB_CS_CertificateAttr *pCertAttr,
	IN ULONG ulAlgId,
	OUT ECCPUBLICKEYBLOB *pTempECCPubKeyBlobA,
	IN BYTE* pbIDA,
	IN ULONG ulIDALen,
	IN ECCPUBLICKEYBLOB *pECCPubKeyBlobB,
	IN ECCPUBLICKEYBLOB *pTempECCPubKeyBlobB,
	IN BYTE* pbIDB,
	IN ULONG ulIDBLen,
	OUT BYTE *pbAgreementKey,
	IN OUT ULONG *pulAgreementKeyLen,
	IN char * pszPIN,
	IN OUT ULONG * puiRetryCount)
{
	HINSTANCE ghInst = NULL;

#if USE_SELF_MUTEX
	UseMixMutex mutex("mutex_dev");
#endif

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

	char dllPathValue[BUFFER_LEN_1K] = { 0 };
	char signTypeValue[BUFFER_LEN_1K] = { 0 };

	DEVHANDLE hDev = NULL;
	HAPPLICATION hAPP = NULL;
	HCONTAINER hCon = NULL;
	HANDLE hAgreementHandle = NULL;

	SMB_CS_SKF_NODE *pPtr = NULL;
	SMB_CS_SKF_NODE *pHeader = NULL;

	SMB_CS_EnumSKF(&pHeader);

	for (pPtr = pHeader; pPtr; pPtr = pPtr->ptr_next)
	{
		if (0 == memcmp(pPtr->ptr_data->stName.data, pCertAttr->stSKFName.data, pCertAttr->stSKFName.length>pPtr->ptr_data->stName.length ? pCertAttr->stSKFName.length-1 : pPtr->ptr_data->stName.length-1))
		{
			memcpy(dllPathValue, pPtr->ptr_data->stPath.data, pPtr->ptr_data->stPath.length);
			memcpy(signTypeValue, pPtr->ptr_data->stSignType.data, pPtr->ptr_data->stSignType.length);
			break;
		}
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

	FUNC_NAME_INIT(func_, GenerateKeyWithECCEx, );
	FUNC_NAME_INIT(func_, GenerateAgreementDataWithECC, );
	FUNC_NAME_INIT(func_, GenerateAgreementDataWithECCEx, );
	FUNC_NAME_INIT(func_, GenerateAgreementDataAndKeyWithECCEx, );

	FUNC_NAME_INIT(func_, LockDev, );
	FUNC_NAME_INIT(func_, UnlockDev, );

	{
		ulRet = func_ConnectDev((char*)pCertAttr->stDeviceName.data, &hDev);
		if (0 != ulRet)
		{
			goto err;
		}

#if USE_SELF_MUTEX

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

		ulRet = func_VerifyPIN(hAPP, 1, pszPIN, puiRetryCount);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_OpenContainer(hAPP, (char*)pCertAttr->stContainerName.data, &hCon);
		if (0 != ulRet)
		{
			goto err;
		}

#if  0
		//send
		ulRet = func_GenerateAgreementDataWithECCEx(hCon, ulAlgId, pTempECCPubKeyBlobA, pbIDA, ulIDALen, &hAgreementHandle);
		if (0 != ulRet)
		{
			goto err;
		}

		ulRet = func_GenerateKeyWithECCEx(hAgreementHandle, pECCPubKeyBlobB, pTempECCPubKeyBlobB, pbIDB, ulIDBLen, pbAgreementKey, pulAgreementKeyLen);
		if (0 != ulRet)
		{
			goto err;
		}
#else
		//re
		ulRet = func_GenerateAgreementDataAndKeyWithECCEx(hCon, ulAlgId, pECCPubKeyBlobB, pTempECCPubKeyBlobB, pTempECCPubKeyBlobA, pbIDB, ulIDBLen, pbIDA, ulIDALen, pbAgreementKey, pulAgreementKeyLen);
		if (0 != ulRet)
		{
			goto err;
		}
#endif
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

	if (pHeader)
	{
		SMB_CS_FreeSKFLink(&pHeader);
	}

	return ulRet;
}

COMMON_API unsigned int CALL_CONVENTION SMB_DEV_SM2GetAgreementKeyEx(
	IN BYTE* pbCert,
	IN unsigned int ulCertLen,
	IN int ulAlgId,
	OUT BYTE* pbTempECCPubKeyBlobA,
	IN OUT int *pulTempECCPubKeyBlobALen,
	IN BYTE* pbIDA,
	IN int ulIDALen,
	IN BYTE* pbECCPubKeyBlobB,
	IN int  ulECCPubKeyBlobBLen,
	IN BYTE* pbTempECCPubKeyBlobB,
	IN int  ulTempECCPubKeyBlobBLen,
	IN BYTE* pbIDB,
	IN int ulIDBLen,
	OUT BYTE *pbAgreementKey,
	IN OUT ULONG *pulAgreementKeyLen,
	IN char * pszPIN,
	IN OUT ULONG * puiRetryCount)
{
	SMB_CS_CertificateContext *pCertCtx = NULL;

	ECCPUBLICKEYBLOB  pTempECCPubKeyBlobA = { 0 };
	ECCPUBLICKEYBLOB  pECCPubKeyBlobB = { 0 };
	ECCPUBLICKEYBLOB  pTempECCPubKeyBlobB = { 0 };
	ECCPUBLICKEYBLOB  pTemp = { 0 };

	unsigned int		uiRet = 0;

	unsigned int		uiECCBitLen = 256;
	unsigned int		uiECCLen = uiECCBitLen / 8;

	uiRet = SMB_CS_GetCertCtxByCert(&pCertCtx, pbCert, ulCertLen);
	if (0 != uiRet)
	{
		return uiRet;
	}
	pCertCtx->stAttr.ucCertUsageType = 2;

	//04 + X + Y
	pECCPubKeyBlobB.BitLen = uiECCBitLen;
	memcpy(pECCPubKeyBlobB.XCoordinate + 64 - uiECCLen, pbECCPubKeyBlobB + 1, uiECCLen);
	memcpy(pECCPubKeyBlobB.YCoordinate + 64 - uiECCLen, pbECCPubKeyBlobB + 1 + uiECCLen, uiECCLen);

	pTempECCPubKeyBlobB.BitLen = uiECCBitLen;
	memcpy(pTempECCPubKeyBlobB.XCoordinate + 64 - uiECCLen, pbTempECCPubKeyBlobB + 1, uiECCLen);
	memcpy(pTempECCPubKeyBlobB.YCoordinate + 64 - uiECCLen, pbTempECCPubKeyBlobB + 1 + uiECCLen, uiECCLen);

	uiRet = SMB_DEV_SM2GetAgreementKeyByCertAttr(&(pCertCtx->stAttr), ulAlgId, &pTempECCPubKeyBlobA, pbIDA, ulIDALen,
		&pECCPubKeyBlobB, &pTempECCPubKeyBlobB, pbIDB, ulIDBLen,
		pbAgreementKey, pulAgreementKeyLen, pszPIN, puiRetryCount);
	if (0 != uiRet)
	{
		return uiRet;
	}

	if (NULL == pbTempECCPubKeyBlobA)
	{
		*pulTempECCPubKeyBlobALen = 0x41;
		return uiRet;
	}

	if ((*pulTempECCPubKeyBlobALen) < 0x41)
	{
		*pulTempECCPubKeyBlobALen = 0x41;
		return EErr_SMB_MEM_LES;
	}

	*pulTempECCPubKeyBlobALen = 0x41;
	memcpy(pbTempECCPubKeyBlobA, "\x04", 1);
	memcpy(pbTempECCPubKeyBlobA + 1, pTempECCPubKeyBlobA.XCoordinate + 64 - uiECCLen, uiECCLen);
	memcpy(pbTempECCPubKeyBlobA + 1 + uiECCLen, pTempECCPubKeyBlobA.YCoordinate + 64 - uiECCLen, uiECCLen);

	return uiRet;
}


COMMON_API unsigned int CALL_CONVENTION SMB_DEV_FindSKFDriver(const char * pszSKFName, char * szVersion)
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

	char * data_value = NULL;
	char * pTmp = NULL;

	char dllPathValue[BUFFER_LEN_1K] = { 0 };
	char signTypeValue[BUFFER_LEN_1K] = { 0 };


	DWORD    dwSize = 0;
	BYTE     *pbVersionInfo = NULL;                 // 获取文件版本信息
	VS_FIXEDFILEINFO    *pFileInfo = NULL;
	UINT                puLenFileInfo = 0;

	SMB_CS_SKF_NODE *pPtr = NULL;
	SMB_CS_SKF_NODE *pHeader = NULL;

	SMB_CS_EnumSKF(&pHeader);

	for (pPtr = pHeader; pPtr; pPtr = pPtr->ptr_next)
	{
		if (0 == memcmp(pPtr->ptr_data->stName.data, pszSKFName, strlen(pszSKFName)))
		{
			memcpy(dllPathValue, pPtr->ptr_data->stPath.data, pPtr->ptr_data->stPath.length);
			memcpy(signTypeValue, pPtr->ptr_data->stSignType.data, pPtr->ptr_data->stSignType.length);
			break;
		}
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

	dwSize = GetFileVersionInfoSizeA(dllPathValue, NULL);
	pbVersionInfo = (BYTE *)malloc(dwSize);
	if (!GetFileVersionInfoA(dllPathValue, 0, dwSize, pbVersionInfo))
	{
		goto err;
	}
	if (!VerQueryValueA(pbVersionInfo, "\\", (LPVOID*)&pFileInfo, &puLenFileInfo))
	{
		goto err;
	}

	sprintf(szVersion, "%d.%d.%d.%d", HIWORD(pFileInfo->dwFileVersionMS), LOWORD(pFileInfo->dwFileVersionMS), HIWORD(pFileInfo->dwFileVersionLS), LOWORD(pFileInfo->dwFileVersionLS));

err:
	if (ghInst)
	{
#if defined(USE_FREE_GHINST)
		FreeLibrary(ghInst);//释放Dll函数
		ghInst = NULL;
#endif
	}

	if (pbVersionInfo)
	{
		free(pbVersionInfo);
	}

	if (pHeader)
	{
		SMB_CS_FreeSKFLink(&pHeader);
	}

	return ulRet;
}


COMMON_API unsigned int CALL_CONVENTION SMB_DEV_ReadSKFPinVerifyByCertAttr(SMB_CS_CertificateAttr *pCertAttr, char * pszPinVerify, unsigned int *puiPinVerifyLen)
{
	unsigned int ulRet = -1;
	SMB_CS_SKF_NODE *pHeader = NULL;
	SMB_CS_SKF_NODE *pPtr = NULL;

	SMB_CS_EnumSKF(&pHeader);


	for (pPtr = pHeader; pPtr; pPtr = pPtr->ptr_next)
	{
		if (0 == memcmp(pPtr->ptr_data->stName.data, pCertAttr->stSKFName.data, pCertAttr->stSKFName.length>pPtr->ptr_data->stName.length ? pCertAttr->stSKFName.length - 1 : pPtr->ptr_data->stName.length - 1))
		{
			if (NULL == pszPinVerify)
			{
				*puiPinVerifyLen = pPtr->ptr_data->stPinVerify.length;
				ulRet = 0;
			}
			else if (*puiPinVerifyLen < pPtr->ptr_data->stPinVerify.length)
			{
				*puiPinVerifyLen = pPtr->ptr_data->stPinVerify.length;
				ulRet = EErr_SMB_MEM_LES;
			}
			else
			{
				*puiPinVerifyLen = pPtr->ptr_data->stPinVerify.length;
				memcpy(pszPinVerify, pPtr->ptr_data->stPinVerify.data, pPtr->ptr_data->stPinVerify.length);
				ulRet = 0;
			}
			break;
		}
	}

	if (pHeader)
	{
		SMB_CS_FreeSKFLink(&pHeader);
	}

	return ulRet;
}


COMMON_API unsigned int CALL_CONVENTION SMB_DEV_FindEnCertificateBySignCert(
	IN unsigned char *pbSignCert, IN unsigned int uiSignCertLen, OUT unsigned char *pbCert, IN OUT unsigned int *puiCertLen
)
{
	SMB_CS_CertificateContext *pCertCtx = NULL;

	unsigned int		uiRet = 0;


	uiRet = SMB_CS_GetCertCtxByCert(&pCertCtx, pbSignCert, uiSignCertLen);
	if (0 != uiRet)
	{
		goto err;
	}

	if (NULL == pCertCtx)
	{
		uiRet = EErr_SMB_NO_CERT;
		goto err;
	}
	
	uiRet = SMB_DEV_FindEnCertificateByCertAttr(&pCertCtx->stAttr,pbCert,puiCertLen);
	if (0 != uiRet)
	{
		goto err;
	}
err:

	if (pCertCtx)
	{
		SMB_CS_FreeCertCtx(pCertCtx);
	}

	return uiRet;
}


COMMON_API unsigned int CALL_CONVENTION SMB_DEV_ReadSKFPinVerifyBySignCert(IN unsigned char *pbSignCert, IN unsigned int uiSignCertLen, char * pszPinVerify, unsigned int *puiPinVerifyLen)
{
	SMB_CS_CertificateContext *pCertCtx = NULL;

	unsigned int		uiRet = 0;


	uiRet = SMB_CS_GetCertCtxByCert(&pCertCtx, pbSignCert, uiSignCertLen);
	if (0 != uiRet)
	{
		goto err;
	}

	if (NULL == pCertCtx)
	{
		uiRet = EErr_SMB_NO_CERT;
		goto err;
	}

	uiRet = SMB_DEV_ReadSKFPinVerifyByCertAttr(&pCertCtx->stAttr, pszPinVerify, puiPinVerifyLen);
	if (0 != uiRet)
	{
		goto err;
	}
err:

	if (pCertCtx)
	{
		SMB_CS_FreeCertCtx(pCertCtx);
	}

	return uiRet;
}


COMMON_API unsigned int CALL_CONVENTION SMB_DEV_SM2SignBySignCert(
	IN unsigned char *pbSignCert, IN unsigned int uiSignCertLen,
	char *pszPIN,
	BYTE *pbDigest, unsigned int uiDigestLen,
	BYTE *pbData, unsigned int uiDataLen,
	PECCSIGNATUREBLOB pSignature, ULONG *puiRetryCount)
{
	SMB_CS_CertificateContext *pCertCtx = NULL;

	unsigned int		uiRet = 0;


	uiRet = SMB_CS_GetCertCtxByCert(&pCertCtx, pbSignCert, uiSignCertLen);
	if (0 != uiRet)
	{
		goto err;
	}

	if (NULL == pCertCtx)
	{
		uiRet = EErr_SMB_NO_CERT;
		goto err;
	}

	uiRet = SMB_DEV_SM2SignByCertAttr(&pCertCtx->stAttr, pszPIN,
		pbDigest,  uiDigestLen,
		pbData, uiDataLen,
		pSignature, puiRetryCount);
	if (0 != uiRet)
	{
		goto err;
	}
err:

	if (pCertCtx)
	{
		SMB_CS_FreeCertCtx(pCertCtx);
	}

	return uiRet;
}