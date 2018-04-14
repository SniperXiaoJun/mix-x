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

#include <openssl/base.h>
#include "sm2_boringssl.h"

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
	int type;
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


#include <gdca_saf/gdca_gm_def.h>
#include <gdca_saf/saf_api_set.h>
#include <gdca_saf/saf_api.h>

ULONG ErrorCodeConvert(ULONG errCode)
{
	if(errCode >= SAR_UnknownErr || errCode <= SAR_PKCS7DecErr)
	{
		switch (errCode)
		{
		case SAR_UnknownErr:               //异常错误
			errCode = SAR_UNKNOWNERR;
			break;
		case SAR_NotSupportYetErr:               //不支持的服务
			errCode = SAR_NOTSUPPORTYETERR;
			break;
		case SAR_FileErr:               //文件操作错误
			errCode = SAR_FILEERR;
			break;
		case SAR_ProviderTypeErr:               //服务提供者参数类型错误
			errCode = errCode;
			break;
		case SAR_LoadProviderErr:               //导入服务提供者接口错误
			errCode = errCode;
			break;
		case SAR_LoadDevMngApiErr:               //导入设备管理接口错误
			errCode = errCode;
			break;
		case SAR_AlgoTypeErr:               //算法类型错误
			errCode = errCode;
			break;
		case SAR_NameLenErr:               //名称长度错误
			errCode = SAR_NAMELENERR;
			break;
		case SAR_KeyUsageErr:               //密钥用途错误
			errCode = SAR_KEYUSAGEERR;
			break;
		case SAR_ModulusLenErr:               //模的长度错误
			errCode = SAR_MODULUSLENERR;
			break;
		case SAR_NotInitializeErr:               //未初始化
			errCode = SAR_NOTINITIALIZEERR;
			break;
		case SAR_ObjErr:               //对象错误
			errCode = SAR_INVALIDHANDLEERR;
			break;
		case SAR_MemoryErr:               //内存错误
			errCode = SAR_MEMORYERR;
			break;
		case SAR_TimeoutErr:               //超时错误
			errCode = SAR_TIMEOUTERR;
			break;
		case SAR_IndataLenErr:               //输入数据长度错误
			errCode = SAR_INDATALENERR;
			break;
		case SAR_IndataErr:               //输入数据错误
			errCode = SAR_INDATAERR;
			break;
		case SAR_GenRandErr:               //生成随机数错误
			errCode = SAR_GENRANDERR;
			break;
		case SAR_HashErr:               //HASH运算错误
			errCode = SAR_HASHOBJERR;
			break;
		case SAR_GenRsaKeyErr:               //产生RSA密钥错误
			errCode = SAR_GENRSAKEYERR;
			break;
		case SAR_RsaModulusLenErr:               //RSA密钥模长错误
			errCode = SAR_RSAMODULUSLENERR;
			break;
		case SAR_CspImportPubKeyErr:               //CSP服务导入公钥错误
			errCode = SAR_CSPIMPRTPUBKEYERR;
			break;
		case SAR_RsaEncErr:               //RSA加密错误
			errCode = SAR_RSAENCERR;
			break;
		case SAR_RsaDecErr:               //RSA解密错误
			errCode = SAR_RSADECERR;
			break;
		case SAR_HashNotEqualErr:               //HASH值不相等
			errCode = SAR_HASHNOTEQUALERR;
			break;
		case SAR_KeyNotFoundErr:               //密钥未发现
			errCode = SAR_KEYNOTFOUNTERR;
			break;
		case SAR_CertNotFoundErr:               //证书未发现
			errCode = SAR_CERTNOTFOUNTERR;
			break;
		case SAR_NotExportErr:               //对象未导出
			errCode = SAR_NOTEXPORTERR;
			break;
		case SAR_CertRevokedErr:               //证书被吊销
			errCode = errCode;
			break;
		case SAR_CertNotYetValidErr:               //证书未生效
			errCode = errCode;
			break;
		case SAR_CertHasExpiredErr:               //证书已过期
			errCode = errCode;
			break;
		case SAR_CertVerifyErr:               //证书验证错误
			errCode = errCode;
			break;
		case SAR_CertEncodeErr:               //证书编码错误
			errCode = errCode;
			break;
		case SAR_DecryptPadErr:               //解密时做补丁错误
			errCode = SAR_DECRYPTPADERR;
			break;
		case SAR_MacLenErr:               //MAC长度错误
			errCode = SAR_MACLENERR;
			break;
		case SAR_KeyInfoTypeErr:               //密钥类型错误
			errCode = SAR_KEYINFOTYPEERR;
			break;
		case SAR_NotLoginErr:               //没有进行登陆认证
			//errCode = SAR_USER_NOT_LOGGED_IN;
			errCode = SAR_PIN_INCORRECT;
			break;
		case SAR_ECCEncErr:               //ECC加密错误
			errCode = errCode;
			break;
		case SAR_ECCDecErr:               //ECC解密错误
			errCode = errCode;
			break;
		case SAR_ExportSKErr:               //导出会话密钥错误
			errCode = errCode;
			break;
		case SAR_ImportSKErr:               //导入会话密钥错误
			errCode = errCode;
			break;
		case SAR_SymmEncErr:               //对称加密错误
			errCode = errCode;
			break;
		case SAR_SymmDecErr:               //对称解密错误
			errCode = errCode;
			break;
		case SAR_PKCS7SignErr:               //P7签名错误
		case SAR_PKCS7VerifyErr:               //P7验证错误
		case SAR_PKCS7EncErr:               //P7加密错误
		case SAR_PKCS7DecErr:               //P7解密错误
			errCode = errCode;
			break;
		default:
			errCode = errCode;
			break;
		}
	}

	return errCode;
}


typedef int(*pSAF_Initialize)(void **phAppHandle,char *pucCfgFilePath);
typedef int(*pSAF_Finalize)(void *hAppHandle);
typedef int(*pSAF_EnumCertificates)(void *hAppHandle, SGD_USR_CERT_ENUMLIST *usrCerts);
typedef int(*pSAF_EnumCertificatesFree)(void *hAppHandle, SGD_USR_CERT_ENUMLIST *usrCerts);
typedef int(*pSAF_Login)(
	void *hAppHandle,
	unsigned int uiUsrType,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned char *pucPin,
	unsigned int uiPinLen,
	unsigned int *puiRemainCount);

typedef int(*pSAF_GetCertificateInfo)(
	void *hAppHandle,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	unsigned int uiInfoType,
	unsigned char *pucInfo,
	unsigned int *puiInfoLen);

typedef int(*pSAF_Hash)(
	unsigned int uiAlgoType,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucPublicKey,
	unsigned int ulPublicKeyLen,
	unsigned char *pucID,
	unsigned int ulIDLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

typedef int(*pSAF_EccSign)(
	void *hAppHandle,
	unsigned char *pucContainerName,
	unsigned int uiContainerNameLen,
	unsigned int uiAlgorithmID,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignData,
	unsigned int *puiSignDataLen);


typedef int(*pSAF_EccVerifySignByCert)(
	unsigned int uiAlgorithmID,
	unsigned char *pucCertificate,
	unsigned int uiCertificateLen,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucSignData,
	unsigned int uiSignDataLen);


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

	pSAF_Initialize fpSAF_Initialize = NULL;
	pSAF_Finalize fpSAF_Finalize = NULL;
	pSAF_EnumCertificates fpSAF_EnumCertificates = NULL;
	pSAF_EnumCertificatesFree fpSAF_EnumCertificatesFree = NULL;
	pSAF_Login fpSAF_Login = NULL;
	pSAF_GetCertificateInfo fpSAF_GetCertificateInfo = NULL;
	pSAF_Hash fpSAF_Hash = NULL;
	pSAF_EccSign fpSAF_EccSign = NULL;
	pSAF_EccVerifySignByCert fpSAF_EccVerifySignByCert = NULL;
	void *hAppHandle = NULL;
	SGD_USR_CERT_ENUMLIST usrCerts;

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

	fpSAF_Initialize = (pSAF_Initialize)GetProcAddress(ghInst, "SAF_Initialize");
	fpSAF_EnumCertificates = (pSAF_EnumCertificates)GetProcAddress(ghInst, "SAF_EnumCertificates");
	fpSAF_EnumCertificatesFree = (pSAF_EnumCertificatesFree)GetProcAddress(ghInst, "SAF_EnumCertificatesFree");
	fpSAF_Login = (pSAF_Login)GetProcAddress(ghInst, "SAF_Login");
	fpSAF_GetCertificateInfo = (pSAF_GetCertificateInfo)GetProcAddress(ghInst, "SAF_GetCertificateInfo");
	fpSAF_Hash = (pSAF_Hash)GetProcAddress(ghInst, "SAF_Hash");
	fpSAF_EccSign = (pSAF_EccSign)GetProcAddress(ghInst, "SAF_EccSign");
	fpSAF_EccVerifySignByCert = (pSAF_EccVerifySignByCert)GetProcAddress(ghInst, "SAF_EccVerifySignByCert");
	fpSAF_Finalize = (pSAF_Finalize)GetProcAddress(ghInst, "SAF_Finalize");

	if (fpSAF_Initialize &&fpSAF_EnumCertificates &&fpSAF_EnumCertificatesFree &&fpSAF_Login &&fpSAF_GetCertificateInfo &&fpSAF_Hash && fpSAF_EccSign &&fpSAF_EccVerifySignByCert)
	{
		//初始化环境
		ulRet = fpSAF_Initialize(&hAppHandle, "saf_cfg_watch.dat");
		if (0 != ulRet)
		{
			printf("SAF_Initialize error\n");
			goto clear_over;
		}

		//枚举用户证书
		ulRet = fpSAF_EnumCertificates(hAppHandle, &usrCerts);
		if (0 != ulRet)
		{
			printf("SAF_EnumCertificates error:ret=%x\n", ulRet);
			goto clear_over;
		}

		ulRet = fpSAF_Login(hAppHandle, 1, pCertAttr->stContainerName.data, pCertAttr->stContainerName.length, (unsigned char *)pszPin, strlen(pszPin), (unsigned int *)puiRetryCount);
		if (0 != ulRet)
		{
			goto clear_over;
		}
	}
	else
	{
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
clear_over:
	//清除环境
	if (NULL != hAppHandle)
	{
		//释放枚举证书的内存
		fpSAF_EnumCertificatesFree(hAppHandle, &usrCerts);
		printf("SAF_EnumCertificatesFree: ret=%x\n", 0);

		fpSAF_Finalize(hAppHandle);
		//printf("SAF_Finalize: ret=%x\n", 0);
		hAppHandle = NULL;
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

	ulRet = ErrorCodeConvert(ulRet);

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

	pSAF_Initialize fpSAF_Initialize = NULL;
	pSAF_Finalize fpSAF_Finalize = NULL;
	pSAF_EnumCertificates fpSAF_EnumCertificates = NULL;
	pSAF_EnumCertificatesFree fpSAF_EnumCertificatesFree = NULL;
	pSAF_Login fpSAF_Login = NULL;
	pSAF_GetCertificateInfo fpSAF_GetCertificateInfo = NULL;
	pSAF_Hash fpSAF_Hash = NULL;
	pSAF_EccSign fpSAF_EccSign = NULL;
	pSAF_EccVerifySignByCert fpSAF_EccVerifySignByCert = NULL;
	void *hAppHandle = NULL;
	SGD_USR_CERT_ENUMLIST usrCerts;

	if (handleArgs)
	{
		if (0xAF == handleArgs->type)
		{
			ghInst = (HINSTANCE)handleArgs->ghInst;
			hAppHandle = handleArgs->hAPP;
		}
		else
		{
			ghInst = (HINSTANCE)handleArgs->ghInst;
			hDev = handleArgs->hDev;
			hAPP = handleArgs->hAPP;
			hCon = handleArgs->hCon;
		}
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

	if (0xAF == handleArgs->type)
	{
		unsigned char signature_data_der[256] = { 0 };
		unsigned int signature_len_der = 256;

		unsigned char signature_data[256] = { 0 };
		int signature_len = 256;

		fpSAF_Initialize = (pSAF_Initialize)GetProcAddress(ghInst, "SAF_Initialize");
		fpSAF_EnumCertificates = (pSAF_EnumCertificates)GetProcAddress(ghInst, "SAF_EnumCertificates");
		fpSAF_EnumCertificatesFree = (pSAF_EnumCertificatesFree)GetProcAddress(ghInst, "SAF_EnumCertificatesFree");
		fpSAF_Login = (pSAF_Login)GetProcAddress(ghInst, "SAF_Login");
		fpSAF_GetCertificateInfo = (pSAF_GetCertificateInfo)GetProcAddress(ghInst, "SAF_GetCertificateInfo");
		fpSAF_Hash = (pSAF_Hash)GetProcAddress(ghInst, "SAF_Hash");
		fpSAF_EccSign = (pSAF_EccSign)GetProcAddress(ghInst, "SAF_EccSign");
		fpSAF_EccVerifySignByCert = (pSAF_EccVerifySignByCert)GetProcAddress(ghInst, "SAF_EccVerifySignByCert");
		fpSAF_Finalize = (pSAF_Finalize)GetProcAddress(ghInst, "SAF_Finalize");

		//枚举用户证书
		ulRet = fpSAF_EnumCertificates(hAppHandle, &usrCerts);
		if (0 != ulRet)
		{
			printf("SAF_EnumCertificates error:ret=%x\n", ulRet);
			goto clear_over;
		}


		//  "0" || "" ：标准PIN有效使用
		//	"1"：无需调用校验PIN接口
		//	"2"：PIN无效，但需调用校验PIN接口
		if (0 == memcmp("2", pinVerifyValue, 1))
		{
			ulRet = fpSAF_Login(hAppHandle, 1, pCertAttr->stContainerName.data, pCertAttr->stContainerName.length ,(unsigned char *)pszPIN,strlen(pszPIN), (unsigned int *)puiRetryCount);
			if (0 != ulRet)
			{
				goto clear_over;
			}
		}
		else if (0 == memcmp("1", pinVerifyValue, 1))
		{

		}
		else if (0 == memcmp("0", pinVerifyValue, 1))
		{
			ulRet = fpSAF_Login(hAppHandle, 1, pCertAttr->stContainerName.data, pCertAttr->stContainerName.length, (unsigned char *)pszPIN, strlen(pszPIN), (unsigned int *)puiRetryCount);
			if (0 != ulRet)
			{
				goto clear_over;
			}
		}
		else if (0 == memcmp("", pinVerifyValue, 1))
		{
			ulRet = fpSAF_Login(hAppHandle, 1, pCertAttr->stContainerName.data, pCertAttr->stContainerName.length, (unsigned char *)pszPIN, strlen(pszPIN), (unsigned int *)puiRetryCount);
			if (0 != ulRet)
			{
				goto clear_over;
			}
		}

		if (0 == memcmp("data", signTypeValue, 4))
		{
			ulRet = fpSAF_EccSign(hAppHandle, pCertAttr->stContainerName.data, pCertAttr->stContainerName.length, SGD_SM2_1, pbData, uiDataLen, signature_data_der, &signature_len_der);
		}
		else
		{
			ulRet = fpSAF_EccSign(hAppHandle, pCertAttr->stContainerName.data, pCertAttr->stContainerName.length, SGD_SM2_1, pbDigest, uiDigestLen, signature_data_der, &signature_len_der);
		}

		if (0 != ulRet)
		{
			goto clear_over;
		}


		SM2SignD2i(signature_data_der, signature_len_der, signature_data, &signature_len);


		memset(pSignature, 0, sizeof(ECCSIGNATUREBLOB));

		memcpy(pSignature->r + 32, signature_data, 32);
		memcpy(pSignature->s + 32, signature_data+32, 32);
	}
	else
	{
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
	}


err:

	if (hDev)
	{
#if USE_SELF_MUTEX

#else
		func_UnlockDev(hDev);
#endif
	}

clear_over:
	//清除环境
	if (NULL != hAppHandle)
	{
		//释放枚举证书的内存
		fpSAF_EnumCertificatesFree(hAppHandle, &usrCerts);
		printf("SAF_EnumCertificatesFree: ret=%x\n", 0);

		//fpSAF_Finalize(hAppHandle);
		//printf("SAF_Finalize: ret=%x\n", 0);
		//hAppHandle = NULL;
	}

	if (pHeader)
	{
		SMB_CS_FreeSKFLink(&pHeader);
	}

	ulRet = ErrorCodeConvert(ulRet);

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

	

	SMB_CS_SKF_NODE *pPtr = NULL;
	SMB_CS_SKF_NODE *pHeader = NULL;
	SMB_CS_CertificateContext_NODE *pCtxNode = NULL;

	DEVHANDLE hDev = NULL;


	pSAF_Initialize fpSAF_Initialize = NULL;
	pSAF_Finalize fpSAF_Finalize = NULL;
	pSAF_EnumCertificates fpSAF_EnumCertificates = NULL;
	pSAF_EnumCertificatesFree fpSAF_EnumCertificatesFree = NULL;
	pSAF_Login fpSAF_Login = NULL;
	pSAF_GetCertificateInfo fpSAF_GetCertificateInfo = NULL;
	pSAF_Hash fpSAF_Hash = NULL;
	pSAF_EccSign fpSAF_EccSign = NULL;
	pSAF_EccVerifySignByCert fpSAF_EccVerifySignByCert = NULL;

	void *hAppHandle = NULL;
	SGD_USR_CERT_ENUMLIST usrCerts;
	unsigned int i;

	CertificateItemParse parse;

	if (0 == ppCertCtxNodeHeader)
	{
		ulRet = EErr_SMB_INVALID_ARG;
		goto err;
	}

	pTmp = (BYTE *)malloc(BUFFER_LEN_1K * 4);

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


	fpSAF_Initialize = (pSAF_Initialize)GetProcAddress(ghInst, "SAF_Initialize"); 
	fpSAF_EnumCertificates = (pSAF_EnumCertificates)GetProcAddress(ghInst, "SAF_EnumCertificates");
	fpSAF_EnumCertificatesFree = (pSAF_EnumCertificatesFree)GetProcAddress(ghInst, "SAF_EnumCertificatesFree");
	fpSAF_Login = (pSAF_Login)GetProcAddress(ghInst, "SAF_Login");
	fpSAF_GetCertificateInfo = (pSAF_GetCertificateInfo)GetProcAddress(ghInst, "SAF_GetCertificateInfo");
	fpSAF_Hash = (pSAF_Hash)GetProcAddress(ghInst, "SAF_Hash");
	fpSAF_EccSign = (pSAF_EccSign)GetProcAddress(ghInst, "SAF_EccSign");
	fpSAF_EccVerifySignByCert = (pSAF_EccVerifySignByCert)GetProcAddress(ghInst, "SAF_EccVerifySignByCert");
	fpSAF_Finalize = (pSAF_Finalize)GetProcAddress(ghInst, "SAF_Finalize");

	if (fpSAF_Initialize &&fpSAF_EnumCertificates &&fpSAF_EnumCertificatesFree &&fpSAF_Login &&fpSAF_GetCertificateInfo &&fpSAF_Hash && fpSAF_EccSign &&fpSAF_EccVerifySignByCert)
	{
		//初始化环境
		ulRet = fpSAF_Initialize(&hAppHandle, "saf_cfg_watch.dat");
		if (0 != ulRet)
		{
			printf("SAF_Initialize error\n");
			goto clear_over;
		}

		//枚举用户证书
		ulRet = fpSAF_EnumCertificates(hAppHandle, &usrCerts);
		if (0 != ulRet)
		{
			printf("SAF_EnumCertificates error:ret=%x\n", ulRet);
			goto clear_over;
		}
		printf("certCount=%d\n", usrCerts.certCount);
		for (i = 0; i<usrCerts.certCount; i++)
		{
			printf("the %d's cert:\n", i);
			printf("containerName=%s\n", usrCerts.containerName[i]);
			printf("containerNameLen=%d\n", usrCerts.containerNameLen[i]);
			printf("keyUsage=%d\n", usrCerts.keyUsage[i]);
			printf("certificateLen=%d\n", usrCerts.certificateLen[i]);

			parse.setCertificate(usrCerts.certificate[i], usrCerts.certificateLen[i]);

			parse.parse();

			if (parse.m_iKeyAlg | uiKeyFlag)
			{
				//获取签名证书
				if (KeyUsageSign == usrCerts.keyUsage[i])
				{
					if (SMB_CERT_USAGE_FLAG_SIGN & uiUsageFlag)
					{
						SMB_CS_CertificateContext *pCertCtx = (SMB_CS_CertificateContext *)malloc(sizeof(SMB_CS_CertificateContext));

						memset(pCertCtx, 0, sizeof(SMB_CS_CertificateContext));

						pCertCtx->stContent.length = usrCerts.certificateLen[i];
						pCertCtx->stContent.data = (unsigned char *)malloc(pCertCtx->stContent.length);
						memcpy(pCertCtx->stContent.data, usrCerts.certificate[i], pCertCtx->stContent.length);

						ptrDev = "saf_example";
						pCertCtx->stAttr.stDeviceName.length = strlen(ptrDev) + 1;
						pCertCtx->stAttr.stDeviceName.data = (unsigned char *)malloc(pCertCtx->stAttr.stDeviceName.length);
						memcpy(pCertCtx->stAttr.stDeviceName.data, ptrDev, pCertCtx->stAttr.stDeviceName.length);

						pCertCtx->stAttr.stContainerName.length = usrCerts.containerNameLen[i];
						pCertCtx->stAttr.stContainerName.data = (unsigned char *)malloc(pCertCtx->stAttr.stContainerName.length);
						memcpy(pCertCtx->stAttr.stContainerName.data, usrCerts.containerName[i], pCertCtx->stAttr.stContainerName.length);

						pCertCtx->stAttr.stSKFName.length = strlen(pszSKFName) + 1;
						pCertCtx->stAttr.stSKFName.data = (unsigned char *)malloc(pCertCtx->stAttr.stSKFName.length);
						memcpy(pCertCtx->stAttr.stSKFName.data, pszSKFName, pCertCtx->stAttr.stSKFName.length);

						pCertCtx->stAttr.ucCertUsageType = 1; //	签名加密

						pCertCtx->stAttr.ucCertAlgType = parse.m_iKeyAlg; // RSA SM2

						OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppCertCtxNodeHeader, (void *)pCertCtx);
					}
					else
					{

					}
				}

				//获取加密证书
				if (KeyUsageEncrypt == usrCerts.keyUsage[i])
				{
					if (SMB_CERT_USAGE_FLAG_EX & uiUsageFlag)
					{
						SMB_CS_CertificateContext *pCertCtx = (SMB_CS_CertificateContext *)malloc(sizeof(SMB_CS_CertificateContext));

						memset(pCertCtx, 0, sizeof(SMB_CS_CertificateContext));

						pCertCtx->stContent.length = usrCerts.certificateLen[i];
						pCertCtx->stContent.data = (unsigned char *)malloc(pCertCtx->stContent.length);
						memcpy(pCertCtx->stContent.data, usrCerts.certificate[i], pCertCtx->stContent.length);

						ptrDev = "saf_example";
						pCertCtx->stAttr.stDeviceName.length = strlen(ptrDev) + 1;
						pCertCtx->stAttr.stDeviceName.data = (unsigned char *)malloc(pCertCtx->stAttr.stDeviceName.length);
						memcpy(pCertCtx->stAttr.stDeviceName.data, ptrDev, pCertCtx->stAttr.stDeviceName.length);

						pCertCtx->stAttr.stContainerName.length = usrCerts.containerNameLen[i];
						pCertCtx->stAttr.stContainerName.data = (unsigned char *)malloc(pCertCtx->stAttr.stContainerName.length);
						memcpy(pCertCtx->stAttr.stContainerName.data, usrCerts.containerName[i], pCertCtx->stAttr.stContainerName.length);

						pCertCtx->stAttr.stSKFName.length = strlen(pszSKFName) + 1;
						pCertCtx->stAttr.stSKFName.data = (unsigned char *)malloc(pCertCtx->stAttr.stSKFName.length);
						memcpy(pCertCtx->stAttr.stSKFName.data, pszSKFName, pCertCtx->stAttr.stSKFName.length);

						pCertCtx->stAttr.ucCertUsageType = 2; //	签名加密

						pCertCtx->stAttr.ucCertAlgType = parse.m_iKeyAlg; // RSA SM2

						OPF_AddMallocedHandleNodeDataToLink((OPST_HANDLE_NODE **)ppCertCtxNodeHeader, (void *)pCertCtx);
					}
					else
					{

					}
				}
			}
		}

		printf("Test_ReadCert success... \n\n");
	}
	else
	{
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
	}


	for (pCtxNode = *ppCertCtxNodeHeader; pCtxNode; pCtxNode = pCtxNode->ptr_next)
	{
		SMB_CS_FillCertAttr(pCtxNode->ptr_data);
	}

	ulRet = 0;


clear_over:
	//清除环境
	if (NULL != hAppHandle)
	{
		//释放枚举证书的内存
		fpSAF_EnumCertificatesFree(hAppHandle, &usrCerts);
		printf("SAF_EnumCertificatesFree: ret=%x\n", 0);

		fpSAF_Finalize(hAppHandle);
		printf("SAF_Finalize: ret=%x\n", 0);

		hAppHandle = NULL;
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

	SMB_DEV_ArgsClr();

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


	pSAF_Initialize fpSAF_Initialize = NULL;
	pSAF_Finalize fpSAF_Finalize = NULL;
	pSAF_EnumCertificates fpSAF_EnumCertificates = NULL;
	pSAF_EnumCertificatesFree fpSAF_EnumCertificatesFree = NULL;
	pSAF_Login fpSAF_Login = NULL;
	pSAF_GetCertificateInfo fpSAF_GetCertificateInfo = NULL;
	pSAF_Hash fpSAF_Hash = NULL;
	pSAF_EccSign fpSAF_EccSign = NULL;
	pSAF_EccVerifySignByCert fpSAF_EccVerifySignByCert = NULL;
	void *hAppHandle = NULL;

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

	fpSAF_Initialize = (pSAF_Initialize)GetProcAddress(ghInst, "SAF_Initialize");
	fpSAF_EnumCertificates = (pSAF_EnumCertificates)GetProcAddress(ghInst, "SAF_EnumCertificates");
	fpSAF_EnumCertificatesFree = (pSAF_EnumCertificatesFree)GetProcAddress(ghInst, "SAF_EnumCertificatesFree");
	fpSAF_Login = (pSAF_Login)GetProcAddress(ghInst, "SAF_Login");
	fpSAF_GetCertificateInfo = (pSAF_GetCertificateInfo)GetProcAddress(ghInst, "SAF_GetCertificateInfo");
	fpSAF_Hash = (pSAF_Hash)GetProcAddress(ghInst, "SAF_Hash");
	fpSAF_EccSign = (pSAF_EccSign)GetProcAddress(ghInst, "SAF_EccSign");
	fpSAF_EccVerifySignByCert = (pSAF_EccVerifySignByCert)GetProcAddress(ghInst, "SAF_EccVerifySignByCert");
	fpSAF_Finalize = (pSAF_Finalize)GetProcAddress(ghInst, "SAF_Finalize");

	if (fpSAF_Initialize &&fpSAF_EnumCertificates &&fpSAF_EnumCertificatesFree &&fpSAF_Login &&fpSAF_GetCertificateInfo &&fpSAF_Hash && fpSAF_EccSign &&fpSAF_EccVerifySignByCert)
	{
		OPST_HANDLE_ARGS * handleArgs = args;

		//初始化环境
		ulRet = fpSAF_Initialize(&hAppHandle, "saf_cfg_watch.dat");
		if (0 != ulRet)
		{
			printf("SAF_Initialize error\n");
			goto clear_over;
		}

		handleArgs->ghInst = ghInst;
		handleArgs->hAPP = hAppHandle;
		handleArgs->type = 0xAF;

		return 0;
	}
	else
	{
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
					handleArgs->type = 0x00;

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

			ulRet = func_DisConnectDev(hDev); hDev = NULL;
			if (0 != ulRet)
			{
				goto err;
			}
		}
	}

err:

	if (hCon)
	{
		func_CloseContainer(hCon); hCon = NULL;
	}

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
clear_over:
	if (NULL != hAppHandle)
	{
		fpSAF_Finalize(hAppHandle);
		printf("SAF_Finalize: ret=%x\n", 0);

		hAppHandle = NULL;
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
	OPST_HANDLE_ARGS * handleArgs = args;

	if (0xAF == args->type)
	{
		pSAF_Finalize fpSAF_Finalize = NULL;
		
		if (handleArgs)
		{
			ghInst = (HINSTANCE)handleArgs->ghInst;
		}
		else
		{
			return EErr_SMB_FAIL;
		}

		fpSAF_Finalize = (pSAF_Finalize)GetProcAddress(ghInst, "SAF_Finalize");

		ulRet = fpSAF_Finalize(args->hAPP);
	}
	else
	{

		FUNC_NAME_DECLARE(func_, DisConnectDev, );
		FUNC_NAME_DECLARE(func_, CloseApplication, );
		FUNC_NAME_DECLARE(func_, CloseContainer, );
		FUNC_NAME_DECLARE(func_, UnlockDev, );

		DEVHANDLE hDev = NULL;
		HAPPLICATION hAPP = NULL;
		HCONTAINER hCon = NULL;

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
			func_DisConnectDev(hDev); hDev = NULL;
		}
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