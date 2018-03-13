#ifndef _SAF_API_H_
#define _SAF_API_H_

#ifdef __cplusplus
extern "C" {
#endif

/******************************************************************
 *
 *                        Win32 Defines
 *
 ******************************************************************/

#if defined(__OS_WIN32__)
 
#define SAF_API_IMPORT_SPEC __declspec(dllimport)


#ifdef  SAF_API_EXPORT
	#define SAF_API_EXPORT_SPEC __declspec(dllexport)
#else
	//#define API_DLL_EXPORT_SPEC API_DLL_IMPORT_SPEC
	#define SAF_API_EXPORT_SPEC
#endif


#define SAF_API_CALL_SPEC __stdcall


//#define API_DLL API_DLL_EXPORT_SPEC API_DLL_CALL_SPEC
#define SAF_API SAF_API_EXPORT_SPEC

#endif 


/******************************************************************
 *
 *                        Linux Defines
 *
 ******************************************************************/

#if defined(__OS_LINUX__) || defined(__OS_AIX__)

#define	SAF_API 

#endif

//常量定义

#define MAX_BUF_LEN		  8192
#define MAX_DATA_LEN 65536   //最大数据长度
#define MAX_BASE64_DATA_LEN 4096  //base64编解码最大长度
#define MAX_RANDOM_LEN 65535  //最大随机数长度
#define MAX_HASH_DATA_LEN 4096 //最大哈希计算长度
#define MAX_ID_LEN 16 //最大用户ID长度
#define MAX_ECC_DATA_LEN 4096 //最大ECC加密长度
#define MAX_SYMM_CAL_DATA_LEN 8192  //最大对称加密数据长度
#define MAX_P7_DATA_LEN 8192  //最大P7操作数据长度



//密码杂凑算法标识
#define SGD_SM3     0x00000001         //SM3杂凑算法
#define SGD_SHA1    0x00000002         //SHA1杂凑算法
#define SGD_SHA256  0x00000004         //SHA256杂凑算法

//非对称密码算法标识
#define SGD_RSA     0x00010000         //RSA算法
#define SGD_SM2     0x00020100         //SM2椭圆曲线密码算法
#define SGD_SM2_1   0x00020200         //SM2椭圆曲线签名算法
#define SGD_SM2_2   0x00020400         //SM2椭圆曲线密钥交换协议
#define SGD_SM2_3   0x00020800         //SM2椭圆曲线加密算法

//对称算法标识
#define SGD_SM1_ECB         0x00000101       //SM1算法ECB加密模式
#define SGD_SM1_CBC         0x00000102       //SM1算法CBC加密模式
#define SGD_SM1_CFB         0x00000104       //SM1算法CFB加密模式
#define SGD_SM1_OFB         0x00000108       //SM1算法OFB加密模式
#define SGD_SM1_MAC         0x00000110       //SM1算法MAC加密模式
#define SGD_SSF33_ECB       0x00000201       //SSF33算法ECB加密模式
#define SGD_SSF33_CBC       0x00000202       //SSF33算法CBC加密模式
#define SGD_SSF33_CFB       0x00000204       //SSF33算法CFB加密模式
#define SGD_SSF33_OFB       0x00000208       //SSF33算法OFB加密模式
#define SGD_SSF33_MAC       0x00000210       //SSF33算法MAC加密模式
#define SGD_SM4_ECB         0x00000401       //SM4算法ECB加密模式
#define SGD_SM4_CBC         0x00000402       //SM4算法CBC加密模式
#define SGD_SM4_CFB         0x00000404       //SM4算法CFB加密模式
#define SGD_SM4_OFB         0x00000408       //SM4算法OFB加密模式
#define SGD_SM4_MAC         0x00000410       //SM4算法MAC加密模式
#define SGD_ZUC_EEA3        0x00000801       //ZUC祖冲之机密性算法128-EEA3算法
#define SGD_ZUC_EIA3        0x00000802       //ZUC祖冲之机密性算法128-EIA3算法
#define SGD_3DES_ECB        0x00002001
#define SGD_3DES_CBC	    0x00002002
#define SGD_AES128_ECB      0x00004001
#define SGD_AES128_CBC	    0x00004002

//证书解析项标识
#define SGD_CERT_VERISON							0x00000001       //证书版本
#define SGD_CERT_SERIAL								0x00000002       //证书序列号
#define SGD_CERT_ISSUER								0x00000005       //证书颁发者信息
#define SGD_CERT_VALID_TIME							0x00000006       //证书有效期
#define SGD_CERT_SUBJECT							0x00000007       //证书拥有者信息
#define SGD_CERT_DER_PUBLIC_KEY						0x00000008       //证书公钥信息
#define SGD_CERT_DER_EXTENSIONS						0x00000009       //证书扩展项信息
#define SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO         0x00000011       //颁发者密钥标识符
#define SGD_EXT_SUBJECTKEYIDENTIFIER_INFO           0x00000012       //证书持有者密钥标识符
#define SGD_EXT_KEYUSAGE_INFO					    0x00000013       //密钥用途
#define SGD_EXT_PRIVATEKEYUSAGEPERIOD_INFO          0x00000014		 //私钥有效期
#define SGD_EXT_CERTIFICATEPOLICIES_INFO            0x00000015       //证书策略
#define SGD_EXT_POLICYMAPPINGS_INFO                 0x00000016       //策略映射
#define SGD_EXT_BASICCONSTRAINTS_INFO               0x00000017       //基本限制
#define SGD_EXT_POLICYCONTRAINTS_INFO               0x00000018       //策略限制
#define SGD_EXT_EXTKEYUSAGE_INFO                    0x00000019       //扩展密钥用途
#define SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO          0x0000001A       //CRL发布点
#define SGD_EXT_NETSCAPE_CERT_TYPE_INFO             0x0000001B       //Netscape属性
#define SGD_EXT_SELFDEFINED_EXTENSION_INFO          0x0000001C       //私有的自定义扩展项
#define SGD_CERT_ISSUER_CN                          0x00000021       //证书颁发者CN
#define SGD_CERT_ISSUER_O                           0x00000022       //证书颁发者O
#define SGD_CERT_ISSUER_OU                          0x00000023       //证书颁发者OU
#define SGD_CERT_SUBJECT_CN                         0x00000031       //证书拥有者信息CN
#define SGD_CERT_SUBJECT_O                          0x00000032       //证书拥有者信息O
#define SGD_CERT_SUBJECT_OU                         0x00000033       //证书拥有者信息OU
#define SGD_CERT_SUBJECT_EMAIL                      0x00000034       //证书拥有者信息EMAIL
#define SGD_GDCA_EXT_CERT_TYPE_UFID		     			0x00010001	   //证书类型统一编号(GDCA)
#define SGD_GDCA_EXT_CERT_TYPE_SUBCODE					0x00010002	   //证书类型子代码(GDCA)
#define SGD_GDCA_EXT_CERT_TYPE_ALL			  			0x00010003	   //证书类型统一编号及子代码(GDCA)
#define	SGD_GDCA_EXT_CERT_TRUST_ID                       0x00010004	   //证书信任服务号(GDCA)

#define SGD_MAX_COUNT         64    //枚举出的对象数量最大值 
#define SGD_MAX_NAME_SIZE     256   //证书某项信息的字符串长度最大值


//数据结构定义

//证书链
typedef struct SGD_EXT_CHAIN_LIST_{
	unsigned int certCount;                                  //证书总数
	unsigned char *certificate[SGD_MAX_COUNT];               //DER编码的数字证书
	unsigned int certificateLen[SGD_MAX_COUNT];              //数字证书的长度
}SGD_EXT_CHAIN_LIST;


//用户证书列表
typedef struct SGD_USR_CERT_ENUMLIST_{
	unsigned int certCount;                                  //证书总数
	unsigned char *certificate[SGD_MAX_COUNT];               //DER编码的数字证书
	unsigned int certificateLen[SGD_MAX_COUNT];              //数字证书的长度
	unsigned char *containerName[SGD_MAX_COUNT];             //容器名称
	unsigned int containerNameLen[SGD_MAX_COUNT];            //容器名称的长度
	unsigned int keyUsage[SGD_MAX_COUNT];                    //密钥用途
}SGD_USR_CERT_ENUMLIST;

//密钥容器信息列表
typedef struct SGD_KEYCONTAINERINFO_ENUMLIST_{
	unsigned int keyPairCount;                              //密钥容器信息总数
	unsigned char *containerName[SGD_MAX_COUNT];            //容器名称
	unsigned int containerNameLen[SGD_MAX_COUNT];          //容器名称的长度
	unsigned int keyUsage[SGD_MAX_COUNT];                   //密钥用途，1：加密，2：签名，3：密钥交换
	unsigned int keyType[SGD_MAX_COUNT];                    //密钥类型，1：SM2，2：RSA1024，3：RSA2048，4：RSA3074，5：RSA4096
}SGD_KEYCONTAINERINFO_ENUMLIST;

//证书中DN的结构
typedef struct{
	unsigned char dn_c[SGD_MAX_NAME_SIZE];                  //国家名称
	unsigned char dn_c_len[1];                              //国家名称的长度
	unsigned char dn_s[SGD_MAX_NAME_SIZE];                  //省份或直辖市名称
	unsigned char dn_s_len[1];                              //省份或直辖市名称的长度
	unsigned char dn_l[SGD_MAX_NAME_SIZE];                  //城市或地区的名称
	unsigned char dn_l_len[1];                              //城市或地区名称的长度
	unsigned char dn_o[5][SGD_MAX_NAME_SIZE];               //机构名称数组
	unsigned int dn_o_len[5];                               //机构名称数组的长度
	unsigned char dn_ou[5][SGD_MAX_NAME_SIZE];              //机构单位名称数组
	unsigned int dn_ou_len[5];                              //机构单位名称数组的长度
	unsigned char dn_cn[2][SGD_MAX_NAME_SIZE];              //证书拥有者名称数组
	unsigned int dn_cn_len[2];                              //证书拥有者名称数组的长度
	unsigned char dn_email[2][SGD_MAX_NAME_SIZE];           //电子邮件数组
	unsigned int dn_email_len[2];                           //电子邮件数组的长度
}SGD_NAME_INFO;

typedef struct{
	unsigned char major;
	unsigned char minor;
}SGD_VERSION;

//设备信息
typedef struct{
	SGD_VERSION		Version;
	char		Manufacturer[64];
	char		Issuer[64];
	char		Label[32];
	char		SerialNumber[32];
	SGD_VERSION		HWVersion;
	SGD_VERSION		FirmwareVersion;
	unsigned long		AlgSymCap;
	unsigned long		AlgAsymCap;
	unsigned long		AlgHashCap;
	unsigned long		DevAuthAlgId;
	unsigned long		TotalSpace;
	unsigned long		FreeSpace;
	unsigned char  		Reserved[64];
}SGD_DEVINFO;

//函数定义

//初始化环境
SAF_API int SAF_Initialize(
		void **phAppHandle, 
		char *pucCfgFilePath);

//清除环境
SAF_API int SAF_Finalize(
		void *hAppHandle);

//获取接口版本信息
SAF_API int SAF_GetVersion(
		unsigned int *puiVersion);

//用户登陆
SAF_API int SAF_Login(
		void *hAppHandle,
		unsigned int uiUsrType,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned char *pucPin,
		unsigned int uiPinLen,
		unsigned int *puiRemainCount);

//修改PIN
SAF_API int SAF_ChangePin(
		void *hAppHandle,
		unsigned int uiUsrType,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned char *pucOldPin,
		unsigned int uiOldPinLen,
		unsigned char *pucNewPin,
		unsigned int uiNewPinLen,
		unsigned int *puiRemainCount);

//注销登陆
SAF_API int SAF_Logout(
		void *hAppHandle,
		unsigned int uiUsrType);

//添加信任的CA根证书
SAF_API int SAF_AddTrustedRootCaCertificate(
		void *hAppHandle,
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen);

//获取根CA证书个数
SAF_API int SAF_GetRootCaCertificateCount(
		void *hAppHandle,
		unsigned int *puiCount);

//获取根CA证书
SAF_API int SAF_GetRootCaCertificate(
		void *hAppHandle,
		unsigned int uiIndex,
		unsigned char *pucCertificate,
		unsigned int *puiCertificateLen);

//删除根CA证书
SAF_API int SAF_RemoveRootCaCertificate(
		void *hAppHandle,
		unsigned int uiIndex);

//添加CA证书
SAF_API int SAF_AddCaCertificate(
		void *hAppHandle,
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen);

//获取CA证书个数
SAF_API int SAF_GetCaCertificateCount(
		void *hAppHandle,
		unsigned int *puiCount);

//获取CA证书
SAF_API int SAF_GetCaCertificate(
		void *hAppHandle,
		unsigned int uiIndex,
		unsigned char *pucCertificate,
		unsigned int *puiCertificateLen);

//删除CA证书
SAF_API int SAF_RemoveCaCertificate(
		void *hAppHandle,
		unsigned int uiIndex);

//添加CRL
SAF_API int SAF_AddCrl(
		void *hAppHandle,
		unsigned char *pucDerCrl,
		unsigned int uiDerCrlLen);

//验证用户证书
SAF_API int SAF_VerifyCertificate(
		void *hAppHandle,
		unsigned char *pucUsrCertificate,
		unsigned int uiUsrCertificateLen);

//根据CRL文件获取用户证书状态
SAF_API int SAF_VerifyCertificateByCrl(
		void *hAppHandle,
		unsigned char *pucUsrCertificate,
		unsigned int uiUsrCertificateLen,
		unsigned char *pucDerCrl,
		unsigned int uiDerCrlLen);

//根据OCSP获取证书状态
SAF_API int SAF_GetCertifitcateStateByOCSP(
		void *hAppHandle,
		unsigned char *pcOcspHostURL,
		unsigned int uiOcspHostURLLen,
		unsigned char *pucUsrCertificate,
		unsigned int uiUsrCertificateLen,
		unsigned char *pucCACertificate,
		unsigned int uiCACertificateLen);

//通过LDAP方式获取证书
SAF_API int SAF_GetCertFromLdap(
		void *hAppHandle,
		char *pcLdapHostURL,
		unsigned int uiLdapHostURLLen,
		unsigned char *pucQueryDN,
		unsigned int uiQueryDNLen,
		unsigned char *pucOutCert,
		unsigned int *puiOutCertLen);

//通过LDAP方式获取证书对应的CRL
SAF_API int SAF_GetCrlFromLdap(
		void *hAppHandle,
		char *pcLdapHostURL,
		unsigned int uiLdapHostURLLen,
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen,
		unsigned char *pucCrlData,
		unsigned int *puiCrlDataLen);

//取证书信息
SAF_API int SAF_GetCertificateInfo(
		void *hAppHandle,
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen,
		unsigned int uiInfoType,
		unsigned char *pucInfo,
		unsigned int *puiInfoLen);

//取证书扩展信息
SAF_API int SAF_GetExtTypeInfo(
		void *hAppHandle,
		unsigned char *pucDerCert,
		unsigned int uiDerCertLen,
		unsigned int uiInfoType,
		unsigned char *pucPriOid,
		unsigned int uiPriOidLen,
		unsigned char *pucInfo,
		unsigned int *puiInfoLen);

//列举用户证书
SAF_API int SAF_EnumCertificates(
		void *hAppHandle,
		SGD_USR_CERT_ENUMLIST *usrCerts);

//列举用户的密钥容器信息
SAF_API int SAF_EnumKeyContainerInfo(
		void *hAppHandle,
		SGD_KEYCONTAINERINFO_ENUMLIST *keyContainerInfo);

//释放列举用户证书的内存
SAF_API int SAF_EnumCertificatesFree(
		void *hAppHandle,
		SGD_USR_CERT_ENUMLIST *usrCerts);

//释放列举密钥容器信息的内存
SAF_API int SAF_EnumKeyContainerInfoFree(
		void *hAppHandle,
		SGD_KEYCONTAINERINFO_ENUMLIST *keyContainerInfo);

//单块BASE64编码
SAF_API int SAF_Base64_Encode(
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//单块BASE64解码
SAF_API int SAF_Base64_Decode(
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//创建BASE64对象
SAF_API int SAF_Base64_CreateBase64Obj(
		void **phBase64Obj);

//销毁BASE64对象
SAF_API int SAF_Base64_DestroyBase64Obj(
		void *hBase64Obj);

//通过BASE64对象多块编码
SAF_API int SAF_Base64_EncodeUpdate(
		void *hBase64Obj,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//通过BASE64对象编码结束
SAF_API int SAF_Base64_EncodeFinal(
		void *hBase64Obj,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//通过BASE64对象多块解码
SAF_API int SAF_Base64_DecodeUpdate(
		void *hBase64Obj,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//通过BASE64对象解码结束
SAF_API int SAF_Base64_DecodeFinal(
		void *hBase64Obj,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//生成随机数
SAF_API int SAF_GenRandom(
		unsigned int uiRandLen,
		unsigned char *pucRand);

//HASH运算
SAF_API int SAF_Hash(
		unsigned int uiAlgoType,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucPublicKey,
		unsigned int ulPublicKeyLen,
		unsigned char *pucID,
		unsigned int ulIDLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//创建HASH对象
SAF_API int SAF_CreateHashObj(
		void **phHashObj,
		unsigned int uiAlgorithmType,
		unsigned char *pucPublicKey,
		unsigned int ulPublicKeyLen,
		unsigned char *pucID,
		unsigned int ulIDLen);

//删除HASH对象
SAF_API int SAF_DestroyHashObj(
		void *hHashObj);

//通过对象进行多块HASH运算
SAF_API int SAF_HashUpdate(
		void *hHashObj,
		unsigned char *pucInData,
		unsigned int uiInDataLen);

//结束HASH运算
SAF_API int SAF_HashFinal(
		void *hHashObj,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//生成RSA密钥对
SAF_API int SAF_GenRsaKeyPair(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int uiKeyBits,
		unsigned int uiKeyUsage,
		unsigned int uiExportFlag);

//获取RSA公钥
SAF_API int SAF_GetRsaPublicKey(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int uiKeyUsage,
		unsigned char *pucPublicKey,
		unsigned int *puiPublicKeyLen);

//RSA签名运算
SAF_API int SAF_RsaSign(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int uiHashAlgorithmID,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucSignData,
		unsigned int *puiSignDataLen);

//对文件进行RSA签名运算
SAF_API int SAF_RsaSignFile(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int uiHashAlgorithmID,
		unsigned char *pucFileName,
		unsigned char *pucSignData,
		unsigned int *puiSignDataLen);

//RSA验证签名运算
SAF_API int SAF_RsaVerifySign(
		unsigned int uiHashAlgorithmID,
		unsigned char *pucPublicKey,
		unsigned int uiPublicKeyLen,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucSignData,
		unsigned int uiSignDataLen);

//对文件及其签名进行RSA验证
SAF_API int SAF_RsaVerifySignFile(
		unsigned int uiHashAlgorithmID,
		unsigned char *pucPublicKey,
		unsigned int uiPublicKeyLen,
		unsigned char *pucFileName,
		unsigned char *pucSignData,
		unsigned int uiSignDataLen);

//基于证书的RSA公钥验证
SAF_API int SAF_VerifySignByCert(
		unsigned int uiHashAlgorithmID,
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucSignData,
		unsigned int uiSignDataLen);

//基于证书的RSA公钥加密
SAF_API int SAF_RsaPublicKeyEncByCert(
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//生成ECC密钥对
SAF_API int SAF_GenEccKeyPair(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerLen,
		unsigned int uiKeyBits,
		unsigned int uiKeyUsage,
		unsigned int uiExportFlag);

//获取ECC公钥
SAF_API int SAF_GetEccPublicKey(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int uiKeyUsage,
		unsigned char *pucPublicKey,
		unsigned int *puiPublicKeyLen);

//ECC签名
SAF_API int SAF_EccSign(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int uiAlgorithmID,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucSignData,
		unsigned int *puiSignDataLen);

//ECC验证
SAF_API int SAF_EccVerifySign(
		unsigned char *pucPublicKey,
		unsigned int uiPublicKeyLen,
		unsigned int uiAlgorithmID,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucSignData,
		unsigned int uiSignDataLen);

//ECC公钥加密
SAF_API int SAF_EccPublicKeyEnc(
		unsigned char *pucPublicKey,
		unsigned int uiPublicKeyLen,
		unsigned int uiAlgorithmID,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//基于证书的ECC公钥加密
SAF_API int SAF_EccPublicKeyEncByCert(
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen,
		unsigned int uiAlgorithmID,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//基于证书的ECC公钥验证
SAF_API int SAF_EccVerifySignByCert(
		unsigned int uiAlgorithmID,
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucSignData,
		unsigned int uiSignDataLen);

//创建对称算法对象
SAF_API int SAF_CreateSymmKeyObj(
		void *hAppHandle,
		void **phSymmKeyObj,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned char *pucIV,
		unsigned int uiIVLen,
		unsigned int uiEncOrDec,
		unsigned int uiCryptoAlgID);

//生成会话密钥并用外部公钥加密输出
SAF_API int SAF_GenerateKeyWithEPK(
		void *hSymmKeyObj,
		unsigned char *pucPublicKey,
		unsigned int uiPublicKeyLen,
		unsigned char *pucSymmKey,
		unsigned int *puiSymmKeyLen,
		void **phKeyHandle);

//导入加密的会话密钥
SAF_API int SAF_ImportEncedKey(
		void *hSymmKeyObj,
		unsigned char *pucSymmKey,
		unsigned int uiSymmKeyLen,
		void **phKeyHandle);

//生成密钥协商参数并输出
SAF_API int SAF_GenerateAgreementDataWithECC(
		void *hSymmKeyObj,
		unsigned int uiISKIndex,
		unsigned int uiKeyBits,
		unsigned char *pucSponsorID,
		unsigned int uiSponsorIDLength,
		unsigned char *pucSponsorPublicKey,
		unsigned int *puiSponsorPublicKeyLen,
		unsigned char *pucSponsorTmpPublicKey,
		unsigned int *puiSponsorTmpPublicKeyLen,
		void **phAgreementHandle);

//计算会话密钥
SAF_API int SAF_GenerateKeyWithECC(
		void *hAgreementHandle,
		unsigned char *pucResponseID,
		unsigned int uiResponseIDLength,
		unsigned char *pucResponsePublicKey,
		unsigned int uiResponsePublicKeyLen,
		unsigned char *pucResponseTmpPublicKey,
		unsigned int uiResponseTmpPublicKeyLen,
		void **phKeyHandle);

//产生协商数据并计算会话密钥
SAF_API int SAF_GenerateAgreementDataAndKeyWithECC(
		void *hSymmKeyObj,
		unsigned int uiISKIndex,
		unsigned int uiKeyBits,
		unsigned char *pucResponseID,
		unsigned int uiResponseIDLength,
		unsigned char *pucSponsorID,
		unsigned int uiSponsorIDLength,
		unsigned char *pucSponsorPublicKey,
		unsigned int uiSponsorPublicKeyLen,
		unsigned char *pucSponsorTmpPublicKey,
		unsigned int uiSponsorTmpPublicKeyLen,
		unsigned char *pucResponsePublicKey,
		unsigned int *puiRespinsePublicKeyLen,
		unsigned char *pucResponseTmpPublicKey,
		unsigned int *puiResponseTmpPublicKeyLen,
		void **phKeyHandle);

//销毁对称算法对象
SAF_API int SAF_DestroySymmKeyObj(
		void *hSymmKeyObj);

//销毁会话密钥句柄
SAF_API int SAF_DestroyKeyHandle(
		void *hKeyHandle);

//单块加密运算
SAF_API int SAF_SymmEncrypt(
	void *hKeyHandle,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

//多块加密运算
SAF_API int SAF_SymmEncryptUpdate(
	void *hKeyHandle,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

//结束加密运算
SAF_API int SAF_SymmEncryptFinal(
	void *hKeyHandle,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

//单块解密运算
SAF_API int SAF_SymmDecrypt(
	void *hKeyHandle,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

//多块解密运算
SAF_API int SAF_SymmDecryptUpdate(
	void *hKeyHandle,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

//结束解密运算
SAF_API int SAF_SymmDecryptFinal(
	void *hKeyHandle,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

//单组数据消息鉴别码运算
SAF_API int SAF_Mac(
		void *hKeyHandle,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//多组数据消息鉴别码运算
SAF_API int SAF_MacUpdate(
		void *hKeyHandle,
		unsigned char *pucInData,
		unsigned int uiInDataLen);

//结束消息鉴别码运算
SAF_API int SAF_MacFinal(
		void *hKeyHandle,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//编码PKCS#7格式的带签名的数字信封数据
SAF_API int SAF_Pkcs7_EncodeData(
		void *hAppHandle,
		unsigned char *pucSignContainerName,
		unsigned int uiSignContainerNameLen,
		unsigned int uiSignKeyUsage,
		unsigned char *pucSignerCertificate,
		unsigned int uiSignerCertificateLen,
		unsigned int uiDigestAlgorithms,
		unsigned char *pucEncCertificate,
		unsigned int uiEncCertificateLen,
		unsigned int uiSymmAlgorithm,
		unsigned char *pucData,
		unsigned int uiDataLen,
		unsigned char *pucDerP7Data,
		unsigned int *puiDerP7DataLen);

//解码PKCS#7格式的带签名的数字信封数据
SAF_API int SAF_Pkcs7_DecodeData(
		void *hAppHandle,
		unsigned char *pucDecContainerName,
		unsigned int uiDecContainerNameLen,
		unsigned int uiDecKeyUsage,
		unsigned char *pucDerP7Data,
		unsigned int uiDerP7DataLen,
		unsigned char *pucData,
		unsigned int *puiDataLen,
		unsigned char *pucSignerCertificate,
		unsigned int *puiSignerCertificateLen,
		unsigned int *puiDigestAlgorithms,
		unsigned char *pucSignedData,
		unsigned int *puiSignedDataLen);

//编码PKCS7#7格式的签名数据
SAF_API int SAF_Pkcs7_EncodeSignedData(
		void *hAppHandle,
		unsigned char *pucSignContainerName,
		unsigned int uiSignContainerNameLen,
		unsigned int uiSignKeyUsage,
		unsigned char *pucSignerCertificate,
		unsigned int uiSignerCertificateLen,
		unsigned int uiDigestAlgorithms,
		unsigned char *pucData,
		unsigned int uiDataLen,
		unsigned char *pucDerP7SignedData,
		unsigned int *puiDerP7SignedDataLen);

//解码PKCS7#7格式的签名数据
SAF_API int SAF_Pkcs7_DecodeSignedData(
		void *hAppHandle,
		unsigned char *pucDerP7SignedData,
		unsigned int uiDerP7SignedDataLen,
		unsigned char *pucSignerCertificate,
		unsigned int *puiSignerCertificateLen,
		unsigned int *puiDigestAlgorithms,
		unsigned char *pucData,
		unsigned int *puiDataLen,
		unsigned char *pucSign,
		unsigned int *puiSignLen);

//编码PKCS#7格式的数字信封
SAF_API int SAF_Pkcs7_EncodeEnvelopedData(
		void *hAppHandle,
		unsigned char *pucData,
		unsigned int uiDataLen,
		unsigned char *pucEncCertificate,
		unsigned int uiEncCertificateLen,		
		unsigned int uiSymmAlgorithm,
		unsigned char *pucDerP7EnvopedData,
		unsigned int *puiDerP7EnvopedDataLen);

//解码PKCS#7格式的数字信封
SAF_API int SAF_Pkcs7_DecodeEnvelopedData(
		void *hAppHandle,
		unsigned char *pucDecContainerName,
		unsigned int uiDecContainerNameLen,
		unsigned int uiDecKeyUsage,
		unsigned char *pucDerP7EnvopedData,
		unsigned int uiDerP7EnvopedDataLen,
		unsigned char *pucData,
		unsigned int *puiDataLen);

//编码PKCS#7格式的摘要数据
SAF_API int SAF_Pkcs7_EncodeDigestedData(
		void *hAppHandle,
		unsigned int uiDigestAlgorithm,
		unsigned char *pucData,
		unsigned int uiDataLen,
		unsigned char *pucDerP7DigestedData,
		unsigned int *puiDerP7DigestedDataLen);

//解码PKCS#7格式的摘要数据
SAF_API int SAF_Pkcs7_DecodeDigestedData(
		void *hAppHandle,
		unsigned int uiDigestAlgorithm,
		unsigned char *pucDerP7DigestedData,
		unsigned int uiDerP7DigestedDataLen,
		unsigned char *pucData,
		unsigned int *puiDataLen,
		unsigned char *pucDigest,
		unsigned int *puiDigestLen);

//编码基于SM2算法的带签名的数字信封数据
SAF_API int SAF_SM2_EncodeSignedAndEnvelopedData(
		void *hAppHandle,
		unsigned char *pucSignContainerName,
		unsigned int uiSignContainerNameLen,
		unsigned int uiSignKeyUsage,
		unsigned char *pucSignerCertificate,
		unsigned int uiSignerCertificateLen,
		unsigned int uiDigestAlgorithms,
		unsigned char *pucEncCertificate,
		unsigned int uiEncCertificateLen,
		unsigned int uiSymmAlgorithm,
		unsigned char *pucData,
		unsigned int uiDataLen,
		unsigned char *pucDerSignedAndEnvelopedData,
		unsigned int *puiDerSignedAndEnvelopedDataLen);

//解码基于SM2算法的带签名的数字信封数据
SAF_API int SAF_SM2_DecodeSignedAndEnvelopedData(
		void *hAppHandle,
		unsigned char *pucDecContainerName,
		unsigned int uiDecContainerNameLen,
		unsigned int uiDecKeyUsage,
		unsigned char *pucDerSignedAndEnvelopedData,
		unsigned int uiDerSignedAndEnvelopedDataLen,
		unsigned char *pucData,
		unsigned int *puiDataLen,
		unsigned char *pucSignerCertificate,
		unsigned int *puiSignerCertificateLen,
		unsigned int *puiDigestAlgorithms);

//编码基于SM2算法的签名数据
SAF_API int SAF_SM2_EncodeSignedData(
		void *hAppHandle,
		unsigned char *pucSignContainerName,
		unsigned int uiSignContainerNameLen,
		unsigned int uiSignKeyUsage,
		unsigned char *pucSignerCertificate,
		unsigned int uiSignerCertificateLen,
		unsigned int uiDigestAlgorithms,
		unsigned char *pucData,
		unsigned int uiDataLen,
		unsigned char *pucDerSignedData,
		unsigned int *puiDerSignedDataLen);

//解码基于SM2算法的签名数据
SAF_API int SAF_SM2_DecodeSignedData(
		void *hAppHandle,
		unsigned char *pucDerSignedData,
		unsigned int uiDerSignedDataLen,
		unsigned char *pucSignerCertificate,
		unsigned int *puiSignerCertificateLen,
		unsigned int *puiDigestAlgorithms,
		unsigned char *pucData,
		unsigned int *puiDataLen,
		unsigned char *pucSign,
		unsigned int *puiSignLen);

//编码基于SM2算法的数字信封
SAF_API int SAF_SM2_EncodeEnvelopedData(
		void *hAppHandle,
		unsigned char *pucData,
		unsigned int uiDataLen,
		unsigned char *pucEncCertificate,
		unsigned int uiEncCertificateLen,		
		unsigned int uiSymmAlgorithm,
		unsigned char *pucDerEnvopedData,
		unsigned int *puiDerEnvopedDataLen);

//解码基于SM2算法的数字信封
SAF_API int SAF_SM2_DecodeEnvelopedData(
		void *hAppHandle,
		unsigned char *pucDecContainerName,
		unsigned int uiDecContainerNameLen,
		unsigned int uiDecKeyUsage,
		unsigned char *pucDerEnvopedData,
		unsigned int uiDerEnvopedDataLen,
		unsigned char *pucData,
		unsigned int *puiDataLen);

//获取设备信息
SAF_API int SAF_GetDeviceInfo(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		SGD_DEVINFO *pucDeviceInfo);

//获取PIN剩余重试次数
SAF_API int SAF_GetPinRetryCount(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int  ulPINType,
		unsigned int *pulRemainRetryCount);

/////////////////////////////////// GDCA Extension /////////////////////////////////////////////

SAF_API int SAF_Ext_isLogin(
			void *hAppHandle,
			unsigned char *pucContainerName,
			unsigned int uiContainerNameLen,
			unsigned long ulLoginType);

SAF_API int SAF_Ext_ReadLabel(
			void *hAppHandle,
			unsigned char *pucContainerName,
			unsigned int uiContainerNameLen,
			unsigned char *pucName,
			unsigned long ulNameLen,
			unsigned long ulType,
			unsigned char *pucOutData,
			unsigned long *pulOutDataLen);

SAF_API int SAF_Ext_ReadUsrDataFile(
			void *hAppHandle,
			unsigned char *pucContainerName,
			unsigned int uiContainerNameLen,
			unsigned long ulFileType,
			unsigned long ulFileIndex,
			unsigned long ulOffset,    
			unsigned long ulReadLen,
			unsigned char *pucReadData);

SAF_API int SAF_Ext_WriteUsrDataFile(
			void *hAppHandle,
			unsigned char *pucContainerName,
			unsigned int uiContainerNameLen,
			unsigned char *pucPin,
			unsigned long ulPinLen,
			unsigned long ulFileType,
			unsigned long ulFileIndex,
			unsigned long ulOffset,
			unsigned long ulWriteLen,
			unsigned char *pucWriteData);

SAF_API int SAF_Ext_HashFile(
            unsigned long  uiAlgorithmType,
			unsigned char *pucPublicKey,
			unsigned long  ulPublicKeyLen,
			unsigned char *pucID,
			unsigned long  ulIDLen,
            unsigned char *pucInFile,
            unsigned long  ulInFileLen,
            unsigned char *pucOutData,
            unsigned long *pulOutDataLen
            );

SAF_API int SAF_Ext_TspGetTime(
			unsigned char *pucTime,
    		unsigned long *pulTimeLen);

SAF_API int SAF_Ext_TspGetStamp(
			void *hAppHandle,
			unsigned char *pucContainerName,
			unsigned int   uiContainerNameLen,
			unsigned char *pucInData,
			unsigned long  ulInDataLen,
			unsigned char *pucStampResp,
			unsigned long *pulStampRespLen);

SAF_API int SAF_Ext_TspVerifyStamp(
    		unsigned char *pucInData,
    		unsigned long  ulInDataLen,
    		unsigned char *pucStamp,
    		unsigned long  ulStampLen,
			unsigned char *pucTsaCert,
			unsigned long  ulTsaCertLen,
			unsigned char *pucTimeInfo,
			unsigned long *pulTimeInfoLen);

SAF_API int SAF_Ext_TspGetFileStamp(
			void *hAppHandle,
			unsigned char *pucContainerName,
			unsigned int   uiContainerNameLen,
			unsigned char *puInFile,
			unsigned long  ulInFileLen,
			unsigned char *pucStampResp,
			unsigned long *pulStampRespLen);

SAF_API int SAF_Ext_TspVerifyFileStamp(
    		unsigned char *pucInFile,
    		unsigned long  ulInFileLen,
    		unsigned char *pucStamp,
			unsigned long  ulStampLen,
			unsigned char *pucTsaCert,
			unsigned long  ulTsaCertLen,
			unsigned char *pucTimeInfo,
			unsigned long *pulTimeInfoLen);

SAF_API int SAF_Ext_Pkcs7_EncodeSignedData(
		void *hAppHandle,
		unsigned char *pucSignContainerName,
		unsigned int uiSignContainerNameLen,
		unsigned int uiSignKeyUsage,
		unsigned char *pucSignerCertificate,
		unsigned int uiSignerCertificateLen,
		unsigned int uiDigestAlgorithms,
		SGD_EXT_CHAIN_LIST *certChainList,
		unsigned int   uiSignType,
		unsigned char *pucData,
		unsigned int uiDataLen,
		unsigned char *pucDerP7SignedData,
		unsigned int *puiDerP7SignedDataLen);


SAF_API int SAF_Ext_SignFile(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int uiHashAlgorithmID, //GMT0006: 1:SM3, 2:SHA1, 4:SHA256
		unsigned char *pucID,
		unsigned long  ulIDLen,
		unsigned char *pucInFile,
		unsigned long  ulInFileLen,
		unsigned char *pucSignData,
		unsigned int *puiSignDataLen);


SAF_API int SAF_Ext_VerifySignFile(
		unsigned int uiHashAlgorithmID, //GMT0006: 1:SM3, 2:SHA1, 4:SHA256
		unsigned char *pucPublicKey,
		unsigned int uiPublicKeyLen,
		unsigned char *pucID,
		unsigned long  ulIDLen,
		unsigned char *pucInFile,
		unsigned long  ulInFileLen,
		unsigned char *pucSignData,
		unsigned int uiSignDataLen);


SAF_API int SAF_Ext_VerifySignFileByCert(
		unsigned int uiHashAlgorithmID, //GMT0006: 1:SM3, 2:SHA1, 4:SHA256
		unsigned char *pucCert,
		unsigned int   uiCertLen,
		unsigned char *pucID,
		unsigned long  ulIDLen,
		unsigned char *pucInFile,
		unsigned long  ulInFileLen,
		unsigned char *pucSignData,
		unsigned int uiSignDataLen);

SAF_API int SAF_Ext_EncodeEnvelopedFile(
										void *hAppHandle,
										unsigned char *pucInFile,
										unsigned long  ulInFileLen,
										unsigned char *pucEncCertificate,
										unsigned int uiEncCertificateLen,		
										unsigned int uiSymmAlgorithm,
										unsigned int uiDoSoftSymmAlgo,
										unsigned char *pucOutFile,
										unsigned long  ulOutFileLen
										);

SAF_API int SAF_Ext_DecodeEnvelopedFile(
										void *hAppHandle,
										unsigned char *pucDecContainerName,
										unsigned int uiDecContainerNameLen,
										unsigned int uiDecKeyUsage,
										unsigned int uiDoSoftSymmAlgo,//not use
										unsigned char *pucInFile,
										unsigned long  ulInFileLen,
										unsigned char *pucOutFile,
										unsigned long  ulOutFileLen
										);

SAF_API int SAF_Ext_SymmEncryptFile(
            unsigned long ulOption,
			unsigned char *pucOptionData,
			unsigned long ulOptionDataLen,
           	unsigned char *pucKey,
			unsigned long ulKeyLen,
           	unsigned char *inDataFilePath,
			unsigned long inDataFilePathLen,
			unsigned char *outDataFilePath,
			unsigned long outDataFilePathLen
            );

SAF_API int SAF_Ext_SymmDecryptFile(
            unsigned long ulOption,
			unsigned char *pucOptionData,
			unsigned long ulOptionDataLen,
           	unsigned char *pucKey,
			unsigned long ulKeyLen,
           	unsigned char *inDataFilePath,
			unsigned long inDataFilePathLen,
			unsigned char *outDataFilePath,
			unsigned long outDataFilePathLen
            );

SAF_API int SAF_Ext_Pkcs7_ReadContentData(
										  void *hAppHandle,
										  unsigned char *pucDerP7SignedData,
										  unsigned int  uiDerP7SignedDataLen,
										  unsigned int  *puiOptionalExist,
										  unsigned int  *puiDigestAlgorithms,
										  unsigned char *pucData,
										  unsigned int  *puiDataLen,
										  unsigned char *pucHash,
										  unsigned int  *puiHashLen);

//XML????
SAF_API int SAF_Ext_XMLSign(
							void *hAppHandle,
							unsigned int uiOption,
							unsigned char *pucSignContainerName,
							unsigned int uiSignContainerNameLen,
							unsigned int uiSignKeyUsage,
							unsigned char *pucSignerCertificate,
							unsigned int uiSignerCertificateLen,
							unsigned int uiDigestAlgorithms,
							unsigned char *pucXMLData,
							unsigned int uiXMLDataLen,
							unsigned char *pucXMLSignedData,
							unsigned int *puiXMLSignedDataLen
							);

//XML??????
SAF_API int SAF_Ext_XMLVerify(
							  void *hAppHandle,
							  unsigned int uiOption,
							  unsigned char *pucXMLSignedData,
							  unsigned int uiXMLSignedDataLen
							  );

//XML??????
SAF_API int SAF_Ext_XMLParse(
							 void *hAppHandle,
							 unsigned int uiOption,
							 unsigned char *pucXMLSignedData,
							 unsigned int uiXMLSignedDataLen,
							 unsigned char *pucXMLData,
							 unsigned int *puiXMLDataLen,
							 unsigned char *pucDigest,
							 unsigned int *puiDigestLen,
							 unsigned char *pucSign,
							 unsigned int *puiSignLen,
							 unsigned char *pucSignerCertificate,
							 unsigned int *puiSignerCertificateLen,
							 unsigned char *pucDigestAlgorithms,
							 unsigned int* puiDigestAlgorithmsLen,
							 unsigned char *pucSignAlgorithms,
							 unsigned int* puiSignAlgorithmsLen
							 );

//??????
SAF_API int SAF_Ext_HashSign(
							 void *hAppHandle,
							 unsigned char *pucContainerName,
							 unsigned int uiContainerNameLen,
							 unsigned int uiAsymAlgId,
							 unsigned int uiHashAlgorithmID,
							 unsigned char *pucInData,
							 unsigned int uiInDataLen,
							 unsigned char *pucSignData,
							 unsigned int *puiSignDataLen);

SAF_API int SAF_Ext_GM_Tsp_GetTime(
								   unsigned char *pucTime,
								   unsigned long *pulTimeLen);

SAF_API int SAF_Ext_GM_Tsp_SealTimeStamp(
										 unsigned int algType,
										 unsigned char *pucInData,
										 unsigned long  ulInDataLen,
										 unsigned char *pucStampResp,
										 unsigned long *pulStampRespLen);

SAF_API int SAF_Ext_GM_Tsp_VerifyTimeStamp(
										   unsigned char *pucInData,
										   unsigned long  ulInDataLen,
										   unsigned char *pucStamp,
										   unsigned long  ulStampLen,
										   unsigned char *pucTsaCert,
										   unsigned long  ulTsaCertLen,
										   unsigned char *pucTimeInfo,
										   unsigned long *pulTimeInfoLen);

SAF_API int SAF_Ext_Control(
							void          *hAppHandle,
							unsigned char *pucContainerName,
							unsigned int   uiContainerNameLen,
							unsigned char *pucControlName,
							unsigned int   uiControlNameLen,	
							unsigned char *pucControlCommand,
							unsigned int   uiControlCommandLen					   
							);
		

//密码服务接口错误码定义
#define SAR_OK                        0                        //成功
#define SAR_UnknownErr                0x02000001               //异常错误
#define SAR_NotSupportYetErr          0x02000002               //不支持的服务
#define SAR_FileErr                   0x02000003               //文件操作错误
#define SAR_ProviderTypeErr           0x02000004               //服务提供者参数类型错误
#define SAR_LoadProviderErr           0x02000005               //导入服务提供者接口错误
#define SAR_LoadDevMngApiErr          0x02000006               //导入设备管理接口错误
#define SAR_AlgoTypeErr               0x02000007               //算法类型错误
#define SAR_NameLenErr                0x02000008               //名称长度错误
#define SAR_KeyUsageErr               0x02000009               //密钥用途错误
#define SAR_ModulusLenErr             0x02000010               //模的长度错误
#define SAR_NotInitializeErr          0x02000011               //未初始化
#define SAR_ObjErr                    0x02000012               //对象错误
#define SAR_MemoryErr                 0x02000100               //内存错误
#define SAR_TimeoutErr                0x02000101               //超时错误
#define SAR_IndataLenErr              0x02000200               //输入数据长度错误
#define SAR_IndataErr				  0x02000201               //输入数据错误
#define SAR_GenRandErr				  0x02000300               //生成随机数错误
#define SAR_HashErr				      0x02000302               //HASH运算错误
#define SAR_GenRsaKeyErr			  0x02000303               //产生RSA密钥错误
#define SAR_RsaModulusLenErr		  0x02000304               //RSA密钥模长错误
#define SAR_CspImportPubKeyErr		  0x02000305               //CSP服务导入公钥错误
#define SAR_RsaEncErr		          0x02000306               //RSA加密错误
#define SAR_RsaDecErr		          0x02000307               //RSA解密错误
#define SAR_HashNotEqualErr		      0x02000308               //HASH值不相等
#define SAR_KeyNotFoundErr		      0x02000309               //密钥未发现
#define SAR_CertNotFoundErr		      0x02000310               //证书未发现
#define SAR_NotExportErr		      0x02000311               //对象未导出
#define SAR_CertRevokedErr		      0x02000316               //证书被吊销
#define SAR_CertNotYetValidErr		  0x02000317               //证书未生效
#define SAR_CertHasExpiredErr		  0x02000318               //证书已过期
#define SAR_CertVerifyErr		      0x02000319               //证书验证错误
#define SAR_CertEncodeErr		      0x02000320               //证书编码错误
#define SAR_DecryptPadErr		      0x02000400               //解密时做补丁错误
#define SAR_MacLenErr		          0x02000401               //MAC长度错误
#define SAR_KeyInfoTypeErr		      0x02000402               //密钥类型错误
#define SAR_NotLoginErr		          0x02000403               //没有进行登陆认证
#define SAR_ECCEncErr		          0x02000501               //ECC加密错误
#define SAR_ECCDecErr		          0x02000502               //ECC解密错误
#define SAR_ExportSKErr               0x02000503               //导出会话密钥错误
#define SAR_ImportSKErr               0x02000504               //导入会话密钥错误
#define SAR_SymmEncErr                0x02000505               //对称加密错误
#define SAR_SymmDecErr                0x02000506               //对称解密错误
#define SAR_PKCS7SignErr              0x02000507               //P7签名错误
#define SAR_PKCS7VerifyErr            0x02000508               //P7验证错误
#define SAR_PKCS7EncErr               0x02000509               //P7加密错误
#define SAR_PKCS7DecErr               0x0200050a               //P7解密错误

#ifdef __cplusplus
}
#endif
																
#endif

