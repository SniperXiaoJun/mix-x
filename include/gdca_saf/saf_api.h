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

//��������

#define MAX_BUF_LEN		  8192
#define MAX_DATA_LEN 65536   //������ݳ���
#define MAX_BASE64_DATA_LEN 4096  //base64�������󳤶�
#define MAX_RANDOM_LEN 65535  //������������
#define MAX_HASH_DATA_LEN 4096 //����ϣ���㳤��
#define MAX_ID_LEN 16 //����û�ID����
#define MAX_ECC_DATA_LEN 4096 //���ECC���ܳ���
#define MAX_SYMM_CAL_DATA_LEN 8192  //���ԳƼ������ݳ���
#define MAX_P7_DATA_LEN 8192  //���P7�������ݳ���



//�����Ӵ��㷨��ʶ
#define SGD_SM3     0x00000001         //SM3�Ӵ��㷨
#define SGD_SHA1    0x00000002         //SHA1�Ӵ��㷨
#define SGD_SHA256  0x00000004         //SHA256�Ӵ��㷨

//�ǶԳ������㷨��ʶ
#define SGD_RSA     0x00010000         //RSA�㷨
#define SGD_SM2     0x00020100         //SM2��Բ���������㷨
#define SGD_SM2_1   0x00020200         //SM2��Բ����ǩ���㷨
#define SGD_SM2_2   0x00020400         //SM2��Բ������Կ����Э��
#define SGD_SM2_3   0x00020800         //SM2��Բ���߼����㷨

//�Գ��㷨��ʶ
#define SGD_SM1_ECB         0x00000101       //SM1�㷨ECB����ģʽ
#define SGD_SM1_CBC         0x00000102       //SM1�㷨CBC����ģʽ
#define SGD_SM1_CFB         0x00000104       //SM1�㷨CFB����ģʽ
#define SGD_SM1_OFB         0x00000108       //SM1�㷨OFB����ģʽ
#define SGD_SM1_MAC         0x00000110       //SM1�㷨MAC����ģʽ
#define SGD_SSF33_ECB       0x00000201       //SSF33�㷨ECB����ģʽ
#define SGD_SSF33_CBC       0x00000202       //SSF33�㷨CBC����ģʽ
#define SGD_SSF33_CFB       0x00000204       //SSF33�㷨CFB����ģʽ
#define SGD_SSF33_OFB       0x00000208       //SSF33�㷨OFB����ģʽ
#define SGD_SSF33_MAC       0x00000210       //SSF33�㷨MAC����ģʽ
#define SGD_SM4_ECB         0x00000401       //SM4�㷨ECB����ģʽ
#define SGD_SM4_CBC         0x00000402       //SM4�㷨CBC����ģʽ
#define SGD_SM4_CFB         0x00000404       //SM4�㷨CFB����ģʽ
#define SGD_SM4_OFB         0x00000408       //SM4�㷨OFB����ģʽ
#define SGD_SM4_MAC         0x00000410       //SM4�㷨MAC����ģʽ
#define SGD_ZUC_EEA3        0x00000801       //ZUC���֮�������㷨128-EEA3�㷨
#define SGD_ZUC_EIA3        0x00000802       //ZUC���֮�������㷨128-EIA3�㷨
#define SGD_3DES_ECB        0x00002001
#define SGD_3DES_CBC	    0x00002002
#define SGD_AES128_ECB      0x00004001
#define SGD_AES128_CBC	    0x00004002

//֤��������ʶ
#define SGD_CERT_VERISON							0x00000001       //֤��汾
#define SGD_CERT_SERIAL								0x00000002       //֤�����к�
#define SGD_CERT_ISSUER								0x00000005       //֤��䷢����Ϣ
#define SGD_CERT_VALID_TIME							0x00000006       //֤����Ч��
#define SGD_CERT_SUBJECT							0x00000007       //֤��ӵ������Ϣ
#define SGD_CERT_DER_PUBLIC_KEY						0x00000008       //֤�鹫Կ��Ϣ
#define SGD_CERT_DER_EXTENSIONS						0x00000009       //֤����չ����Ϣ
#define SGD_EXT_AUTHORITYKEYIDENTIFIER_INFO         0x00000011       //�䷢����Կ��ʶ��
#define SGD_EXT_SUBJECTKEYIDENTIFIER_INFO           0x00000012       //֤���������Կ��ʶ��
#define SGD_EXT_KEYUSAGE_INFO					    0x00000013       //��Կ��;
#define SGD_EXT_PRIVATEKEYUSAGEPERIOD_INFO          0x00000014		 //˽Կ��Ч��
#define SGD_EXT_CERTIFICATEPOLICIES_INFO            0x00000015       //֤�����
#define SGD_EXT_POLICYMAPPINGS_INFO                 0x00000016       //����ӳ��
#define SGD_EXT_BASICCONSTRAINTS_INFO               0x00000017       //��������
#define SGD_EXT_POLICYCONTRAINTS_INFO               0x00000018       //��������
#define SGD_EXT_EXTKEYUSAGE_INFO                    0x00000019       //��չ��Կ��;
#define SGD_EXT_CRLDISTRIBUTIONPOINTS_INFO          0x0000001A       //CRL������
#define SGD_EXT_NETSCAPE_CERT_TYPE_INFO             0x0000001B       //Netscape����
#define SGD_EXT_SELFDEFINED_EXTENSION_INFO          0x0000001C       //˽�е��Զ�����չ��
#define SGD_CERT_ISSUER_CN                          0x00000021       //֤��䷢��CN
#define SGD_CERT_ISSUER_O                           0x00000022       //֤��䷢��O
#define SGD_CERT_ISSUER_OU                          0x00000023       //֤��䷢��OU
#define SGD_CERT_SUBJECT_CN                         0x00000031       //֤��ӵ������ϢCN
#define SGD_CERT_SUBJECT_O                          0x00000032       //֤��ӵ������ϢO
#define SGD_CERT_SUBJECT_OU                         0x00000033       //֤��ӵ������ϢOU
#define SGD_CERT_SUBJECT_EMAIL                      0x00000034       //֤��ӵ������ϢEMAIL
#define SGD_GDCA_EXT_CERT_TYPE_UFID		     			0x00010001	   //֤������ͳһ���(GDCA)
#define SGD_GDCA_EXT_CERT_TYPE_SUBCODE					0x00010002	   //֤�������Ӵ���(GDCA)
#define SGD_GDCA_EXT_CERT_TYPE_ALL			  			0x00010003	   //֤������ͳһ��ż��Ӵ���(GDCA)
#define	SGD_GDCA_EXT_CERT_TRUST_ID                       0x00010004	   //֤�����η����(GDCA)

#define SGD_MAX_COUNT         64    //ö�ٳ��Ķ����������ֵ 
#define SGD_MAX_NAME_SIZE     256   //֤��ĳ����Ϣ���ַ����������ֵ


//���ݽṹ����

//֤����
typedef struct SGD_EXT_CHAIN_LIST_{
	unsigned int certCount;                                  //֤������
	unsigned char *certificate[SGD_MAX_COUNT];               //DER���������֤��
	unsigned int certificateLen[SGD_MAX_COUNT];              //����֤��ĳ���
}SGD_EXT_CHAIN_LIST;


//�û�֤���б�
typedef struct SGD_USR_CERT_ENUMLIST_{
	unsigned int certCount;                                  //֤������
	unsigned char *certificate[SGD_MAX_COUNT];               //DER���������֤��
	unsigned int certificateLen[SGD_MAX_COUNT];              //����֤��ĳ���
	unsigned char *containerName[SGD_MAX_COUNT];             //��������
	unsigned int containerNameLen[SGD_MAX_COUNT];            //�������Ƶĳ���
	unsigned int keyUsage[SGD_MAX_COUNT];                    //��Կ��;
}SGD_USR_CERT_ENUMLIST;

//��Կ������Ϣ�б�
typedef struct SGD_KEYCONTAINERINFO_ENUMLIST_{
	unsigned int keyPairCount;                              //��Կ������Ϣ����
	unsigned char *containerName[SGD_MAX_COUNT];            //��������
	unsigned int containerNameLen[SGD_MAX_COUNT];          //�������Ƶĳ���
	unsigned int keyUsage[SGD_MAX_COUNT];                   //��Կ��;��1�����ܣ�2��ǩ����3����Կ����
	unsigned int keyType[SGD_MAX_COUNT];                    //��Կ���ͣ�1��SM2��2��RSA1024��3��RSA2048��4��RSA3074��5��RSA4096
}SGD_KEYCONTAINERINFO_ENUMLIST;

//֤����DN�Ľṹ
typedef struct{
	unsigned char dn_c[SGD_MAX_NAME_SIZE];                  //��������
	unsigned char dn_c_len[1];                              //�������Ƶĳ���
	unsigned char dn_s[SGD_MAX_NAME_SIZE];                  //ʡ�ݻ�ֱϽ������
	unsigned char dn_s_len[1];                              //ʡ�ݻ�ֱϽ�����Ƶĳ���
	unsigned char dn_l[SGD_MAX_NAME_SIZE];                  //���л����������
	unsigned char dn_l_len[1];                              //���л�������Ƶĳ���
	unsigned char dn_o[5][SGD_MAX_NAME_SIZE];               //������������
	unsigned int dn_o_len[5];                               //������������ĳ���
	unsigned char dn_ou[5][SGD_MAX_NAME_SIZE];              //������λ��������
	unsigned int dn_ou_len[5];                              //������λ��������ĳ���
	unsigned char dn_cn[2][SGD_MAX_NAME_SIZE];              //֤��ӵ������������
	unsigned int dn_cn_len[2];                              //֤��ӵ������������ĳ���
	unsigned char dn_email[2][SGD_MAX_NAME_SIZE];           //�����ʼ�����
	unsigned int dn_email_len[2];                           //�����ʼ�����ĳ���
}SGD_NAME_INFO;

typedef struct{
	unsigned char major;
	unsigned char minor;
}SGD_VERSION;

//�豸��Ϣ
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

//��������

//��ʼ������
SAF_API int SAF_Initialize(
		void **phAppHandle, 
		char *pucCfgFilePath);

//�������
SAF_API int SAF_Finalize(
		void *hAppHandle);

//��ȡ�ӿڰ汾��Ϣ
SAF_API int SAF_GetVersion(
		unsigned int *puiVersion);

//�û���½
SAF_API int SAF_Login(
		void *hAppHandle,
		unsigned int uiUsrType,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned char *pucPin,
		unsigned int uiPinLen,
		unsigned int *puiRemainCount);

//�޸�PIN
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

//ע����½
SAF_API int SAF_Logout(
		void *hAppHandle,
		unsigned int uiUsrType);

//������ε�CA��֤��
SAF_API int SAF_AddTrustedRootCaCertificate(
		void *hAppHandle,
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen);

//��ȡ��CA֤�����
SAF_API int SAF_GetRootCaCertificateCount(
		void *hAppHandle,
		unsigned int *puiCount);

//��ȡ��CA֤��
SAF_API int SAF_GetRootCaCertificate(
		void *hAppHandle,
		unsigned int uiIndex,
		unsigned char *pucCertificate,
		unsigned int *puiCertificateLen);

//ɾ����CA֤��
SAF_API int SAF_RemoveRootCaCertificate(
		void *hAppHandle,
		unsigned int uiIndex);

//���CA֤��
SAF_API int SAF_AddCaCertificate(
		void *hAppHandle,
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen);

//��ȡCA֤�����
SAF_API int SAF_GetCaCertificateCount(
		void *hAppHandle,
		unsigned int *puiCount);

//��ȡCA֤��
SAF_API int SAF_GetCaCertificate(
		void *hAppHandle,
		unsigned int uiIndex,
		unsigned char *pucCertificate,
		unsigned int *puiCertificateLen);

//ɾ��CA֤��
SAF_API int SAF_RemoveCaCertificate(
		void *hAppHandle,
		unsigned int uiIndex);

//���CRL
SAF_API int SAF_AddCrl(
		void *hAppHandle,
		unsigned char *pucDerCrl,
		unsigned int uiDerCrlLen);

//��֤�û�֤��
SAF_API int SAF_VerifyCertificate(
		void *hAppHandle,
		unsigned char *pucUsrCertificate,
		unsigned int uiUsrCertificateLen);

//����CRL�ļ���ȡ�û�֤��״̬
SAF_API int SAF_VerifyCertificateByCrl(
		void *hAppHandle,
		unsigned char *pucUsrCertificate,
		unsigned int uiUsrCertificateLen,
		unsigned char *pucDerCrl,
		unsigned int uiDerCrlLen);

//����OCSP��ȡ֤��״̬
SAF_API int SAF_GetCertifitcateStateByOCSP(
		void *hAppHandle,
		unsigned char *pcOcspHostURL,
		unsigned int uiOcspHostURLLen,
		unsigned char *pucUsrCertificate,
		unsigned int uiUsrCertificateLen,
		unsigned char *pucCACertificate,
		unsigned int uiCACertificateLen);

//ͨ��LDAP��ʽ��ȡ֤��
SAF_API int SAF_GetCertFromLdap(
		void *hAppHandle,
		char *pcLdapHostURL,
		unsigned int uiLdapHostURLLen,
		unsigned char *pucQueryDN,
		unsigned int uiQueryDNLen,
		unsigned char *pucOutCert,
		unsigned int *puiOutCertLen);

//ͨ��LDAP��ʽ��ȡ֤���Ӧ��CRL
SAF_API int SAF_GetCrlFromLdap(
		void *hAppHandle,
		char *pcLdapHostURL,
		unsigned int uiLdapHostURLLen,
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen,
		unsigned char *pucCrlData,
		unsigned int *puiCrlDataLen);

//ȡ֤����Ϣ
SAF_API int SAF_GetCertificateInfo(
		void *hAppHandle,
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen,
		unsigned int uiInfoType,
		unsigned char *pucInfo,
		unsigned int *puiInfoLen);

//ȡ֤����չ��Ϣ
SAF_API int SAF_GetExtTypeInfo(
		void *hAppHandle,
		unsigned char *pucDerCert,
		unsigned int uiDerCertLen,
		unsigned int uiInfoType,
		unsigned char *pucPriOid,
		unsigned int uiPriOidLen,
		unsigned char *pucInfo,
		unsigned int *puiInfoLen);

//�о��û�֤��
SAF_API int SAF_EnumCertificates(
		void *hAppHandle,
		SGD_USR_CERT_ENUMLIST *usrCerts);

//�о��û�����Կ������Ϣ
SAF_API int SAF_EnumKeyContainerInfo(
		void *hAppHandle,
		SGD_KEYCONTAINERINFO_ENUMLIST *keyContainerInfo);

//�ͷ��о��û�֤����ڴ�
SAF_API int SAF_EnumCertificatesFree(
		void *hAppHandle,
		SGD_USR_CERT_ENUMLIST *usrCerts);

//�ͷ��о���Կ������Ϣ���ڴ�
SAF_API int SAF_EnumKeyContainerInfoFree(
		void *hAppHandle,
		SGD_KEYCONTAINERINFO_ENUMLIST *keyContainerInfo);

//����BASE64����
SAF_API int SAF_Base64_Encode(
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//����BASE64����
SAF_API int SAF_Base64_Decode(
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//����BASE64����
SAF_API int SAF_Base64_CreateBase64Obj(
		void **phBase64Obj);

//����BASE64����
SAF_API int SAF_Base64_DestroyBase64Obj(
		void *hBase64Obj);

//ͨ��BASE64���������
SAF_API int SAF_Base64_EncodeUpdate(
		void *hBase64Obj,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//ͨ��BASE64����������
SAF_API int SAF_Base64_EncodeFinal(
		void *hBase64Obj,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//ͨ��BASE64���������
SAF_API int SAF_Base64_DecodeUpdate(
		void *hBase64Obj,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//ͨ��BASE64����������
SAF_API int SAF_Base64_DecodeFinal(
		void *hBase64Obj,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//���������
SAF_API int SAF_GenRandom(
		unsigned int uiRandLen,
		unsigned char *pucRand);

//HASH����
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

//����HASH����
SAF_API int SAF_CreateHashObj(
		void **phHashObj,
		unsigned int uiAlgorithmType,
		unsigned char *pucPublicKey,
		unsigned int ulPublicKeyLen,
		unsigned char *pucID,
		unsigned int ulIDLen);

//ɾ��HASH����
SAF_API int SAF_DestroyHashObj(
		void *hHashObj);

//ͨ��������ж��HASH����
SAF_API int SAF_HashUpdate(
		void *hHashObj,
		unsigned char *pucInData,
		unsigned int uiInDataLen);

//����HASH����
SAF_API int SAF_HashFinal(
		void *hHashObj,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//����RSA��Կ��
SAF_API int SAF_GenRsaKeyPair(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int uiKeyBits,
		unsigned int uiKeyUsage,
		unsigned int uiExportFlag);

//��ȡRSA��Կ
SAF_API int SAF_GetRsaPublicKey(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int uiKeyUsage,
		unsigned char *pucPublicKey,
		unsigned int *puiPublicKeyLen);

//RSAǩ������
SAF_API int SAF_RsaSign(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int uiHashAlgorithmID,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucSignData,
		unsigned int *puiSignDataLen);

//���ļ�����RSAǩ������
SAF_API int SAF_RsaSignFile(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int uiHashAlgorithmID,
		unsigned char *pucFileName,
		unsigned char *pucSignData,
		unsigned int *puiSignDataLen);

//RSA��֤ǩ������
SAF_API int SAF_RsaVerifySign(
		unsigned int uiHashAlgorithmID,
		unsigned char *pucPublicKey,
		unsigned int uiPublicKeyLen,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucSignData,
		unsigned int uiSignDataLen);

//���ļ�����ǩ������RSA��֤
SAF_API int SAF_RsaVerifySignFile(
		unsigned int uiHashAlgorithmID,
		unsigned char *pucPublicKey,
		unsigned int uiPublicKeyLen,
		unsigned char *pucFileName,
		unsigned char *pucSignData,
		unsigned int uiSignDataLen);

//����֤���RSA��Կ��֤
SAF_API int SAF_VerifySignByCert(
		unsigned int uiHashAlgorithmID,
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucSignData,
		unsigned int uiSignDataLen);

//����֤���RSA��Կ����
SAF_API int SAF_RsaPublicKeyEncByCert(
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//����ECC��Կ��
SAF_API int SAF_GenEccKeyPair(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerLen,
		unsigned int uiKeyBits,
		unsigned int uiKeyUsage,
		unsigned int uiExportFlag);

//��ȡECC��Կ
SAF_API int SAF_GetEccPublicKey(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int uiKeyUsage,
		unsigned char *pucPublicKey,
		unsigned int *puiPublicKeyLen);

//ECCǩ��
SAF_API int SAF_EccSign(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned int uiAlgorithmID,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucSignData,
		unsigned int *puiSignDataLen);

//ECC��֤
SAF_API int SAF_EccVerifySign(
		unsigned char *pucPublicKey,
		unsigned int uiPublicKeyLen,
		unsigned int uiAlgorithmID,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucSignData,
		unsigned int uiSignDataLen);

//ECC��Կ����
SAF_API int SAF_EccPublicKeyEnc(
		unsigned char *pucPublicKey,
		unsigned int uiPublicKeyLen,
		unsigned int uiAlgorithmID,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//����֤���ECC��Կ����
SAF_API int SAF_EccPublicKeyEncByCert(
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen,
		unsigned int uiAlgorithmID,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//����֤���ECC��Կ��֤
SAF_API int SAF_EccVerifySignByCert(
		unsigned int uiAlgorithmID,
		unsigned char *pucCertificate,
		unsigned int uiCertificateLen,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucSignData,
		unsigned int uiSignDataLen);

//�����Գ��㷨����
SAF_API int SAF_CreateSymmKeyObj(
		void *hAppHandle,
		void **phSymmKeyObj,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		unsigned char *pucIV,
		unsigned int uiIVLen,
		unsigned int uiEncOrDec,
		unsigned int uiCryptoAlgID);

//���ɻỰ��Կ�����ⲿ��Կ�������
SAF_API int SAF_GenerateKeyWithEPK(
		void *hSymmKeyObj,
		unsigned char *pucPublicKey,
		unsigned int uiPublicKeyLen,
		unsigned char *pucSymmKey,
		unsigned int *puiSymmKeyLen,
		void **phKeyHandle);

//������ܵĻỰ��Կ
SAF_API int SAF_ImportEncedKey(
		void *hSymmKeyObj,
		unsigned char *pucSymmKey,
		unsigned int uiSymmKeyLen,
		void **phKeyHandle);

//������ԿЭ�̲��������
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

//����Ự��Կ
SAF_API int SAF_GenerateKeyWithECC(
		void *hAgreementHandle,
		unsigned char *pucResponseID,
		unsigned int uiResponseIDLength,
		unsigned char *pucResponsePublicKey,
		unsigned int uiResponsePublicKeyLen,
		unsigned char *pucResponseTmpPublicKey,
		unsigned int uiResponseTmpPublicKeyLen,
		void **phKeyHandle);

//����Э�����ݲ�����Ự��Կ
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

//���ٶԳ��㷨����
SAF_API int SAF_DestroySymmKeyObj(
		void *hSymmKeyObj);

//���ٻỰ��Կ���
SAF_API int SAF_DestroyKeyHandle(
		void *hKeyHandle);

//�����������
SAF_API int SAF_SymmEncrypt(
	void *hKeyHandle,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

//����������
SAF_API int SAF_SymmEncryptUpdate(
	void *hKeyHandle,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

//������������
SAF_API int SAF_SymmEncryptFinal(
	void *hKeyHandle,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

//�����������
SAF_API int SAF_SymmDecrypt(
	void *hKeyHandle,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

//����������
SAF_API int SAF_SymmDecryptUpdate(
	void *hKeyHandle,
	unsigned char *pucInData,
	unsigned int uiInDataLen,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

//������������
SAF_API int SAF_SymmDecryptFinal(
	void *hKeyHandle,
	unsigned char *pucOutData,
	unsigned int *puiOutDataLen);

//����������Ϣ����������
SAF_API int SAF_Mac(
		void *hKeyHandle,
		unsigned char *pucInData,
		unsigned int uiInDataLen,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//����������Ϣ����������
SAF_API int SAF_MacUpdate(
		void *hKeyHandle,
		unsigned char *pucInData,
		unsigned int uiInDataLen);

//������Ϣ����������
SAF_API int SAF_MacFinal(
		void *hKeyHandle,
		unsigned char *pucOutData,
		unsigned int *puiOutDataLen);

//����PKCS#7��ʽ�Ĵ�ǩ���������ŷ�����
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

//����PKCS#7��ʽ�Ĵ�ǩ���������ŷ�����
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

//����PKCS7#7��ʽ��ǩ������
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

//����PKCS7#7��ʽ��ǩ������
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

//����PKCS#7��ʽ�������ŷ�
SAF_API int SAF_Pkcs7_EncodeEnvelopedData(
		void *hAppHandle,
		unsigned char *pucData,
		unsigned int uiDataLen,
		unsigned char *pucEncCertificate,
		unsigned int uiEncCertificateLen,		
		unsigned int uiSymmAlgorithm,
		unsigned char *pucDerP7EnvopedData,
		unsigned int *puiDerP7EnvopedDataLen);

//����PKCS#7��ʽ�������ŷ�
SAF_API int SAF_Pkcs7_DecodeEnvelopedData(
		void *hAppHandle,
		unsigned char *pucDecContainerName,
		unsigned int uiDecContainerNameLen,
		unsigned int uiDecKeyUsage,
		unsigned char *pucDerP7EnvopedData,
		unsigned int uiDerP7EnvopedDataLen,
		unsigned char *pucData,
		unsigned int *puiDataLen);

//����PKCS#7��ʽ��ժҪ����
SAF_API int SAF_Pkcs7_EncodeDigestedData(
		void *hAppHandle,
		unsigned int uiDigestAlgorithm,
		unsigned char *pucData,
		unsigned int uiDataLen,
		unsigned char *pucDerP7DigestedData,
		unsigned int *puiDerP7DigestedDataLen);

//����PKCS#7��ʽ��ժҪ����
SAF_API int SAF_Pkcs7_DecodeDigestedData(
		void *hAppHandle,
		unsigned int uiDigestAlgorithm,
		unsigned char *pucDerP7DigestedData,
		unsigned int uiDerP7DigestedDataLen,
		unsigned char *pucData,
		unsigned int *puiDataLen,
		unsigned char *pucDigest,
		unsigned int *puiDigestLen);

//�������SM2�㷨�Ĵ�ǩ���������ŷ�����
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

//�������SM2�㷨�Ĵ�ǩ���������ŷ�����
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

//�������SM2�㷨��ǩ������
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

//�������SM2�㷨��ǩ������
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

//�������SM2�㷨�������ŷ�
SAF_API int SAF_SM2_EncodeEnvelopedData(
		void *hAppHandle,
		unsigned char *pucData,
		unsigned int uiDataLen,
		unsigned char *pucEncCertificate,
		unsigned int uiEncCertificateLen,		
		unsigned int uiSymmAlgorithm,
		unsigned char *pucDerEnvopedData,
		unsigned int *puiDerEnvopedDataLen);

//�������SM2�㷨�������ŷ�
SAF_API int SAF_SM2_DecodeEnvelopedData(
		void *hAppHandle,
		unsigned char *pucDecContainerName,
		unsigned int uiDecContainerNameLen,
		unsigned int uiDecKeyUsage,
		unsigned char *pucDerEnvopedData,
		unsigned int uiDerEnvopedDataLen,
		unsigned char *pucData,
		unsigned int *puiDataLen);

//��ȡ�豸��Ϣ
SAF_API int SAF_GetDeviceInfo(
		void *hAppHandle,
		unsigned char *pucContainerName,
		unsigned int uiContainerNameLen,
		SGD_DEVINFO *pucDeviceInfo);

//��ȡPINʣ�����Դ���
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
		

//�������ӿڴ����붨��
#define SAR_OK                        0                        //�ɹ�
#define SAR_UnknownErr                0x02000001               //�쳣����
#define SAR_NotSupportYetErr          0x02000002               //��֧�ֵķ���
#define SAR_FileErr                   0x02000003               //�ļ���������
#define SAR_ProviderTypeErr           0x02000004               //�����ṩ�߲������ʹ���
#define SAR_LoadProviderErr           0x02000005               //��������ṩ�߽ӿڴ���
#define SAR_LoadDevMngApiErr          0x02000006               //�����豸����ӿڴ���
#define SAR_AlgoTypeErr               0x02000007               //�㷨���ʹ���
#define SAR_NameLenErr                0x02000008               //���Ƴ��ȴ���
#define SAR_KeyUsageErr               0x02000009               //��Կ��;����
#define SAR_ModulusLenErr             0x02000010               //ģ�ĳ��ȴ���
#define SAR_NotInitializeErr          0x02000011               //δ��ʼ��
#define SAR_ObjErr                    0x02000012               //�������
#define SAR_MemoryErr                 0x02000100               //�ڴ����
#define SAR_TimeoutErr                0x02000101               //��ʱ����
#define SAR_IndataLenErr              0x02000200               //�������ݳ��ȴ���
#define SAR_IndataErr				  0x02000201               //�������ݴ���
#define SAR_GenRandErr				  0x02000300               //�������������
#define SAR_HashErr				      0x02000302               //HASH�������
#define SAR_GenRsaKeyErr			  0x02000303               //����RSA��Կ����
#define SAR_RsaModulusLenErr		  0x02000304               //RSA��Կģ������
#define SAR_CspImportPubKeyErr		  0x02000305               //CSP�����빫Կ����
#define SAR_RsaEncErr		          0x02000306               //RSA���ܴ���
#define SAR_RsaDecErr		          0x02000307               //RSA���ܴ���
#define SAR_HashNotEqualErr		      0x02000308               //HASHֵ�����
#define SAR_KeyNotFoundErr		      0x02000309               //��Կδ����
#define SAR_CertNotFoundErr		      0x02000310               //֤��δ����
#define SAR_NotExportErr		      0x02000311               //����δ����
#define SAR_CertRevokedErr		      0x02000316               //֤�鱻����
#define SAR_CertNotYetValidErr		  0x02000317               //֤��δ��Ч
#define SAR_CertHasExpiredErr		  0x02000318               //֤���ѹ���
#define SAR_CertVerifyErr		      0x02000319               //֤����֤����
#define SAR_CertEncodeErr		      0x02000320               //֤��������
#define SAR_DecryptPadErr		      0x02000400               //����ʱ����������
#define SAR_MacLenErr		          0x02000401               //MAC���ȴ���
#define SAR_KeyInfoTypeErr		      0x02000402               //��Կ���ʹ���
#define SAR_NotLoginErr		          0x02000403               //û�н��е�½��֤
#define SAR_ECCEncErr		          0x02000501               //ECC���ܴ���
#define SAR_ECCDecErr		          0x02000502               //ECC���ܴ���
#define SAR_ExportSKErr               0x02000503               //�����Ự��Կ����
#define SAR_ImportSKErr               0x02000504               //����Ự��Կ����
#define SAR_SymmEncErr                0x02000505               //�ԳƼ��ܴ���
#define SAR_SymmDecErr                0x02000506               //�Գƽ��ܴ���
#define SAR_PKCS7SignErr              0x02000507               //P7ǩ������
#define SAR_PKCS7VerifyErr            0x02000508               //P7��֤����
#define SAR_PKCS7EncErr               0x02000509               //P7���ܴ���
#define SAR_PKCS7DecErr               0x0200050a               //P7���ܴ���

#ifdef __cplusplus
}
#endif
																
#endif

