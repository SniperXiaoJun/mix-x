
#ifndef __MSC_CLIENT_API_H__

#define __MSC_CLIENT_API_H__

#include "common.h"

typedef enum _MSCAPIErrCode
{
	MSCAPIErrCodeSuccess = 0,
	MSCAPIErrCodeBase    = 0x1F0000,
	MSCAPIErrCodeMemLess,



	MSCAPIErrCodeFailure = -1
}MSCAPIErrCode;


#ifdef __cplusplus
extern "C" {
#endif

	/*
	��������:	���Ӱ�ȫоƬ
	��������:	MSCAPI_ConnextSecureElement
	�������:	
	�������:	
				
	����ֵ: 
	ʧ�ܣ�
	��������:	
	*/
	COMMON_API unsigned int MSCAPI_ConnectSecureElement(int iFlag);

	/*
	��������:	�Ͽ���ȫоƬ
	��������:	MSCAPI_ConnextSecureElement
	�������:	
	�������:	

	����ֵ: 
	ʧ�ܣ�
	��������:	
	*/
	COMMON_API unsigned int MSCAPI_DisConnectSecureElement(int iFlag);

	/*
	��������:	��ȡ��ȫоƬ���к�
	��������:	MSCAPI_ReadSecureElementSerialNumber
	�������:	
	�������:	
				pszSN	   ���к�ֵ
				puiSNLen   ���к�ֵ����
	����ֵ: 
	ʧ�ܣ�
	��������:	
	*/
	COMMON_API unsigned int MSCAPI_ReadSecureElementSerialNumber(char * pszSN,unsigned int *puiSNLen, int iFlag);

	/*
	��������:	��ȡ��ȫоƬ֤��
	��������:	MSCAPI_ReadSecureElementCerts
	�������:	
	�������:	
				pszCerts	  ֤������
				puiCertsLen      ֤�鳤��
	����ֵ: 
	ʧ�ܣ�
	��������:	
	*/
	COMMON_API unsigned int MSCAPI_ReadSecureElementCerts(char * pszCerts,unsigned int *puiCertsLen, int iFlag);

	/*
	��������:	��ȡCPU���к�
	��������:	MSCAPI_ReadCPUSerialNumber
	�������:	
	�������:	
				pszSN	   ���к�ֵ
				puiSNLen   ���к�ֵ����
	����ֵ: 
	ʧ�ܣ�
	��������:	
	*/
	COMMON_API unsigned int MSCAPI_ReadCPUSerialNumber(char * pszSN,unsigned int *puiSNLen, int iFlag);

	/*
	��������:	��ȡӲ�����к�
	��������:	MSCAPI_ReadHardDiskSerialNumber
	�������:	
	�������:	
				pszSN	   ���к�ֵ
				puiSNLen   ���к�ֵ����
	����ֵ: 
	ʧ�ܣ�
	��������:	
	*/
	COMMON_API unsigned int MSCAPI_ReadHardDiskSerialNumber(char * pszSN,unsigned int *puiSNLen, int iFlag);

	/*
	��������:	��ȡMAC��ַ
	��������:	MSCAPI_ReadHostMACAddress
	�������:	
	�������:	
				pszAddress	   ��ֵַ
				puiAddressLen   ��ֵַ����
	����ֵ: 
	ʧ�ܣ�
	��������:	
	*/
	COMMON_API unsigned int MSCAPI_ReadHostMACAddress(char * pszAddress,unsigned int *puiAddressLen, int iFlag);

	/*
	��������:	��ȡ����IP��ַ
	��������:	MSCAPI_ReadHostIPAddress
	�������:	
	�������:	
				pszAddress	   ��ֵַ
				puiAddressLen   ��ֵַ����
	����ֵ: 
	ʧ�ܣ�
	��������:	
	*/
	COMMON_API unsigned int MSCAPI_ReadHostIPAddress(char * pszAddress,unsigned int *puiAddressLen, int iFlag);

	/*
	��������:	��ȡ����IP��ַ
	��������:	MSCAPI_ReadHostAddress
	�������:
	�������:
	pszAddress	   ��ֵַ
	puiAddressLen   ��ֵַ����
	����ֵ:
	ʧ�ܣ�
	��������:
	*/

	typedef struct _STHostAddress
	{
		char szIPAddress[32];
		char szMacAddress[32];
	}STHostAddress;

	COMMON_API unsigned int MSCAPI_ReadHostAddress(STHostAddress *pszAddress, unsigned int *puiAddressLen);


	/*
	��������:	����Ӳ����ϢHASHֵ
	��������:	MSCAPI_CalcHWInfoHash
	�������:	
	�������:	
				pszHash	   HASHֵ
				puiHashLen   HASHֵ����
	����ֵ: 
	ʧ�ܣ�
	��������:	
	*/
	COMMON_API unsigned int MSCAPI_CalcHWInfoHash(char *pszCpuSN,char *pszMacSN, char *pszHostMacAddress, char *pszHostIPAddress,char * pszHash,unsigned int *puiHashLen, int iFlag);


	/*
	��������:	��ȡ����ϵͳ�汾��Ϣ
	��������:	MSCAPI_ReadSystemVersionInfo
	�������:	
	�������:	
				pszSysInfo	     ��Ϣֵ
				puiSysInfoLen    ��Ϣ����
	����ֵ: 
	ʧ�ܣ�
	��������:	
	*/
	COMMON_API unsigned int MSCAPI_ReadSystemVersionInfo(char * pszSysInfo,unsigned int *puiSysInfoLen, int iFlag);

	/*
	��������:	��ȡ������汾��Ϣ
	��������:	MSCAPI_ReadBrowserVersionInfo
	�������:	
	�������:	
				pszBrowserInfo	     ��Ϣֵ
				puiBrowserInfoLen    ��Ϣ����
	����ֵ: 
	ʧ�ܣ�
	��������:	
	*/
	COMMON_API unsigned int MSCAPI_ReadBrowserVersionInfo(char * pszBrowserInfo,unsigned int *puiBrowserInfoLen, int iFlag);

	/*
	��������:	��ȡ�ͻ��˰汾��Ϣ
	��������:	MSCAPI_ReadClientCSPInfo
	�������:	
	�������:	
				pszCSPInfo	     ��Ϣֵ
				puiCSPInfoLen    ��Ϣ����
	����ֵ: 
	ʧ�ܣ�
	��������:	
	*/
	COMMON_API unsigned int MSCAPI_ReadClientCSPInfo(char * pszCSPInfo,unsigned int *puiCSPInfoLen, int iFlag);


#ifdef __cplusplus
}
#endif



#endif