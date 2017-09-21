
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
	功能名称:	连接安全芯片
	函数名称:	MSCAPI_ConnextSecureElement
	输入参数:	
	输出参数:	
				
	返回值: 
	失败：
	功能描述:	
	*/
	COMMON_API unsigned int MSCAPI_ConnectSecureElement(int iFlag);

	/*
	功能名称:	断开安全芯片
	函数名称:	MSCAPI_ConnextSecureElement
	输入参数:	
	输出参数:	

	返回值: 
	失败：
	功能描述:	
	*/
	COMMON_API unsigned int MSCAPI_DisConnectSecureElement(int iFlag);

	/*
	功能名称:	读取安全芯片序列号
	函数名称:	MSCAPI_ReadSecureElementSerialNumber
	输入参数:	
	输出参数:	
				pszSN	   序列号值
				puiSNLen   序列号值长度
	返回值: 
	失败：
	功能描述:	
	*/
	COMMON_API unsigned int MSCAPI_ReadSecureElementSerialNumber(char * pszSN,unsigned int *puiSNLen, int iFlag);

	/*
	功能名称:	读取安全芯片证书
	函数名称:	MSCAPI_ReadSecureElementCerts
	输入参数:	
	输出参数:	
				pszCerts	  证书内容
				puiCertsLen      证书长度
	返回值: 
	失败：
	功能描述:	
	*/
	COMMON_API unsigned int MSCAPI_ReadSecureElementCerts(char * pszCerts,unsigned int *puiCertsLen, int iFlag);

	/*
	功能名称:	读取CPU序列号
	函数名称:	MSCAPI_ReadCPUSerialNumber
	输入参数:	
	输出参数:	
				pszSN	   序列号值
				puiSNLen   序列号值长度
	返回值: 
	失败：
	功能描述:	
	*/
	COMMON_API unsigned int MSCAPI_ReadCPUSerialNumber(char * pszSN,unsigned int *puiSNLen, int iFlag);

	/*
	功能名称:	读取硬盘序列号
	函数名称:	MSCAPI_ReadHardDiskSerialNumber
	输入参数:	
	输出参数:	
				pszSN	   序列号值
				puiSNLen   序列号值长度
	返回值: 
	失败：
	功能描述:	
	*/
	COMMON_API unsigned int MSCAPI_ReadHardDiskSerialNumber(char * pszSN,unsigned int *puiSNLen, int iFlag);

	/*
	功能名称:	读取MAC地址
	函数名称:	MSCAPI_ReadHostMACAddress
	输入参数:	
	输出参数:	
				pszAddress	   地址值
				puiAddressLen   地址值长度
	返回值: 
	失败：
	功能描述:	
	*/
	COMMON_API unsigned int MSCAPI_ReadHostMACAddress(char * pszAddress,unsigned int *puiAddressLen, int iFlag);

	/*
	功能名称:	读取主机IP地址
	函数名称:	MSCAPI_ReadHostIPAddress
	输入参数:	
	输出参数:	
				pszAddress	   地址值
				puiAddressLen   地址值长度
	返回值: 
	失败：
	功能描述:	
	*/
	COMMON_API unsigned int MSCAPI_ReadHostIPAddress(char * pszAddress,unsigned int *puiAddressLen, int iFlag);

	/*
	功能名称:	读取主机IP地址
	函数名称:	MSCAPI_ReadHostAddress
	输入参数:
	输出参数:
	pszAddress	   地址值
	puiAddressLen   地址值长度
	返回值:
	失败：
	功能描述:
	*/

	typedef struct _STHostAddress
	{
		char szIPAddress[32];
		char szMacAddress[32];
	}STHostAddress;

	COMMON_API unsigned int MSCAPI_ReadHostAddress(STHostAddress *pszAddress, unsigned int *puiAddressLen);


	/*
	功能名称:	计算硬件信息HASH值
	函数名称:	MSCAPI_CalcHWInfoHash
	输入参数:	
	输出参数:	
				pszHash	   HASH值
				puiHashLen   HASH值长度
	返回值: 
	失败：
	功能描述:	
	*/
	COMMON_API unsigned int MSCAPI_CalcHWInfoHash(char *pszCpuSN,char *pszMacSN, char *pszHostMacAddress, char *pszHostIPAddress,char * pszHash,unsigned int *puiHashLen, int iFlag);


	/*
	功能名称:	读取操作系统版本信息
	函数名称:	MSCAPI_ReadSystemVersionInfo
	输入参数:	
	输出参数:	
				pszSysInfo	     信息值
				puiSysInfoLen    信息长度
	返回值: 
	失败：
	功能描述:	
	*/
	COMMON_API unsigned int MSCAPI_ReadSystemVersionInfo(char * pszSysInfo,unsigned int *puiSysInfoLen, int iFlag);

	/*
	功能名称:	读取浏览器版本信息
	函数名称:	MSCAPI_ReadBrowserVersionInfo
	输入参数:	
	输出参数:	
				pszBrowserInfo	     信息值
				puiBrowserInfoLen    信息长度
	返回值: 
	失败：
	功能描述:	
	*/
	COMMON_API unsigned int MSCAPI_ReadBrowserVersionInfo(char * pszBrowserInfo,unsigned int *puiBrowserInfoLen, int iFlag);

	/*
	功能名称:	读取客户端版本信息
	函数名称:	MSCAPI_ReadClientCSPInfo
	输入参数:	
	输出参数:	
				pszCSPInfo	     信息值
				puiCSPInfoLen    信息长度
	返回值: 
	失败：
	功能描述:	
	*/
	COMMON_API unsigned int MSCAPI_ReadClientCSPInfo(char * pszCSPInfo,unsigned int *puiCSPInfoLen, int iFlag);


#ifdef __cplusplus
}
#endif



#endif