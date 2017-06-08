// 防火墙杀毒软件头文件
#ifndef __CHECK_API_H__
#define __CHECK_API_H__



//////////////////////////////////////////////////////////////////////////
// 类型声明
// 

// 产品类型
#define PROVIDER_FIREWALL               1	// 防火墙产品
#define PROVIDER_ANTIVIRUS				4	// 反病毒产品

// 激活状态
#define ACTIVESTATE_ENABLED		1	// 启用
#define ACTIVESTATE_DISABLED	2	// 关闭
#define ACTIVESTATE_UNKNOWN		3	// 未知
// 版本状态
#define VESIONSTATE_NEW			1	// 最新版本
#define VESIONSTATE_OLD			2	// 版本过老
#define VESIONSTATE_UNKNOWN		3	// 未知

// 安全产品信息结构体
typedef  struct	st_SecurityProduct
{
	unsigned long	ulType;		// 产品类型: 防火墙(PROVIDER_FIREWALL) 和 杀毒软件(PROVIDER_ANTIVIRUS)
	wchar_t	*pDisplayName;		// 产品名称
	wchar_t	*pCompanyName;		// 公司名称(可能为"")
	char	bActiveState;		// 激活状态: ACTIVESTATE_ENABLED(启用) 或 ACTIVESTATE_DISABLED(关闭) 或 ACTIVESTATE_UNKNOWN(未知)
	
//反病毒专用--->
	char	bVesionState;		// 病毒库版本状态: VESIONSTATE_NEW(最新) 或 VESIONSTATE_OLD(过时) 或 VESIONSTATE_UNKNOWN(未知)
	wchar_t	*pVersionNumber;    // 病毒库版本
//<---
	
	// 
	st_SecurityProduct	*next;	// 指向下一个SECURITY_PRODUCT
	// 
} SECURITY_PRODUCT;


// 安全产品信息链表
class CSecurityProductList
{
private:
	SECURITY_PRODUCT		*mp_Header;

	SECURITY_PRODUCT		*mp_Next;
public:
	CSecurityProductList();
	
	~CSecurityProductList();
	
public:
	unsigned long	Add (unsigned long ulProviderType, wchar_t *pszDisplayName, wchar_t *pszCompanyName, wchar_t* pszVersionNumber, char boolEnabled, char boolNew);
	BOOL			Next(SECURITY_PRODUCT		*psp);
	
};



//////////////////////////////////////////////////////////////////////////
// 函数声明
// 


// 安全产品类型: 反病毒产品
#define		SECURITYCENTER_ANTIVIRUS	1
// 安全产品类型: 防火墙产品
#define		SECURITYCENTER_FIREWALL		2

/**
 * 检测安全中心软件
 * 
 * @param ulSecurityCenterType		[IN]检测安全产品类型: 反病毒产品(SECURITYCENTER_ANTIVIRUS) 或 防火墙产品(SECURITYCENTER_FIREWALL)
 * @param p_SecurityProductList		[IN/OUT] 安全产品链表
 * 
 * @return	0: 成功
 * 			非0: 失败, 返回错误代码
 */
unsigned long	CheckSecurityCenter(unsigned long ulSecurityCenterType, CSecurityProductList *p_SecurityProductList);




#endif