
// 该文件内所有返回的JSON串内容出现中文字符都显示为乱码（UTF8串在WIN32终端显示）
// 返回值JSON结构msg代表信息，success代表成功与否为bool值，sec_level表示安全级别值对应TYPE_SEC_LEVEL,state代表状态信息其他都与函数本身相关


#ifndef _EBANK_SYSTEM_DETECT_H
#define _EBANK_SYSTEM_DETECT_H

#include <Windows.h>

typedef enum URL_TRUST_TYPE
{
	URL_TRUST_TYPE_YES = 0x02,		// 受信任站点
	URL_TRUST_TYPE_NO = 0x04,		// 受限制站点
}URL_TRUST_TYPE;

typedef enum TYPE_SAFE_LEVEL
{
	TYPE_SAFE_LOW,
	TYPE_SAFE_MEDIUM_LOW,
	TYPE_SAFE_MEDIUM,
	TYPE_SAFE_MEDIUM_HIGH,
	TYPE_SAFE_HIGH,
}TYPE_SAFE_LEVEL;

// 检测安全级别
typedef enum TYPE_SEC_LEVEL
{
	TYPE_SEC_NORMAL,       // 正常
	TYPE_SEC_WARNING,       // 警告
	TYPE_SEC_EXCEPT,       // 异常
}TYPE_SEC_LEVEL;

// 证书有效级别
// expiration_status
typedef enum EXPIRATION_STATUS
{
	EXPIRATION_STATUS_IN = 0,			// 正常
	EXPIRATION_STATUS_LEFT_IN_EXPIRE = 1,	// 即将到期
	EXPIRATION_STATUS_OUT = 2,			// 不在有效期
}EXPIRATION_STATUS;

typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
typedef BOOL (WINAPI *PGPI)(DWORD, DWORD, DWORD, DWORD, PDWORD);

#include <string>
#include <list>
using namespace std;


/*
	函数功能：获取防火墙软件信息
	返回值： json string 
	返回JSON结构：
	{
	"active_state" : "开启",
	"company_name" : "Microsoft",
	"product_name" : "Windows Firewall",
	"product_type" : "防火墙",
	"sec_level" : 0,
	"success" : 1
	}
*/
string WTF_GetFireWallInfo();

/*
	函数功能：获取杀毒软件信息
	返回值： json string 
	返回JSON结构:
	{
	"active_state" : "未开启",
	"company_name" : "",
	"product_name" : "金山杀毒软件",
	"product_type" : "杀毒软件",
	"sec_level" : 0,
	"success" : 1,
	"version_number" : "",
	"version_state" : "最新"
	}
*/
string WTF_GetAntivirusInfo();

/*
	函数功能：获取时间信息
	返回值： json string
	返回JSON结构:
	{
	"local_time" : "1430186039",
	"local_time_str" : "2015-04-28 09:53:59",
	"msg" : "与网络时间同步",
	"net_time" : "1430186041",
	"net_time_str" : "2015-04-28 09:54:01",
	"sec_level" : 0,
	"success" : 1
	}
*/
string WTF_GetTime();



/*
	函数功能：获取所有设备
	描述：返回设备名和设备信息
	返回值： json string
	返回JSON结构:
	[
	{
	"AlgAsymCap" : 67108864,
	"AlgHashCap" : 458755,
	"AlgSymCap" : 421462016,
	"DevAuthAlgId" : 16842752,
	"FirmwareVersionMajor" : 49,
	"FirmwareVersionMinor" : 48,
	"FreeSpace" : 2424832,
	"HWVersionMajor" : 49,
	"HWVersionMinor" : 48,
	"Issuer" : "CMBC",
	"Label" : "CMBC",
	"Manufacturer" : "HB",
	"SerialNumber" : "5330000238036648",
	"TotalSpace" : 3604480,
	"VersionMajor" : 49,
	"VersionMinor" : 48,
	"devNickName" : "0305549100001236",
	"manufacturer" : "恒宝股份"
	}
	]
*/
string WTF_GetAllDevs();

/*
	函数功能：获取设备信息和所有证书以及其信息
	描述：返回值包含一个certContentB64String项， 这个用来保存证书内容为结构SK_CERT_CONTENT的Base64编码
	输入参数：
		pszDevName 设备名称（实际是SM2签名证书使用者CN），为空则表示枚举所有的设备和证书
	返回值： json string 
	返回JSON结构:
	[
	{
	"algAsymCap" : 67108864,
	"algHashCap" : 458755,
	"algSymCap" : 421462016,
	"certs" : [
	{
	"applicationName" : "HB_CMBC",
	"certContentB64String" : "",
	"commonName" : "0305549100001236",
	"containerName" : "{1D0CCA19-3C74-4F75-9E7D-BF41E643DE73}",
	"deviceName" : "\\\\?\\usbstor#cdrom&ven_hengbao&prod_uranusafe_key&rev_1.00#6&489da4d&0#{53f56308-b6bf-11d0-94f2-00a0c91efb8b}01",
	"issuer" : "O=CFCA RSA TEST OCA21",
	"notAfter" : "2017-02-18 15:19:41",
	"notBefore" : "2016-08-18 15:19:41",
	"serialNumber" : "30 01 71 20 85 ",
	"signType" : 0,
	"skfName" : "hbcmbc",
	"subject" : "CN=0305549100001236",
	"type" : 1,
	"verify" : 0
	},
	{
	"applicationName" : "HB_CMBC",
	"certContentB64String" : "",
	"commonName" : "0305549100001236",
	"containerName" : "{737D07AB-8C97-4733-94D4-A6B0B613A447}",
	"deviceName" : "\\\\?\\usbstor#cdrom&ven_hengbao&prod_uranusafe_key&rev_1.00#6&489da4d&0#{53f56308-b6bf-11d0-94f2-00a0c91efb8b}01",
	"issuer" : "O=CFCA SM2 TEST OCA21",
	"notAfter" : "2017-02-18 15:19:41",
	"notBefore" : "2016-08-18 15:19:41",
	"serialNumber" : "30 01 71 20 86 ",
	"signType" : 1,
	"skfName" : "hbcmbc",
	"subject" : "CN=0305549100001236",
	"type" : 2,
	"verify" : 0
	},
	{
	"applicationName" : "HB_CMBC",
	"certContentB64String" : "",
	"commonName" : "0305549100001236",
	"containerName" : "{737D07AB-8C97-4733-94D4-A6B0B613A447}",
	"deviceName" : "\\\\?\\usbstor#cdrom&ven_hengbao&prod_uranusafe_key&rev_1.00#6&489da4d&0#{53f56308-b6bf-11d0-94f2-00a0c91efb8b}01",
	"issuer" : "O=CFCA SM2 TEST OCA21",
	"notAfter" : "2017-02-18 15:19:41",
	"notBefore" : "2016-08-18 15:19:41",
	"serialNumber" : "30 01 71 20 87 ",
	"signType" : 0,
	"skfName" : "hbcmbc",
	"subject" : "CN=0305549100001236",
	"type" : 2,
	"verify" : 0
	}
	],
	"devAuthAlgId" : 16842752,
	"devNickName" : "0305549100001236",
	"firmwareVersionMajor" : 49,
	"firmwareVersionMinor" : 48,
	"freeSpace" : 2424832,
	"hwVersionMajor" : 49,
	"hwVersionMinor" : 48,
	"issuer" : "CMBC",
	"label" : "CMBC",
	"manufacturer" : "HB",
	"serialNumber" : "5330000238036648",
	"totalSpace" : 3604480,
	"versionMajor" : 49,
	"versionMinor" : 48
	}
	]
*/
string WTF_GetDevAllCerts(const char * pszDevName, int Expire);

/*
	函数功能：获取设备SM2签名证书
	描述：返回设备SM2签名证书 通过该设备SM2签名证书可以快速找到设备进行操作
	返回值： json string
	返回JSON结构:
	[
	{
	"AlgAsymCap" : 67108864,
	"AlgHashCap" : 458755,
	"AlgSymCap" : 421462016,
	"DevAuthAlgId" : 16842752,
	"FirmwareVersionMajor" : 49,
	"FirmwareVersionMinor" : 48,
	"FreeSpace" : 2424832,
	"HWVersionMajor" : 49,
	"HWVersionMinor" : 48,
	"Issuer" : "CMBC",
	"Label" : "CMBC",
	"Manufacturer" : "HB",
	"SerialNumber" : "5330000238036648",
	"TotalSpace" : 3604480,
	"VersionMajor" : 49,
	"VersionMinor" : 48,
	"certContentB64String" : "",
	"devNickName" : "0305549100001236",
	"expiration_status" : 0,
	"expire_msg" : "证书有效！",
	"manufacturer" : "恒宝股份"
	}
	]
	仅SM2
*/
string WTF_GetDevSignCert(const char * pszDevName);

/*
	函数功能：修改设备密码
	输入参数：
		strDevName 设备名称（实际是SM2签名证书使用者CN）
		strOldPassword 原始密码
		strNewPassword 新密码
	返回值： json string 
	返回JSON结构:
	{
	"msg" : "修改密码成功！",
	"retryCount" : 6,
	"success" : 1
	}
*/
string WTF_ChangeDevPassword(const string strDevName,const string strOldPassword, const string strNewPassword);

/*
	函数功能：修改设备密码通过设备B64串
	输入参数：
		strSignCertPropB64 签名证书属性结构体SK_CERT_DESC_PROPERTY的B64串
		strOldPassword 原始密码
		strNewPassword 新密码
		返回值： json string 
	描述：strSignCertPropB64为结构SK_CERT_DESC_PROPERTY的Base64编码, 通过该属性可以快速找到设备进行操作
	返回JSON结构:
	{
	"msg" : "修改密码成功！",
	"retryCount" : 6,
	"success" : 1
	}
*/
string WTF_ChangeDevPasswordBySignCertPropB64(const string strSignCertPropB64,const string strOldPassword, const string strNewPassword);


/*
	函数功能：验证设备密码
	输入参数：
		strDevName 设备名称（实际是SM2签名证书使用者CN）
		strPassword 密码

	返回值： json string 
	返回JSON结构:
	{
	"msg" : "验证密码成功！",
	"retryCount" : 6,
	"success" : 1
	}
*/
string WTF_VerifyDevPassword(const string strDevName,const string strPassword);

/*
	函数功能：验证设备密码通过设备B64串
	输入参数：
		strSignCertPropB64 签名证书属性结构体SK_CERT_DESC_PROPERTY的B64串
		strPassword 密码
	描述：strSignCertPropB64为结构SK_CERT_DESC_PROPERTY的Base64编码, 通过该属性可以快速找到设备进行操作
	返回值： json string 
	返回JSON结构:
	{
	"msg" : "验证密码成功！",
	"retryCount" : 6,
	"success" : 1
	}
*/
string WTF_VerifyDevPasswordBySignCertPropB64(const string strSignCertPropB64,const string strPassword);

/*
	函数功能：显示证书UI
	输入参数：
		strCertContentB64 证书内容结构体SK_CERT_CONTENTB64串
	返回值： json string 
	描述：该接口为显示证书UI返回值无意义
	返回JSON结构:
	{
	"msg" : "",
	"success" : 1
	}

*/
string WTF_ShowCert(const string strCertContentB64);

/*
	函数功能：获取信任站点
	输入参数：
		bTrust  是否信任
	返回值： json string 
	返回JSON结构:
	{
	"sec_level" : 0,
	"success" : 1,
	"url" : "www.hao123.com"
	}

*/
string WTF_GetTrustUrl(bool bTrust);

/*
	函数功能：设置信任(不信任)站点
	输入参数：
		str_site 网址
		bTrust  是否信任
	返回值： json string 
	返回JSON结构:
	{
	"sec_level" : 0,
	"success" : 1,
	"url" : "www.hao123.com"
	}
*/
string WTF_SetTrustUrl(string str_site, bool bTrust);

/*
	函数功能：获取默认浏览器
	返回值： json string 
	说明： 未提供
*/
string WTF_GetDefaultBrowser();

/*
	函数功能：获取系统信息
	返回值： json string 
	返回JSON结构:
	{
	"sec_level" : 0,
	"success" : 1,
	"sysinfo" : "Microsoft Windows 7 Ultimate EditionService Pack 1 (build 7601),
	64-bit"
	}
*/
string WTF_GetSystemInfo();

/*
	函数功能：获取链接状态
	
	输入参数:
		strWebSite 网址
		strSubDetail 子网址
		nPort 端口
	https://per.cmbc.com.cn/pweb/static/login.html 对应 "per.cmbc.com.cn","pweb/static/login.html", 443
	返回值： json string 
	返回JSON结构:
	{
	"sec_level" : 0,
	"success" : 1,
	"url" : "per.cmbc.com.cn"
	}

*/
string WTF_CheckWebSite(string strWebSite, string strSubDetail, int nPort, unsigned int uiTimeOutSecond);


/*
	函数功能：检测系统未安装的更新
	返回值： json string 

	返回JSON结构:
	{
	"items" : [
	{
	"bstrDescription" : "安装本语言包之后，您可以将 Windows 7 的显示语言更改为拉脱维亚语。请在“控制面板”中转至“时钟、语言和区域”类别，以更改显示语言。",
	"bstrUId" : "4f9af231-5723-4a52-9293-015d4e5d4cdf",
	"bstrUpdateName" : "拉脱维亚语语言包 - 适用于 x64 系统的 Windows 7 Service Pack 1 (KB2483139)",
	"ossDate" : "Tuesday, February 22, 2011",
	"ossKBArticleIDs" : "个数1<br/>更新包情况：KB2483139 ",
	"priority" : 1
	},
	省略部分...
	{
	"bstrDescription" : "Install this update to revise the definition files used to detect spyware and other potentially unwanted software. Once you have installed this item, it cannot be removed.",
	"bstrUId" : "d05153cf-26ea-45ea-8907-eb226297aace",
	"bstrUpdateName" : "Definition Update for Windows Defender - KB915597 (Definition 1.197.474.0)",
	"ossDate" : "Friday, April 24, 2015",
	"ossKBArticleIDs" : "个数1<br/>更新包情况：KB915597 ",
	"priority" : 2
	}
	],
	"msg" : "Searching finished!"
	}
*/
string WTF_CheckSystemUpdateState();


/*
	函数功能：检测证书链（根证，二级证书）
	输入参数：
		strRootCertKeyIDHex 证书使用者密钥标示
		ulFlag WTF_CERT_VERIFY_FLAG
		ulAlgType  WTF_CERT_ALG_FLAG
	返回值： json string 

	返回JSON结构:
	{
	"chain_root_state" : "success",
	"sec_level" : 0,
	"success" : 1
	}
*/
string WTF_CheckCertChain(list<string> strListRootCertKeyIDHex, unsigned int ulFlag,unsigned int ulAlgType);


/*
	函数功能：host文件检查
	输入参数：strURL URL地址 例：www.baidu.com mail.google.com etc.
	返回值： json string 

	返回JSON结构:
	 {
	 "ip" : "173.194.210.17",
	 "sec_level" : 0,
	 "success" : 1,
	 "url" : "mail.google.com"
	 }
*/
string WTF_CheckHostFile(string strURL);

/*
	函数功能：获取网络上更新文件的版本
	输入参数：
		strObjItem 项
		strSite   网址
		strSub	  子网
		nPort	端口
	返回值： json string 

	返回JSON结构:
	{
	"msg" : "{\"idtest\":\"1\",\"file_name\":\"1\",\"file_version\":\"1.1.1.1\"}{
	\"idtest\":\"2\",\"file_name\":\"2\",\"file_version\":\"2.2.2.2\"}",
	"sec_level" : 0,
	"success" : 1
	}
*/
string WTF_GetWebFileVersion(string strObjItem,string strSite, string strSub, int nPort);

/*
	函数功能：获取文件版本
	输入参数：
		strPath 本地文件路径
	返回值： json string 
	返回JSON结构:
	{
	"version" : "1.0.0.1"
	}
*/
string WTF_GetLocalFileVersion(string strPath);

/*
	函数功能：获取SKF驱动状态
	输入参数：
		strSKFList SKF名称列表
	返回值： json string 
	返回JSON结构:
	[
	{
	"skf_name" : "hbcmbc",
	"skf_state" : 1,
	"skf_version" : "1.0.0.3"
	},
	省略部分
	{
	"skf_name" : "CMBC",
	"skf_state" : 0,
	"skf_version" : ""
	}
	]
*/
string WTF_ListSKFDriver(list<string> strSKFList);

/*
函数功能：获取CSP驱动状态
输入参数：
strCSPList CSP名称列表
返回值： json string
返回JSON结构:
[
{
"csp_name" : "hbcmbc",
"csp_state" : 1
},
省略部分
{
"csp_name" : "CMBC",
"csp_state" : 0
}
]
*/
string WTF_ListCSPDriver(list<string> strCSPList);


/*
	函数功能：修复本地时间
	返回值： json string 
	返回JSON结构:
	{
	"msg" : "同步本地时间成功",
	"success" : true,
	"time" : "1430297546",
	"time_str" : "2015-04-29 16:52:26"
	}
*/
string WTF_RepairLocalTime();

/*
	函数功能：修复hosts文件
	描述：该接口可能对应项目有不同的实现， 所以保留了参数项目名称strProName， 目前传""
	输入参数：
		strProName 项目名称
		strKey 关键字(目前民生银行项目代表IP地址)
	返回值： json string 
	返回JSON结构:
	{

	}
*/
string WTF_RepairHostFile(string strProName, string strKey);

/*
	函数功能：安装应用程序
	输入参数：
		strAppPath 安装包路径
		nTimeoutMilliseconds 超时时间
	返回值： json string 
	返回JSON结构:
	{
	"application_path" : "D:\\XXX.exe",
	"success" : true,
	"timeoutMilliseconds" : 20000
	}
*/
string WTF_InstallApp(string strAppPath, string strArgs, unsigned int nTimeoutMilliseconds, int ulFlag);


/*
	函数功能：运行应用程序
	输入参数：
		strAppPath 引用程序路径
	返回值： json string 
	返回JSON结构:
	{
	"application_path" : "D:/x_commontools20170601.exe",
	"file_path" : "D:/x_commontools20170601.exe",
	"flag" : 1,
	"msg" : "应用程序启动成功",
	"success" : 1
	}
*/
string WTF_RunApplication(string strAppPath, string strArgs, int ulFlag);


/*
	函数功能：安装CA证书
	输入参数：
		strCaCertPath CA证书路径
	返回值： json string 
	返回JSON结构:
	{
	"success" : true,
	}
*/
string WTF_InstallCaCert(list<string> strCaCertPath, int ulFlag);


/*
函数功能：计算杂凑值
输入参数：
strProcessName 应用程序名称
返回值： json string 
返回JSON结构:
{
"application_path" : "D:/x_commontools20170601.exe",
"digest" : "8D92A64A7072566C969A249F31E62057",
"file_path" : "D:/x_commontools20170601.exe",
"success" : 1
}
*/
string WTF_CalculateDigest(string strAppPath, int ulNid);


/*
函数功能：通过文件信息校验所有CSP
输入参数：
返回值： json string
返回JSON结构:
{
"CMBC CSP V1.0" : {
"fileList" : [
{
"fileMD5Calculate" : "C56B381B3913A0DFFFF16FD5DEA253E1",
"fileMD5Record" : "C56B381B3913A0DFFFF16FD5DEA253E1",
"fileName" : "2",
"filePath" : "C:\\Program Files (x86)\\CMBC\\EBankingAssistant\\USBKey\\CMBC.dll",
"fileType" : "csp",
"success" : 1
},
{
"fileMD5Calculate" : "1F79428E0A8A130C8BD689651A47CC5E",
"fileMD5Record" : "1F79428E0A8A130C8BD689651A47CC5E",
"fileName" : "1",
"filePath" : "d:/show.cer",
"fileType" : "csp",
"success" : 1
}
],
"success" : 1
}
}
*/
string WTF_CheckCSPWithFileInfo();

/*
函数功能：校验CSP完整性
输入参数：
返回值： json string
返回JSON结构:
{
"cspName" : "CMBC CSP V1.0",
"fileList" : [
{
"fileMD5Calculate" : "C56B381B3913A0DFFFF16FD5DEA253E1",
"fileMD5Record" : "C56B381B3913A0DFFFF16FD5DEA253E1",
"fileName" : "2",
"filePath" : "C:\\Program Files (x86)\\CMBC\\EBankingAssistant\\USBKey\\CMBC.dll",
"fileType" : "csp",
"success" : 1
},
{
"fileMD5Calculate" : "1F79428E0A8A130C8BD689651A47CC5E",
"fileMD5Record" : "1F79428E0A8A130C8BD689651A47CC5E",
"fileName" : "1",
"filePath" : "d:/show.cer",
"fileType" : "csp",
"success" : 1
}
],
"success" : 1
}
*/
string WTF_CheckCSPItemWithFileInfo(string strCspName);

/*
函数功能：校验文件完整性MD5
输入参数：
返回值： json string
返回JSON结构:
{
"file_list1" : {
"fileList" : [
{
"fileMD5Calculate" : "C56B381B3913A0DFFFF16FD5DEA253E1",
"fileMD5Record" : "C56B381B3913A0DFFFF16FD5DEA253E1",
"fileName" : "3",
"filePath" : "C:\\Program Files (x86)\\CMBC\\EBankingAssistant\\USBKey\\CMBC.dll",
"fileType" : "file",
"success" : 1
},
{
"fileMD5Calculate" : "1F79428E0A8A130C8BD689651A47CC5E",
"fileMD5Record" : "1F79428E0A8A130C8BD689651A47CC5E",
"fileName" : "4",
"filePath" : "d:/show.cer",
"fileType" : "file",
"success" : 1
}
],
"success" : 1
}
}
*/
string WTF_CheckFileMd5();

/*
函数功能：读取UKey类型（莱商）
输入参数：
返回值： json string
返回JSON结构:
*/
string WTF_ReadUkeyType();

/*
函数功能：检测运行状态
输入参数：
strProcessName 应用程序名称
返回值： json string 
返回JSON结构:
{
"process_count" : 30,
"process_name" : "chrome",
"success" : 1
}
*/
string WTF_DetectProcessLikeRunState(string strProcessName, int ulType);


/*
函数功能：检测MAC地址
输入参数：
返回值： json string 
返回JSON结构:
{
"mac_address" : "1C1B0D2EA3F7 005056C00001 005056C00008 00E04C3C7C00 B0D59D56F5CE B2959D56F5CE ",
"msg" : "获取MAC地址成功",
"success" : 1
}
*/
string WTF_DetectMACAddress();

/*
函数功能：检测本地IP地址
输入参数：
返回值： json string 
返回JSON结构:
{
"ip_address" : "0.0.0.0 169.254.77.163 169.254.50.155 169.254.76.135 192.168.18.162 0.0.0.0 ",
"msg" : "获取IP地址成功",
"success" : 1
}
*/
string WTF_DetectLocalIPAddress();

/*
函数功能：检测网络IP地址
输入参数：
返回值： json string 
返回JSON结构:
{
"msg" : "异常错误，获取IP地址失败",
"success" : 0
}
*/
string WTF_DetectNetworkIPAddress();

#endif/*_EBANK_SYSTEM_DETECT_H*/