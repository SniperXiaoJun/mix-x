
// APITest_CommonTools.cpp : ¶¨ÒåÓ¦ÓÃ³ÌÐòµÄÀàÐÐÎª¡£
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlg.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CommonToolsApp

BEGIN_MESSAGE_MAP(CommonToolsApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CommonToolsApp ¹¹Ôì

CommonToolsApp::CommonToolsApp()
{
	// Ö§³ÖÖØÐÂÆô¶¯¹ÜÀíÆ÷
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;

	// TODO: ÔÚ´Ë´¦Ìí¼Ó¹¹Ôì´úÂë£¬
	// ½«ËùÓÐÖØÒªµÄ³õÊ¼»¯·ÅÖÃÔÚ InitInstance ÖÐ
}


// Î¨Ò»µÄÒ»¸ö CommonToolsApp ¶ÔÏó

CommonToolsApp theApp;


// CommonToolsApp ³õÊ¼»¯

BOOL CommonToolsApp::InitInstance()
{
	// Èç¹ûÒ»¸öÔËÐÐÔÚ Windows XP ÉÏµÄÓ¦ÓÃ³ÌÐòÇåµ¥Ö¸¶¨Òª
	// Ê¹ÓÃ ComCtl32.dll °æ±¾ 6 »ò¸ü¸ß°æ±¾À´ÆôÓÃ¿ÉÊÓ»¯·½Ê½£¬
	//ÔòÐèÒª InitCommonControlsEx()¡£·ñÔò£¬½«ÎÞ·¨´´½¨´°¿Ú¡£
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// ½«ËüÉèÖÃÎª°üÀ¨ËùÓÐÒªÔÚÓ¦ÓÃ³ÌÐòÖÐÊ¹ÓÃµÄ
	// ¹«¹²¿Ø¼þÀà¡£
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();


	AfxEnableControlContainer();

	// ´´½¨ shell ¹ÜÀíÆ÷£¬ÒÔ·À¶Ô»°¿ò°üº¬
	// ÈÎºÎ shell Ê÷ÊÓÍ¼¿Ø¼þ»ò shell ÁÐ±íÊÓÍ¼¿Ø¼þ¡£
	CShellManager *pShellManager = new CShellManager;

	// ±ê×¼³õÊ¼»¯
	// Èç¹ûÎ´Ê¹ÓÃÕâÐ©¹¦ÄÜ²¢Ï£Íû¼õÐ¡
	// ×îÖÕ¿ÉÖ´ÐÐÎÄ¼þµÄ´óÐ¡£¬ÔòÓ¦ÒÆ³ýÏÂÁÐ
	// ²»ÐèÒªµÄÌØ¶¨³õÊ¼»¯Àý³Ì
	// ¸ü¸ÄÓÃÓÚ´æ´¢ÉèÖÃµÄ×¢²á±íÏî
	// TODO: Ó¦ÊÊµ±ÐÞ¸Ä¸Ã×Ö·û´®£¬
	// ÀýÈçÐÞ¸ÄÎª¹«Ë¾»ò×éÖ¯Ãû
	SetRegistryKey(_T("Ó¦ÓÃ³ÌÐòÏòµ¼Éú³ÉµÄ±¾µØÓ¦ÓÃ³ÌÐò"));

	CommonToolsDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: ÔÚ´Ë·ÅÖÃ´¦ÀíºÎÊ±ÓÃ
		//  ¡°È·¶¨¡±À´¹Ø±Õ¶Ô»°¿òµÄ´úÂë
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: ÔÚ´Ë·ÅÖÃ´¦ÀíºÎÊ±ÓÃ
		//  ¡°È¡Ïû¡±À´¹Ø±Õ¶Ô»°¿òµÄ´úÂë
	}

	// É¾³ýÉÏÃæ´´½¨µÄ shell ¹ÜÀíÆ÷¡£
	if (pShellManager != NULL)
	{
		delete pShellManager;
	}

	// ÓÉÓÚ¶Ô»°¿òÒÑ¹Ø±Õ£¬ËùÒÔ½«·µ»Ø FALSE ÒÔ±ãÍË³öÓ¦ÓÃ³ÌÐò£¬
	//  ¶ø²»ÊÇÆô¶¯Ó¦ÓÃ³ÌÐòµÄÏûÏ¢±Ã¡£
	return FALSE;
}

/*
* 当libjpeg-turbo为vs2010编译时，vs2015下静态链接libjpeg-turbo会链接出错:找不到__iob_func,
* 增加__iob_func到__acrt_iob_func的转换函数解决此问题,
* 当libjpeg-turbo用vs2015编译时，不需要此补丁文件
*/
#if _MSC_VER>=1900
#include "stdio.h" 
_ACRTIMP_ALT FILE* __cdecl __acrt_iob_func(unsigned);
#ifdef __cplusplus 
extern "C"
#endif 
FILE* __cdecl __iob_func(unsigned i) {
	return __acrt_iob_func(i);
}
#endif /* _MSC_VER>=1900 */
