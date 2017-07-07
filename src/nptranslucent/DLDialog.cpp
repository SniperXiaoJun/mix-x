#include "DLDialog.h"
#include "stdafx.h"
#include "resource.h" 
#include "DemoBackDialog.h"
#include "DemoForeDialog.h"
#include "TranslucentDemo.h"

CTranslucentDemoApp theApp;

DLDialog::DLDialog():
	m_hDlg(NULL)
{
	 
}

DLDialog::~DLDialog()
{

}

bool DLDialog::Create(void* hWndParent)
{
	m_hWndParent = hWndParent;

	m_hDlg = new CDemoBackDialog(IDB_PNG_BACKIMAGE, CWnd::FromHandle((HWND)hWndParent));

	return m_hDlg !=NULL;
}

bool DLDialog::ShowWindowPos(int x, int y, int width, int height, int flag)
{
	bool res = false;
	
	res = CWnd::FromHandle((HWND)m_hWndParent)->ShowWindow(SW_SHOW);

	if (res)
	{
		MessageBoxA(NULL, "ShowWindow success", "info", 0);
	}
	else
	{
		MessageBoxA(NULL, "ShowWindow err", "info", 0);
	}

	res = CWnd::FromHandle((HWND)m_hWndParent)->SetWindowPos(NULL, 0, 0, width, height, flag);

	{
		char buffer_msg[1024];

		sprintf(buffer_msg,"errcode = %d",GetLastError());

		MessageBoxA(NULL, buffer_msg, "info", 0);
	}

	if (CWnd::FromHandle((HWND)m_hWndParent))
	{
		MessageBoxA(NULL, "CWnd::FromHandle((HWND)m_hWndParent) success", "info", 0);
	}
	else
	{
		MessageBoxA(NULL, "CWnd::FromHandle((HWND)m_hWndParent) err", "info", 0);
	}

	if (res)
	{
		MessageBoxA(NULL, "ShowWindowPos success","info",0);
	}
	else
	{
		MessageBoxA(NULL, "ShowWindowPos err", "info", 0);
	}

	return res;
}

