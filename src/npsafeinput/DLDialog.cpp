#include "DLDialog.h"



DLDialog::DLDialog():
	hWnd(NULL)
{
}


DLDialog::~DLDialog()
{
}

INT_PTR CALLBACK DlgProc(HWND hDlg,UINT message,WPARAM wParam,LPARAM lParam)
{
	switch(message)
	{
	case WM_SIZE:
		{
			RECT rc;
			GetClientRect(hDlg,&rc);
			HWND pitem=GetDlgItem(hDlg,IDC_INPUT);
			SetWindowPos(pitem,HWND_TOPMOST,0,0,rc.right,rc.bottom,SWP_NOZORDER|SWP_NOMOVE);
		}
		break;
	}
	return false;
}

bool DLDialog::Create(HINSTANCE hInstance,LPCTSTR lpTemplate,HWND hWndParent)
{
	hWnd=CreateDialog(hInstance,lpTemplate,hWndParent,(DLGPROC)DlgProc);
	return hWnd!=NULL;
}

bool DLDialog::ShowDlg()
{
	return ShowWindow(hWnd,SW_SHOW);
}

char * DLDialog::GetVal()
{
	HWND edit=::GetDlgItem(hWnd,IDC_INPUT);
	static char str[255];
	GetWindowTextA(edit,str,255);
	return str;
}
