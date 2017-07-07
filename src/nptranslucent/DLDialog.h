#pragma once
#include <windows.h>
#include <windowsx.h>
#include "resource.h"

class DLDialog
{
public:
	HWND hWnd;

public:
	DLDialog();
	~DLDialog();

	bool Create(HINSTANCE hInstance,LPCTSTR lpTemplate,HWND hWndParent);
	bool ShowDlg();

	char * GetVal();
};

