#pragma once

class DLDialog
{
public:
	void * m_hDlg;
	void * m_hWndParent;
public:
	DLDialog();
	~DLDialog();

	bool Create(void * hWndParent);
	bool DLDialog::ShowWindowPos(int x, int y, int width, int height, int flag);
	bool ShowDlg();
};

