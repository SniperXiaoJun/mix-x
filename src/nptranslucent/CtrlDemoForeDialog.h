#pragma once
#include "ForeDialogBase.h"

// CDemoForeDialog dialog

class CCtrlDemoForeDialog : public CForeDialogBase
{
	DECLARE_DYNAMIC(CCtrlDemoForeDialog)

public:
	CCtrlDemoForeDialog(CWnd* pParent = NULL);   // standard constructor
	virtual ~CCtrlDemoForeDialog();

// Dialog Data
	enum { IDD = IDD_CTRLDEMO_FOREDIALOG };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
    afx_msg void OnBnClickedButtonExit();
};
