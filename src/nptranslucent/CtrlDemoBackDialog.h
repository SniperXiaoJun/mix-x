#pragma once
#include "BackDialogBase.h"

// CDemoBackDialog dialog

class CCtrlDemoBackDialog : public CBackDialogBase
{
	DECLARE_DYNAMIC(CCtrlDemoBackDialog)

public:
	CCtrlDemoBackDialog(UINT nImgID, CWnd* pParent = NULL);   // standard constructor
	virtual ~CCtrlDemoBackDialog();

// Dialog Data
	enum { IDD = IDD_CTRLDEMO_BACKDIALOG };

    virtual CForeDialogBase* CreateForeDialog();

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
};
