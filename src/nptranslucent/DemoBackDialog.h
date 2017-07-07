#pragma once
#include "BackDialogBase.h"

// CDemoBackDialog dialog

class CDemoBackDialog : public CBackDialogBase
{
	DECLARE_DYNAMIC(CDemoBackDialog)

public:
	CDemoBackDialog(UINT nImgID, CWnd* pParent = NULL);   // standard constructor
	virtual ~CDemoBackDialog();

// Dialog Data
	enum { IDD = IDD_DEMO_BACKDIALOG };

    virtual CForeDialogBase* CreateForeDialog();

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
};
