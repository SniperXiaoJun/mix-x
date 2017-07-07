#pragma once
#include "ForeDialogBase.h"
#include "explorer.h"
#include "afxwin.h"

// CDemoForeDialog dialog

class CDemoForeDialog : public CForeDialogBase
{
	DECLARE_DYNAMIC(CDemoForeDialog)

public:
	CDemoForeDialog(CWnd* pParent = NULL);   // standard constructor
	virtual ~CDemoForeDialog();

// Dialog Data
	enum { IDD = IDD_DEMO_FOREDIALOG };

protected:
    virtual BOOL OnInitDialog();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
    virtual void OnOK();

	DECLARE_MESSAGE_MAP()
public:
    afx_msg void OnBnClickedButtonExit();
    afx_msg void OnBnClickedButtonCtrlDemo();
    afx_msg void OnBnClickedButtonNavigate();
    
private:
    CString m_strURL;
    CEdit m_urlEdit;
    CExplorer m_WebBrowser;
};
