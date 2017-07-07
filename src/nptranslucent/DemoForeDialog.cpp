// DemoForeDialog.cpp : implementation file
//

#include "stdafx.h"
#include "resource.h" 
#include "DemoForeDialog.h"
#include "afxdialogex.h"
#include "CtrlDemoBackDialog.h"


// CDemoForeDialog dialog

IMPLEMENT_DYNAMIC(CDemoForeDialog, CForeDialogBase)

CDemoForeDialog::CDemoForeDialog(CWnd* pParent /*=NULL*/)
	: CForeDialogBase(CDemoForeDialog::IDD, pParent)
    , m_strURL(_T(""))
{

}

CDemoForeDialog::~CDemoForeDialog()
{
}

BOOL CDemoForeDialog::OnInitDialog()
{
    CForeDialogBase::OnInitDialog();

    m_strURL = _T("www.baidu.com");
    UpdateData(FALSE);
    m_WebBrowser.Navigate(m_strURL, NULL, NULL, NULL, NULL);

    return TRUE;
}

void CDemoForeDialog::DoDataExchange(CDataExchange* pDX)
{
    CDialog::DoDataExchange(pDX);
    DDX_Text(pDX, IDC_EDIT_URL, m_strURL);
    DDX_Control(pDX, IDC_EXPLORER, m_WebBrowser);
    DDX_Control(pDX, IDC_EDIT_URL, m_urlEdit);
}


BEGIN_MESSAGE_MAP(CDemoForeDialog, CForeDialogBase)
    ON_BN_CLICKED(IDC_BUTTON_EXIT, &CDemoForeDialog::OnBnClickedButtonExit)
    ON_BN_CLICKED(IDC_BUTTON_CTRLDEMO, &CDemoForeDialog::OnBnClickedButtonCtrlDemo)
    ON_BN_CLICKED(IDC_BUTTON_NAVIGATE, &CDemoForeDialog::OnBnClickedButtonNavigate)
END_MESSAGE_MAP()


// CDemoForeDialog message handlers


void CDemoForeDialog::OnBnClickedButtonExit()
{
    CForeDialogBase::OnCancel();
}


void CDemoForeDialog::OnBnClickedButtonCtrlDemo()
{
    CCtrlDemoBackDialog dlg(IDB_PNG_CTRLDEMO);

    INT_PTR nResponse = dlg.DoModal();
    if (nResponse == IDOK)
    {
        // TODO: Place code here to handle when the dialog is
        //  dismissed with OK
    }
    else if (nResponse == IDCANCEL)
    {
        // TODO: Place code here to handle when the dialog is
        //  dismissed with Cancel
    }
}


void CDemoForeDialog::OnBnClickedButtonNavigate()
{
    UpdateData(TRUE);
    m_WebBrowser.Navigate(m_strURL, NULL, NULL, NULL, NULL);
}

void CDemoForeDialog::OnOK()
{
    if (GetFocus() == &m_urlEdit)
    {
        UpdateData(TRUE);
        m_WebBrowser.Navigate(m_strURL, NULL, NULL, NULL, NULL);
    }
}
