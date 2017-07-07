// DemoForeDialog.cpp : implementation file
//

#include "stdafx.h"
#include "resource.h" 
#include "CtrlDemoForeDialog.h"


// CDemoForeDialog dialog

IMPLEMENT_DYNAMIC(CCtrlDemoForeDialog, CForeDialogBase)

CCtrlDemoForeDialog::CCtrlDemoForeDialog(CWnd* pParent /*=NULL*/)
	: CForeDialogBase(CCtrlDemoForeDialog::IDD, pParent)
{

}

CCtrlDemoForeDialog::~CCtrlDemoForeDialog()
{
}

void CCtrlDemoForeDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CCtrlDemoForeDialog, CForeDialogBase)
    ON_BN_CLICKED(IDC_BUTTON_EXIT, &CCtrlDemoForeDialog::OnBnClickedButtonExit)
END_MESSAGE_MAP()


// CDemoForeDialog message handlers


void CCtrlDemoForeDialog::OnBnClickedButtonExit()
{
    CForeDialogBase::OnCancel();
}
