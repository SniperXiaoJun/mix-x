// DemoBackDialog.cpp : implementation file
//

#include "stdafx.h"
#include "resource.h" 
#include "CtrlDemoBackDialog.h"
#include "CtrlDemoForeDialog.h"


// CDemoBackDialog dialog

IMPLEMENT_DYNAMIC(CCtrlDemoBackDialog, CBackDialogBase)

CCtrlDemoBackDialog::CCtrlDemoBackDialog(UINT nImgID, CWnd* pParent /*=NULL*/)
	: CBackDialogBase(CCtrlDemoBackDialog::IDD, nImgID, pParent)
{

}

CCtrlDemoBackDialog::~CCtrlDemoBackDialog()
{
}

void CCtrlDemoBackDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CCtrlDemoBackDialog, CBackDialogBase)
END_MESSAGE_MAP()

CForeDialogBase* CCtrlDemoBackDialog::CreateForeDialog()
{
    return ::new CCtrlDemoForeDialog(this);
}

// CDemoBackDialog message handlers
