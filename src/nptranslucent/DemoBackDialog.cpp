// DemoBackDialog.cpp : implementation file
//

#include "stdafx.h"
#include "resource.h" 
#include "DemoBackDialog.h"
#include "DemoForeDialog.h"


// CDemoBackDialog dialog

IMPLEMENT_DYNAMIC(CDemoBackDialog, CBackDialogBase)

CDemoBackDialog::CDemoBackDialog(UINT nImgID, CWnd* pParent /*=NULL*/)
	: CBackDialogBase(CDemoBackDialog::IDD, nImgID, pParent)
{

}

CDemoBackDialog::~CDemoBackDialog()
{
}

void CDemoBackDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CDemoBackDialog, CBackDialogBase)
END_MESSAGE_MAP()

CForeDialogBase* CDemoBackDialog::CreateForeDialog()
{
    return ::new CDemoForeDialog(this);
}

// CDemoBackDialog message handlers
