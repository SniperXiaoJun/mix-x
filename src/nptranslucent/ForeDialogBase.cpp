#include "StdAfx.h"
#include "ForeDialogBase.h"

IMPLEMENT_DYNAMIC(CForeDialogBase, CDialog)

BEGIN_MESSAGE_MAP(CForeDialogBase, CDialog)
    ON_WM_CTLCOLOR()
END_MESSAGE_MAP()

CForeDialogBase::CForeDialogBase(UINT nIDTemplate, CWnd* pParentWnd/* = NULL*/, COLORREF crKey/* = RGB(0, 255, 0)*/) : CDialog(nIDTemplate, pParentWnd)
{
    m_crKey = crKey;
}


CForeDialogBase::~CForeDialogBase(void)
{
}

void CForeDialogBase::ShowDialog()
{
    Create(m_lpszTemplateName, m_pParentWnd);

    AdjustRectByParent();
}

void CForeDialogBase::AdjustRectByParent()
{
    CRect rect;
    m_pParentWnd->GetWindowRect(&rect);
    ::SetWindowPos(m_hWnd, NULL, rect.left, rect.top, rect.Width(), rect.Height(), SWP_SHOWWINDOW);
}

BOOL CForeDialogBase::OnInitDialog()
{
    CDialog::OnInitDialog();

    ModifyStyle(WS_BORDER | WS_SIZEBOX | WS_DLGFRAME | DS_MODALFRAME, WS_POPUP);
    ModifyStyleEx(WS_EX_APPWINDOW | WS_EX_DLGMODALFRAME, WS_EX_LAYERED);

    ::SetLayeredWindowAttributes(m_hWnd, m_crKey, 0, LWA_COLORKEY); 

    return TRUE;
}

void CForeDialogBase::OnOK()
{
    CWnd* pParent = GetParent();
    if (pParent != NULL)
    {
        HWND hWnd = pParent->m_hWnd; 
        ::SendMessage(hWnd, WM_CLOSE, 0, 0); 
    }

    CDialog::OnOK();
}

void CForeDialogBase::OnCancel()
{
    CWnd* pParent = GetParent();
    if (pParent != NULL)
    {
        HWND hWnd = pParent->m_hWnd; 
        ::SendMessage(hWnd, WM_CLOSE, 0, 0); 
    }

    CDialog::OnCancel();
}

void CForeDialogBase::EndDialog(int nResult)
{
    CWnd* pParent = GetParent();
    if (pParent != NULL)
    {
        HWND hWnd = pParent->m_hWnd; 
        ::SendMessage(hWnd, WM_CLOSE, 0, 0); 
    }

    CDialog::EndDialog(nResult);
}

HBRUSH CForeDialogBase::OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor)
{
    if (nCtlColor == CTLCOLOR_DLG)
    {
        return CreateSolidBrush(m_crKey);
    }

    return CDialog::OnCtlColor(pDC, pWnd, nCtlColor);
}