#pragma once
#include "afxwin.h"

class CForeDialogBase : public CDialog
{
    DECLARE_DYNAMIC(CForeDialogBase)
    DECLARE_MESSAGE_MAP()
public:
    CForeDialogBase(UINT nIDTemplate, CWnd* pParentWnd = NULL, COLORREF crKey = RGB(0, 255, 0));
    virtual ~CForeDialogBase(void);

    void ShowDialog();
    void AdjustRectByParent();

protected:
    virtual BOOL OnInitDialog();
    virtual void OnOK();
    virtual void OnCancel();
    void EndDialog(int nResult);

    afx_msg HBRUSH OnCtlColor(CDC* pDC, CWnd* pWnd, UINT nCtlColor);

private:
    COLORREF m_crKey;
};