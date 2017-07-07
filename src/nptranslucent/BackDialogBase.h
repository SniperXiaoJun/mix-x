#pragma once
#include "afxwin.h"
#include "ForeDialogBase.h"

class CBackDialogBase : public CDialog
{
    DECLARE_DYNAMIC(CBackDialogBase)
    DECLARE_MESSAGE_MAP()

public:
    CBackDialogBase(UINT nIDTemplate, UINT nImgID, CWnd* pParent = NULL);
    virtual ~CBackDialogBase();

    virtual CForeDialogBase* CreateForeDialog() = 0;
    void UpdateView();

protected:

    virtual BOOL OnInitDialog();
    afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
    afx_msg BOOL OnEraseBkgnd(CDC* pDC);
    afx_msg void OnMove(int x, int y);
    afx_msg void OnSize(UINT nType, int cx, int cy);
    afx_msg void OnLButtonDown(UINT nFlags, CPoint point);

private:
    Gdiplus::Image* m_pImage;
    CForeDialogBase* m_pForeDialog;
};
