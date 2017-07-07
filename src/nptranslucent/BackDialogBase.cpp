#include "StdAfx.h"
#include "resource.h"
#include "BackDialogBase.h"

IMPLEMENT_DYNAMIC(CBackDialogBase, CDialog)

BEGIN_MESSAGE_MAP(CBackDialogBase, CDialog)
    ON_WM_ERASEBKGND()
    ON_WM_MOVE()
    ON_WM_SIZE()
    ON_WM_CREATE()
    ON_WM_LBUTTONDOWN()
END_MESSAGE_MAP()

CBackDialogBase::CBackDialogBase(UINT nIDTemplate, UINT nImgID, CWnd* pParent /*=NULL*/)
    : CDialog(nIDTemplate, pParent)
    , m_pForeDialog(NULL)
{
    HMODULE hInstance = (HMODULE)::AfxGetResourceHandle();
    HRSRC hRsrc = ::FindResource(hInstance, MAKEINTRESOURCE(nImgID), _T("PNG")); 
    ATLASSERT(hRsrc != NULL);

    DWORD dwSize = ::SizeofResource(hInstance, hRsrc);
    LPBYTE lpRsrc = (LPBYTE)::LoadResource(hInstance, hRsrc);
    ATLASSERT(lpRsrc != NULL);

    HGLOBAL hMem = ::GlobalAlloc(GMEM_FIXED, dwSize);
    LPBYTE pMem = (LPBYTE)::GlobalLock(hMem);
    memcpy(pMem, lpRsrc, dwSize);
    IStream* pStream = NULL;
    ::CreateStreamOnHGlobal( hMem, FALSE, &pStream);

    m_pImage = Gdiplus::Image::FromStream(pStream);

    ::GlobalUnlock(hMem);
    pStream->Release();
    ::FreeResource(lpRsrc);
}

CBackDialogBase::~CBackDialogBase()
{
    if (m_pForeDialog != NULL)
    {
        ::delete m_pForeDialog;
        m_pForeDialog = NULL;
    }

    if (m_pImage != NULL)
    {
        delete m_pImage;
        m_pImage = NULL;
    }
}

BOOL CBackDialogBase::OnInitDialog()
{
    CDialog::OnInitDialog();

    ModifyStyle(WS_CAPTION | WS_CHILD, WS_POPUP);
    ModifyStyleEx(0, WS_EX_LAYERED | WS_OVERLAPPED);

    ::SetWindowPos(m_pForeDialog->GetSafeHwnd(), NULL, 0, 0, m_pImage->GetWidth(), m_pImage->GetHeight(), SWP_NOZORDER | SWP_NOMOVE);
    CenterWindow();

    UpdateView();

    return TRUE;
}

BOOL CBackDialogBase::OnEraseBkgnd(CDC* pDC)
{
    return TRUE;
}

void CBackDialogBase::OnMove(int x, int y)
{
    CDialog::OnMove(x, y);

    if (m_pForeDialog != NULL)
    {
        m_pForeDialog->AdjustRectByParent();

    }
}

void CBackDialogBase::OnSize(UINT nType, int cx, int cy)
{
    CDialog::OnSize(nType, cx, cy);

    if (m_pForeDialog != NULL)
    {
        m_pForeDialog->AdjustRectByParent();
    }
}

int CBackDialogBase::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
    if (CDialog::OnCreate(lpCreateStruct) == -1)
    {
        return -1;
    }

    m_pForeDialog = CreateForeDialog();
    if (m_pForeDialog != NULL)
    {
        m_pForeDialog->ShowDialog();
    }

    return 0;
}

void CBackDialogBase::UpdateView()
{
    HDC hDC = ::GetDC(m_hWnd);
    HDC hdcMemory = CreateCompatibleDC(hDC);

    SIZE sizeWindow = {m_pImage->GetWidth(), m_pImage->GetHeight()};
    HBITMAP hBitMap = CreateCompatibleBitmap(hDC, sizeWindow.cx, sizeWindow.cy);
    ::SelectObject(hdcMemory, hBitMap);

    BITMAPINFOHEADER stBmpInfoHeader = { 0 };   
    int nBytesPerLine = ((sizeWindow.cx * 32 + 31) & (~31)) >> 3;
    stBmpInfoHeader.biSize = sizeof(BITMAPINFOHEADER);   
    stBmpInfoHeader.biWidth = sizeWindow.cx;   
    stBmpInfoHeader.biHeight = sizeWindow.cy;   
    stBmpInfoHeader.biPlanes = 1;   
    stBmpInfoHeader.biBitCount = 32;   
    stBmpInfoHeader.biCompression = BI_RGB;   
    stBmpInfoHeader.biClrUsed = 0;   
    stBmpInfoHeader.biSizeImage = nBytesPerLine * sizeWindow.cy;   

    PVOID pvBits = NULL;   
    HBITMAP hbmpMem = ::CreateDIBSection(NULL, (PBITMAPINFO)&stBmpInfoHeader, DIB_RGB_COLORS, &pvBits, NULL, 0);
    if (hbmpMem == NULL)
    {
        ::DeleteDC(hdcMemory);
        ::ReleaseDC(m_hWnd, hDC);

        return;
    }
    memset( pvBits, 0, sizeWindow.cx * 4 * sizeWindow.cy);

    HGDIOBJ hbmpOld = ::SelectObject( hdcMemory, hbmpMem);

    Gdiplus::Graphics graph(hdcMemory);
    graph.SetSmoothingMode(Gdiplus::SmoothingModeNone);
    graph.DrawImage(m_pImage, 0, 0, sizeWindow.cx, sizeWindow.cy);

    RECT rcWindow;
    GetWindowRect(&rcWindow);
    POINT ptWinPos = {rcWindow.left, rcWindow.top};
    POINT ptSrc = { 0, 0};
    BLENDFUNCTION stBlend = {AC_SRC_OVER, 0, 255, AC_SRC_ALPHA};
    ::UpdateLayeredWindow(m_hWnd, hDC, &ptWinPos, &sizeWindow, hdcMemory, &ptSrc, 0, &stBlend, ULW_ALPHA);
    CDC dc;

    graph.ReleaseHDC(hdcMemory);
    ::SelectObject( hdcMemory, hbmpOld);
    ::DeleteObject(hbmpMem); 

    ::DeleteDC(hdcMemory);
    ::ReleaseDC(m_hWnd, hDC);
}

void CBackDialogBase::OnLButtonDown(UINT nFlags, CPoint point)
{
    ::SendMessage( GetSafeHwnd(), WM_SYSCOMMAND, SC_MOVE | HTCAPTION, 0);

    CDialog::OnLButtonDown(nFlags, point);
}