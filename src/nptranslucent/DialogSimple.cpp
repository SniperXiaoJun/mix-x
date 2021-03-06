// DialogSimple.cpp : 实现文件
//

#include "stdafx.h"
#include "resource.h" 
#include "DialogSimple.h"
#include "afxdialogex.h"


// CDialogSimple 对话框

IMPLEMENT_DYNAMIC(CDialogSimple, CDialogEx)

CDialogSimple::CDialogSimple(CWnd* pParent /*=NULL*/)
	: CDialogEx(CDialogSimple::IDD, pParent)
{

}

CDialogSimple::~CDialogSimple()
{
}

void CDialogSimple::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(CDialogSimple, CDialogEx)
	ON_BN_CLICKED(IDOK, &CDialogSimple::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CDialogSimple::OnBnClickedCancel)
END_MESSAGE_MAP()


// CDialogSimple 消息处理程序


void CDialogSimple::OnBnClickedOk()
{
	m_pDlg = new CDemoBackDialog(IDB_PNG_BACKIMAGE);
	m_pDlg->DoModal();
	delete m_pDlg;
}


void CDialogSimple::OnBnClickedCancel()
{
	m_pDlg = new CDemoBackDialog(IDB_PNG_BACKIMAGE);
	m_pDlg->DoModal();
	delete m_pDlg;
}
