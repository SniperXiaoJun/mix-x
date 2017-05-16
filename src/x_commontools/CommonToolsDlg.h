
// APITest_CommonToolsDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"


// CommonToolsDlg 对话框
class CommonToolsDlg : public CDialogEx
{
// 构造
public:
	CommonToolsDlg(CWnd* pParent = NULL);	// 标准构造函数

	~CommonToolsDlg();

// 对话框数据
	enum { IDD = IDD_VS2015_COMMONTOOLS_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CTabCtrl m_tb;
	afx_msg void OnTcnSelchangeTabAll(NMHDR *pNMHDR, LRESULT *pResult);

	int m_CurSelTab;
	CDialog * pDialog[14];
	int pos;

	CDialog m_page1;
	CDialog m_page2;
	CDialog m_page3;
	afx_msg void OnCbnSelchangeCombo1();
	afx_msg void OnCbnSelchangeCombotype();
	CComboBox comboBoxHashAlgType;
	afx_msg void OnCbnSelchangeCombotype2();
	CComboBox comboBoxKeyAlgType;
};
