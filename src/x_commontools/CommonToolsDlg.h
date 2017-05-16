
// APITest_CommonToolsDlg.h : ͷ�ļ�
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"


// CommonToolsDlg �Ի���
class CommonToolsDlg : public CDialogEx
{
// ����
public:
	CommonToolsDlg(CWnd* pParent = NULL);	// ��׼���캯��

	~CommonToolsDlg();

// �Ի�������
	enum { IDD = IDD_VS2015_COMMONTOOLS_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
