
// APITest_CommonToolsDlg.cpp : ÊµÏÖÎÄ¼þ
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlg.h"
#include "afxdialogex.h"
#include "CommonToolsDlgChar.h"
#include "CommonToolsDlgB64.h"
#include "CommonToolsDlgSM2Point.h"
#include "CommonToolsDlgSM2ENDE.h"
#include "CommonToolsDlgSM2SignVerify.h"
#include "CommonToolsDlgSM2KEY.h"
#include "CommonToolsDlgSM2REQ.h"
#include "CommonToolsDlgSM2CERT.h"
#include "CommonToolsDlgSM2Write.h"
#include "CommonToolsTypedef.h"
#include "CommonToolsDlgHASH.h"
#include "CommonToolsDlgKeyEx.h"
#include "CommonToolsDlgBit.h"
#include "CommonToolsDlgFILL.h"
#include "CommonToolsDlgReverse.h"
#include "CommonToolsDlgDigitalE.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

E_HASH_ALG_TYPE g_HashAlgType = E_HASH_ALG_SM3;

E_KEY_ALG_TYPE g_KeyAlgType = E_KEY_ALG_SM2;

// ÓÃÓÚÓ¦ÓÃ³ÌÐò¡°¹ØÓÚ¡±²Ëµ¥ÏîµÄ CAboutDlg ¶Ô»°¿ò

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

	// ¶Ô»°¿òÊý¾Ý
	enum { IDD = IDD_ABOUTBOX };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV Ö§³Ö

	// ÊµÏÖ
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{

}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CommonToolsDlg ¶Ô»°¿ò




CommonToolsDlg::CommonToolsDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CommonToolsDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_TAB_ALL, m_tb);
	DDX_Control(pDX, IDC_COMBOTYPE, comboBoxHashAlgType);
	DDX_Control(pDX, IDC_COMBOTYPE2, comboBoxKeyAlgType);
}

BEGIN_MESSAGE_MAP(CommonToolsDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_NOTIFY(TCN_SELCHANGE, IDC_TAB_ALL, &CommonToolsDlg::OnTcnSelchangeTabAll)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CommonToolsDlg::OnCbnSelchangeCombo1)
	ON_CBN_SELCHANGE(IDC_COMBOTYPE, &CommonToolsDlg::OnCbnSelchangeCombotype)
	ON_CBN_SELCHANGE(IDC_COMBOTYPE2, &CommonToolsDlg::OnCbnSelchangeCombotype2)
END_MESSAGE_MAP()


// CommonToolsDlg ÏûÏ¢´¦Àí³ÌÐò

BOOL CommonToolsDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ½«¡°¹ØÓÚ...¡±²Ëµ¥ÏîÌí¼Óµ½ÏµÍ³²Ëµ¥ÖÐ¡£

	// IDM_ABOUTBOX ±ØÐëÔÚÏµÍ³ÃüÁî·¶Î§ÄÚ¡£
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// ÉèÖÃ´Ë¶Ô»°¿òµÄÍ¼±ê¡£µ±Ó¦ÓÃ³ÌÐòÖ÷´°¿Ú²»ÊÇ¶Ô»°¿òÊ±£¬¿ò¼Ü½«×Ô¶¯
	//  Ö´ÐÐ´Ë²Ù×÷
	SetIcon(m_hIcon, TRUE);			// ÉèÖÃ´óÍ¼±ê
	SetIcon(m_hIcon, FALSE);		// ÉèÖÃÐ¡Í¼±ê

	// TODO: ÔÚ´ËÌí¼Ó¶îÍâµÄ³õÊ¼»¯´úÂë

	m_tb.InsertItem(0, L"字符转换");
	m_tb.InsertItem(1, L"Base64编码");
	m_tb.InsertItem(9, L"HASH OR ZM");
	m_tb.InsertItem(3, L"加密解密");
	m_tb.InsertItem(4, L"签名验证");
	m_tb.InsertItem(5, L"密钥生成");
	m_tb.InsertItem(6, L"证书请求");
	m_tb.InsertItem(7, L"证书");
	m_tb.InsertItem(8, L"写文件");
	m_tb.InsertItem(9, L"点验证");
	m_tb.InsertItem(10, L"密钥交换");
	m_tb.InsertItem(11, L"BIT");
	m_tb.InsertItem(12, L"FILL");
	m_tb.InsertItem(13, L"REVERSE");
	m_tb.InsertItem(14, L"DigitalE");



	//´´½¨Á½¸ö¶Ô»°¿ò
	//m_page1.Create(IDD_DIALOG, &m_tb);
	//m_page2.Create(IDD_DIALOG_CERTUI_PROP_DETAIL, &m_tb);
	//m_page3.Create(IDD_DIALOG_CERTUI_PROP_PATH, &m_tb);

	//Éè¶¨ÔÚTabÄÚÏÔÊ¾µÄ·¶Î§
	CRect rc;
	m_tb.GetClientRect(rc);
	rc.top += 20;
	rc.bottom -= 8;
	rc.left += 8;
	rc.right -= 8;

	for (int i = 0; i < sizeof(pDialog)/sizeof(char *); i++)
	{
		switch(i)
		{
		case 0:
			pDialog[i] = new CommonToolsDlgChar(this);

			pDialog[i]->Create(IDD_DIALOG_CHAR, &m_tb);
			break;
		case 1:
			pDialog[i] = new CommonToolsDlgB64(this);

			pDialog[i]->Create(IDD_DIALOG_B64, &m_tb);
			break;
		case 2:
			pDialog[i] = new CommonToolsDlgHASH(this);

			pDialog[i]->Create(IDD_DIALOG_HASH, &m_tb);
			break;
		case 3:
			pDialog[i] = new CommonToolsDlgSM2ENDE(this);

			pDialog[i]->Create(IDD_DIALOG_SM2ENDE, &m_tb);
			break;
		case 4:
			pDialog[i] = new CommonToolsDlgSM2SignVerify(this);

			pDialog[i]->Create(IDD_DIALOG_SM2SIGNVERIFY, &m_tb);
			break;
		case 5:
			pDialog[i] = new CommonToolsDlgSM2KEY(this);

			pDialog[i]->Create(IDD_DIALOG_SM2KEY, &m_tb);
			break;

		case 6:
			pDialog[i] = new CommonToolsDlgSM2REQ(this);

			pDialog[i]->Create(IDD_DIALOG_SM2REQ, &m_tb);
			break;

		case 7:
			pDialog[i] = new CommonToolsDlgSM2CERT(this);

			pDialog[i]->Create(IDD_DIALOG_SM2CERT, &m_tb);
			break;

		case 8:
			pDialog[i] = new CommonToolsDlgSM2Write(this);

			pDialog[i]->Create(IDD_DIALOG_SM2WRITE, &m_tb);
			break;
		case 9:

			pDialog[i] = new CommonToolsDlgSM2Point(this);

			pDialog[i]->Create(IDD_DIALOG_SM2POINT, &m_tb);
			break;

		case 10:

			pDialog[i] = new CommonToolsDlgKeyEx(this);

			pDialog[i]->Create(IDD_DIALOG_KEY_EX, &m_tb);
			break;
		case 11:

			pDialog[i] = new CommonToolsDlgBit(this);

			pDialog[i]->Create(IDD_DIALOG_BIT, &m_tb);
			break;

		case 12:

			pDialog[i] = new CommonToolsDlgFILL(this);

			pDialog[i]->Create(IDD_DIALOG_FILL, &m_tb);
			break;
		case 13:

			pDialog[i] = new CommonToolsDlgReverse(this);

			pDialog[i]->Create(IDD_DIALOG_REVERSE, &m_tb);
			break;

		case 14:

			pDialog[i] = new CommonToolsDlgDigitalE(this);

			pDialog[i]->Create(IDD_DIALOG_SM2DigitalE, &m_tb);
			break;


		default:
			pDialog[i] = new CDialog();

			break;
		}

		if (i < 15)
		{
			pDialog[i]->MoveWindow(&rc);
			pDialog[i]->ShowWindow(SW_HIDE);
		}

	}




	pos = -1;

	pos = comboBoxHashAlgType.InsertString(pos + 1, L"SM3");
	pos = comboBoxHashAlgType.InsertString(pos + 1, L"ZY512");
	pos = comboBoxHashAlgType.InsertString(pos + 1, L"ZY256");

	comboBoxHashAlgType.SetCurSel(0);


	pos = -1;

	pos = comboBoxKeyAlgType.InsertString(pos + 1, L"SM2");
	pos = comboBoxKeyAlgType.InsertString(pos + 1, L"ECC512");

	comboBoxKeyAlgType.SetCurSel(0);


	g_HashAlgType = E_HASH_ALG_SM3;
	g_KeyAlgType = E_KEY_ALG_SM2;

	//ÏÔÊ¾³õÊ¼Ò³Ãæ
	pDialog[0]->ShowWindow(SW_SHOW);

	//±£´æµ±Ç°Ñ¡Ôñ
	m_CurSelTab = 0;

	return TRUE;  // ³ý·Ç½«½¹µãÉèÖÃµ½¿Ø¼þ£¬·ñÔò·µ»Ø TRUE
}

void CommonToolsDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// Èç¹ûÏò¶Ô»°¿òÌí¼Ó×îÐ¡»¯°´Å¥£¬ÔòÐèÒªÏÂÃæµÄ´úÂë
//  À´»æÖÆ¸ÃÍ¼±ê¡£¶ÔÓÚÊ¹ÓÃÎÄµµ/ÊÓÍ¼Ä£ÐÍµÄ MFC Ó¦ÓÃ³ÌÐò£¬
//  Õâ½«ÓÉ¿ò¼Ü×Ô¶¯Íê³É¡£

void CommonToolsDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ÓÃÓÚ»æÖÆµÄÉè±¸ÉÏÏÂÎÄ

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Ê¹Í¼±êÔÚ¹¤×÷Çø¾ØÐÎÖÐ¾ÓÖÐ
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// »æÖÆÍ¼±ê
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//µ±ÓÃ»§ÍÏ¶¯×îÐ¡»¯´°¿ÚÊ±ÏµÍ³µ÷ÓÃ´Ëº¯ÊýÈ¡µÃ¹â±ê
//ÏÔÊ¾¡£
HCURSOR CommonToolsDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CommonToolsDlg::OnTcnSelchangeTabAll(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	//°Ñµ±Ç°µÄÒ³ÃæÒþ²ØÆðÀ´
	pDialog[m_CurSelTab]->ShowWindow(SW_HIDE);
	//µÃµ½ÐÂµÄÒ³ÃæË÷Òý
	m_CurSelTab = m_tb.GetCurSel();
	//°ÑÐÂµÄÒ³ÃæÏÔÊ¾³öÀ´
	pDialog[m_CurSelTab]->ShowWindow(SW_SHOW);
	*pResult = 0;
}

CommonToolsDlg::~CommonToolsDlg()
{
	//int i =0;
	//for (;i < sizeof(pDialog); i++)
	//{
	//	delete pDialog[i];
	//}
}


void CommonToolsDlg::OnCbnSelchangeCombo1()
{
	// TODO: Add your control notification handler code here



}


void CommonToolsDlg::OnCbnSelchangeCombotype()
{
	// TODO: Add your control notification handler code here

	if (comboBoxHashAlgType.GetCurSel() == 0)
	{
		g_HashAlgType = E_HASH_ALG_SM3;
	}
	else if (comboBoxHashAlgType.GetCurSel() == 1)
	{
		g_HashAlgType = E_HASH_ALG_ZY_512;
	}
	else
	{
		g_HashAlgType = E_HASH_ALG_ZY_256;
	}
}


void CommonToolsDlg::OnCbnSelchangeCombotype2()
{
	if (comboBoxKeyAlgType.GetCurSel() == 0)
	{
		g_KeyAlgType = E_KEY_ALG_SM2;
	}
	else if (comboBoxKeyAlgType.GetCurSel() == 1)
	{
		g_KeyAlgType = E_KEY_ALG_ECC_512;
	}
	else
	{
		g_KeyAlgType = E_KEY_ALG_SM2;
	}
}
