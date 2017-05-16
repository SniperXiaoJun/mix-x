// CommonToolsDlgSM2REQ.cpp : ÊµÏÖÎÄ¼þ
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgSM2REQ.h"
#include "afxdialogex.h"

#include "common.h"
#include "FILE_LOG.h"
#include "commontoolstypedef.h"
#include "o_all_func_def.h"
#include "openssl_func_def.h"
#include "encode_switch.h"
#include "gm-ecc-512.h"
extern E_KEY_ALG_TYPE g_KeyAlgType;


// CommonToolsDlgSM2REQ ¶Ô»°¿ò

IMPLEMENT_DYNAMIC(CommonToolsDlgSM2REQ, CDialogEx)

CommonToolsDlgSM2REQ::CommonToolsDlgSM2REQ(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgSM2REQ::IDD, pParent)
{

}

CommonToolsDlgSM2REQ::~CommonToolsDlgSM2REQ()
{
}

void CommonToolsDlgSM2REQ::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, editPRV);
	DDX_Control(pDX, IDC_EDIT2, editXY);
	DDX_Control(pDX, IDC_EDIT_NAME, editName);
	DDX_Control(pDX, IDC_EDIT_EMAIL, editEmail);
	DDX_Control(pDX, IDC_EDIT5, editReq);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgSM2REQ, CDialogEx)
	ON_BN_CLICKED(IDOK, &CommonToolsDlgSM2REQ::OnBnClickedOk)
	ON_BN_CLICKED(IDCANCEL, &CommonToolsDlgSM2REQ::OnBnClickedCancel)
	ON_EN_CHANGE(IDC_EDIT1, &CommonToolsDlgSM2REQ::OnEnChangeEdit1)
	ON_EN_CHANGE(IDC_EDIT_NAME, &CommonToolsDlgSM2REQ::OnEnChangeEditName)
END_MESSAGE_MAP()


// CommonToolsDlgSM2REQ ÏûÏ¢´¦Àí³ÌÐò

void CommonToolsDlgSM2REQ::OnBnClickedOk()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	//CDialogEx::OnOK();

	unsigned char data_value_xy[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_prv[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_csr[BUFFER_LEN_1K * 4] = {0};

	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_xy[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len_xy = BUFFER_LEN_1K * 4;
	unsigned int data_len_prv = BUFFER_LEN_1K * 4;
	unsigned int data_len_csr= BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;

	OpenSSL_Initialize();

	// pubkey xy
	editXY.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	data_len_tmp = wcslen(data_value_tmp);
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_xy,&data_len_xy);

	// privkey
	editPRV.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	data_len_tmp = wcslen(data_value_tmp);
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_prv,&data_len_prv);

	OPST_USERINFO userInfo = {0};

	editName.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	strcpy(userInfo.commonName, utf8_encode(data_value_tmp).c_str());
	userInfo.uiLenCN = strlen(userInfo.commonName);

	editEmail.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);

	strcpy(userInfo.emailAddress, utf8_encode(data_value_tmp).c_str());
	userInfo.uiLenEA = strlen(userInfo.emailAddress);

	unsigned int uiRet = 0;

	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		if (GM_ECC_512_BYTES_LEN != data_len_prv || 2 * GM_ECC_512_BYTES_LEN != data_len_xy)
		{
			MessageBox(L"操作失败");
			goto err;
		}

		uiRet = OpenSSL_GMECC512GenCSRWithPubkey(&userInfo,
			data_value_xy , GM_ECC_512_BYTES_LEN,
			data_value_xy + GM_ECC_512_BYTES_LEN, GM_ECC_512_BYTES_LEN,
			data_value_csr,&data_len_csr);

		if (uiRet)
		{
			MessageBox(L"操作失败");
			goto err;
		}
	}
	else
	{
		if (SM2_BYTES_LEN != data_len_prv || 2 * SM2_BYTES_LEN != data_len_xy)
		{
			MessageBox(L"操作失败");
			goto err;
		}

		uiRet = OpenSSL_SM2GenCSRWithPubkey(&userInfo,
			data_value_xy , SM2_BYTES_LEN,
			data_value_xy + SM2_BYTES_LEN, SM2_BYTES_LEN,
			data_value_csr,&data_len_csr);

		if (uiRet)
		{
			MessageBox(L"操作失败");
			goto err;
		}
	}

	data_len_tmp = BUFFER_LEN_1K * 4;

	OPF_Bin2WStr( (unsigned char *)data_value_csr,data_len_csr, data_value_tmp,&data_len_tmp);

	editReq.SetWindowText(data_value_tmp);
err:

	OpenSSL_Finalize();

}


void CommonToolsDlgSM2REQ::OnBnClickedCancel()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	//CDialogEx::OnCancel();
	unsigned char data_value_xy[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_prv[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_csr[BUFFER_LEN_1K * 4] = {0};

	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_xy[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len_xy = BUFFER_LEN_1K * 4;
	unsigned int data_len_prv = BUFFER_LEN_1K * 4;
	unsigned int data_len_csr= BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;

	OpenSSL_Initialize();

	// pubkey xy
	editXY.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	data_len_tmp = wcslen(data_value_tmp);
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_xy,&data_len_xy);

	// privkey
	editPRV.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	data_len_tmp = wcslen(data_value_tmp);
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_prv,&data_len_prv);

	OPST_USERINFO userInfo = {0};

	editName.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	strcpy(userInfo.commonName, utf8_encode(data_value_tmp).c_str());
	userInfo.uiLenCN = strlen(userInfo.commonName);

	editEmail.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	strcpy(userInfo.emailAddress, utf8_encode(data_value_tmp).c_str());
	userInfo.uiLenEA = strlen(userInfo.emailAddress);

	unsigned int uiRet = 0;

	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		if (GM_ECC_512_BYTES_LEN != data_len_prv || 2 * GM_ECC_512_BYTES_LEN != data_len_xy)
		{
			MessageBox(L"操作失败");
			goto err;
		}

		uiRet = OpenSSL_GMECC512GenCSRWithPubkey(&userInfo,
			data_value_xy , GM_ECC_512_BYTES_LEN,
			data_value_xy + GM_ECC_512_BYTES_LEN, GM_ECC_512_BYTES_LEN,
			data_value_csr,&data_len_csr);

		if (uiRet)
		{
			MessageBox(L"操作失败");
			goto err;
		}
		uiRet = OpenSSL_GMECC512SignCSR(data_value_csr,data_len_csr,data_value_prv,data_len_prv,0,data_value_csr,&data_len_csr);
	}
	else
	{
		if (SM2_BYTES_LEN != data_len_prv || 2 * SM2_BYTES_LEN != data_len_xy)
		{
			MessageBox(L"操作失败");
			goto err;
		}

		uiRet = OpenSSL_SM2GenCSRWithPubkey(&userInfo,
			data_value_xy , SM2_BYTES_LEN,
			data_value_xy + SM2_BYTES_LEN, SM2_BYTES_LEN,
			data_value_csr,&data_len_csr);

		if (uiRet)
		{
			MessageBox(L"操作失败");
			goto err;
		}
		uiRet = OpenSSL_SM2SignCSR(data_value_csr,data_len_csr,data_value_prv,data_len_prv,0,data_value_csr,&data_len_csr);
	}

	

	if (uiRet)
	{
		MessageBox(L"操作失败");
		goto err;
	}

	data_len_tmp = BUFFER_LEN_1K * 4;

	OPF_Bin2WStr( (unsigned char *)data_value_csr,data_len_csr, data_value_tmp,&data_len_tmp);

	editReq.SetWindowText(data_value_tmp);
err:

	OpenSSL_Finalize();
}


void CommonToolsDlgSM2REQ::OnEnChangeEdit1()
{
	// TODO:  Èç¹û¸Ã¿Ø¼þÊÇ RICHEDIT ¿Ø¼þ£¬Ëü½«²»
	// ·¢ËÍ´ËÍ¨Öª£¬³ý·ÇÖØÐ´ CDialogEx::OnInitDialog()
	// º¯Êý²¢µ÷ÓÃ CRichEditCtrl().SetEventMask()£¬
	// Í¬Ê±½« ENM_CHANGE ±êÖ¾¡°»ò¡±ÔËËãµ½ÑÚÂëÖÐ¡£

	// TODO:  ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
}


void CommonToolsDlgSM2REQ::OnEnChangeEditName()
{
	// TODO:  Èç¹û¸Ã¿Ø¼þÊÇ RICHEDIT ¿Ø¼þ£¬Ëü½«²»
	// ·¢ËÍ´ËÍ¨Öª£¬³ý·ÇÖØÐ´ CDialogEx::OnInitDialog()
	// º¯Êý²¢µ÷ÓÃ CRichEditCtrl().SetEventMask()£¬
	// Í¬Ê±½« ENM_CHANGE ±êÖ¾¡°»ò¡±ÔËËãµ½ÑÚÂëÖÐ¡£

	// TODO:  ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
}
