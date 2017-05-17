// CommonToolsDlgSM2CERT.cpp : ÊµÏÖÎÄ¼þ
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgSM2CERT.h"
#include "afxdialogex.h"

#include "common.h"
#include "FILE_LOG.h"
#include "commontoolstypedef.h"
#include "o_all_func_def.h"
#include "openssl_func_def.h"
#include "encode_switch.h"
#include "gm-ecc-512.h"
extern E_KEY_ALG_TYPE g_KeyAlgType;

// CommonToolsDlgSM2CERT ¶Ô»°¿ò

IMPLEMENT_DYNAMIC(CommonToolsDlgSM2CERT, CDialogEx)

CommonToolsDlgSM2CERT::CommonToolsDlgSM2CERT(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgSM2CERT::IDD, pParent)
{

}

CommonToolsDlgSM2CERT::~CommonToolsDlgSM2CERT()
{
}

void CommonToolsDlgSM2CERT::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, editPRV);
	DDX_Control(pDX, IDC_EDIT2, editXY);
	DDX_Control(pDX, IDC_EDIT4, editROOTCER);
	DDX_Control(pDX, IDC_EDIT6, editCSR);
	DDX_Control(pDX, IDC_EDIT5, editCER);
	DDX_Control(pDX, IDC_COMBO1, comboBoxType);
	DDX_Control(pDX, IDC_EDIT3, editDate);
	DDX_Control(pDX, IDC_EDIT7, editSN);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgSM2CERT, CDialogEx)
	ON_BN_CLICKED(IDOK, &CommonToolsDlgSM2CERT::OnBnClickedOk)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CommonToolsDlgSM2CERT::OnCbnSelchangeCombo1)
	ON_BN_CLICKED(IDCANCEL, &CommonToolsDlgSM2CERT::OnBnClickedCancel)
	ON_BN_CLICKED(IDOK2, &CommonToolsDlgSM2CERT::OnBnClickedOk2)
END_MESSAGE_MAP()


// CommonToolsDlgSM2CERT ÏûÏ¢´¦Àí³ÌÐò


void CommonToolsDlgSM2CERT::OnBnClickedOk()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	//CDialogEx::OnOK();

	unsigned char data_value_xy[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_prv[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_csr[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_rootcer[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_cer[BUFFER_LEN_1K * 4] = {0};

	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len_xy = BUFFER_LEN_1K * 4;
	unsigned int data_len_prv = BUFFER_LEN_1K * 4;
	unsigned int data_len_csr= BUFFER_LEN_1K * 4;
	unsigned int data_len_cer= BUFFER_LEN_1K * 4;
	unsigned int data_len_rootcer= BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;

	OpenSSL_Initialize();

	// pubkey xy
	editXY.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_xy,&data_len_xy);

	// privkey
	editPRV.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_prv,&data_len_prv);

	// csr
	editCSR.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	
	OPF_WStr2Bin(data_value_tmp,data_len_tmp,(unsigned char *)data_value_csr,&data_len_csr);

	// rootcer
	editROOTCER.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	
	OPF_WStr2Bin(data_value_tmp,data_len_tmp,(unsigned char *)data_value_rootcer,&data_len_rootcer);

	unsigned int ulRet = 0;
	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		if (GM_ECC_512_BYTES_LEN != data_len_prv || 2 * GM_ECC_512_BYTES_LEN != data_len_xy)
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
	}


	unsigned char sn[BUFFER_LEN_1K * 4] = {0};
	unsigned int sn_len = 0;


	editSN.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	
	OPF_WStr2Bin(data_value_tmp,data_len_tmp,sn,&sn_len);

	unsigned int date = 0;

	editDate.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	date = atoi((char *)utf8_encode(data_value_tmp).c_str());

	unsigned int typeSignEncrypt = 0;

	typeSignEncrypt = comboBoxType.GetCurSel();
	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		ulRet = OpenSSL_GMECC512GenRootCert(data_value_csr,data_len_csr,sn,sn_len,0,date,
			data_value_cer,&data_len_cer);
	}
	else
	{
		ulRet = OpenSSL_SM2GenRootCert(data_value_csr,data_len_csr,sn,sn_len,0,date,
			data_value_cer,&data_len_cer);
	}


	if (ulRet)
	{
		MessageBox(L"操作失败");
		goto err;
	}

	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		ulRet = OpenSSL_GMECC512SignCert(data_value_cer,data_len_cer,
			data_value_xy,GM_ECC_512_BYTES_LEN,
			data_value_xy+GM_ECC_512_BYTES_LEN,GM_ECC_512_BYTES_LEN,
			data_value_prv,data_len_prv,
			data_value_cer,&data_len_cer);
	}
	else
	{
		ulRet = OpenSSL_SM2SignCert(data_value_cer,data_len_cer,
			data_value_xy,SM2_BYTES_LEN,
			data_value_xy+SM2_BYTES_LEN,SM2_BYTES_LEN,
			data_value_prv,data_len_prv,
			data_value_cer,&data_len_cer);
	}


	if (ulRet)
	{
		MessageBox(L"操作失败");
		goto err;
	}

	data_len_tmp = BUFFER_LEN_1K * 4;

	OPF_Bin2WStr( (unsigned char *)data_value_cer,data_len_cer, data_value_tmp,&data_len_tmp);

	editCER.SetWindowText(data_value_tmp);
err:

	OpenSSL_Finalize();
}


void CommonToolsDlgSM2CERT::OnCbnSelchangeCombo1()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
}


void CommonToolsDlgSM2CERT::OnBnClickedCancel()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	//CDialogEx::OnCancel();

	unsigned char data_value_xy[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_prv[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_csr[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_rootcer[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_cer[BUFFER_LEN_1K * 4] = {0};

	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_xy[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len_xy = BUFFER_LEN_1K * 4;
	unsigned int data_len_prv = BUFFER_LEN_1K * 4;
	unsigned int data_len_csr= BUFFER_LEN_1K * 4;
	unsigned int data_len_cer= BUFFER_LEN_1K * 4;
	unsigned int data_len_rootcer= BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;

	OpenSSL_Initialize();

	// pubkey xy
	editXY.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_xy,&data_len_xy);

	// privkey
	editPRV.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_prv,&data_len_prv);

	// csr
	editCSR.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	
	OPF_WStr2Bin(data_value_tmp,data_len_tmp,(unsigned char *)data_value_csr,&data_len_csr);

	// rootcer
	editROOTCER.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	
	OPF_WStr2Bin(data_value_tmp,data_len_tmp,(unsigned char *)data_value_rootcer,&data_len_rootcer);

	unsigned int ulRet = 0;

	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		if (GM_ECC_512_BYTES_LEN != data_len_prv || 2 * GM_ECC_512_BYTES_LEN != data_len_xy)
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
	}

	unsigned char sn[BUFFER_LEN_1K * 4] = {0};
	unsigned int sn_len = 0;


	editSN.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	
	OPF_WStr2Bin(data_value_tmp,data_len_tmp,sn,&sn_len);

	unsigned int date = 0;

	editDate.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	date = atoi((char *)utf8_encode(data_value_tmp).c_str());

	unsigned int typeSignEncrypt = 0;

	typeSignEncrypt = comboBoxType.GetCurSel();
	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		ulRet = OpenSSL_GMECC512GenCert(data_value_csr,data_len_csr,data_value_rootcer, data_len_rootcer,sn,sn_len,0,date,
			typeSignEncrypt,data_value_cer,&data_len_cer);
	}
	else
	{
		ulRet = OpenSSL_SM2GenCert(data_value_csr,data_len_csr,data_value_rootcer, data_len_rootcer,sn,sn_len,0,date,
			typeSignEncrypt,data_value_cer,&data_len_cer);
	}


	if (ulRet)
	{
		MessageBox(L"操作失败");
		goto err;
	}
	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		ulRet = OpenSSL_GMECC512SignCert(data_value_cer,data_len_cer,
			data_value_xy,GM_ECC_512_BYTES_LEN,
			data_value_xy+GM_ECC_512_BYTES_LEN,GM_ECC_512_BYTES_LEN,
			data_value_prv,data_len_prv,
			data_value_cer,&data_len_cer);
	}
	else
	{
		ulRet = OpenSSL_SM2SignCert(data_value_cer,data_len_cer,
			data_value_xy,SM2_BYTES_LEN,
			data_value_xy+SM2_BYTES_LEN,SM2_BYTES_LEN,
			data_value_prv,data_len_prv,
			data_value_cer,&data_len_cer);

	}

	if (ulRet)
	{
		MessageBox(L"操作失败");
		goto err;
	}

	data_len_tmp = BUFFER_LEN_1K * 4;

	OPF_Bin2WStr( (unsigned char *)data_value_cer,data_len_cer, data_value_tmp,&data_len_tmp);

	editCER.SetWindowText(data_value_tmp);
err:

	OpenSSL_Finalize();
}


BOOL CommonToolsDlgSM2CERT::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	int pos = -1;

	pos = comboBoxType.InsertString(pos + 1, L"签名");

	pos = comboBoxType.InsertString(pos + 1, L"加密");

	pos = comboBoxType.InsertString(pos + 1, L"数据加密");

	pos = comboBoxType.InsertString(pos + 1, L"密钥加密");

	comboBoxType.SetCurSel(0);


	// TODO:  ÔÚ´ËÌí¼Ó¶îÍâµÄ³õÊ¼»¯

	return TRUE;  // return TRUE unless you set the focus to a control
	// Òì³£: OCX ÊôÐÔÒ³Ó¦·µ»Ø FALSE
}


void CommonToolsDlgSM2CERT::OnBnClickedOk2()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë

	unsigned int ulRet = 0;


	unsigned char data_value_xy[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_prv[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_csr[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_rootcer[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_cer[BUFFER_LEN_1K * 4] = {0};

	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_xy[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len_xy = BUFFER_LEN_1K * 4;
	unsigned int data_len_prv = BUFFER_LEN_1K * 4;
	unsigned int data_len_csr= BUFFER_LEN_1K * 4;
	unsigned int data_len_cer= BUFFER_LEN_1K * 4;
	unsigned int data_len_rootcer= BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;

	OpenSSL_Initialize();

	// pubkey xy
	editXY.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value_xy,&data_len_xy);

	// cer
	editCER.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	
	OPF_WStr2Bin(data_value_tmp,data_len_tmp,(unsigned char *)data_value_cer,&data_len_cer);

	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		ulRet = OpenSSL_GMECC512VerifyCert(data_value_cer,data_len_cer,0,data_value_xy,GM_ECC_512_BYTES_LEN,data_value_xy + GM_ECC_512_BYTES_LEN,GM_ECC_512_BYTES_LEN);
	}
	else
	{
		ulRet = OpenSSL_SM2VerifyCert(data_value_cer,data_len_cer,0,data_value_xy,SM2_BYTES_LEN,data_value_xy + SM2_BYTES_LEN,SM2_BYTES_LEN);
	}

	if (ulRet)
	{
		MessageBox(L"操作失败");
	}
	else
	{
		MessageBox(L"操作成功");
	}

err:

	OpenSSL_Finalize();
}
