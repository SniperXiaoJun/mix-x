// CommonToolsDlgSM2Write.cpp : ÊµÏÖÎÄ¼þ
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgSM2Write.h"
#include "afxdialogex.h"

#include "common.h"
#include "FILE_LOG.h"
#include "commontoolstypedef.h"
#include "o_all_func_def.h"
#include "openssl_func_def.h"
#include "encode_switch.h"


// CommonToolsDlgSM2Write ¶Ô»°¿ò

IMPLEMENT_DYNAMIC(CommonToolsDlgSM2Write, CDialogEx)

CommonToolsDlgSM2Write::CommonToolsDlgSM2Write(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgSM2Write::IDD, pParent)
{

}

CommonToolsDlgSM2Write::~CommonToolsDlgSM2Write()
{
}

void CommonToolsDlgSM2Write::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO2, comboBoxType);
	DDX_Control(pDX, IDC_COMBO1, comboBoxEncode);
	DDX_Control(pDX, IDC_EDIT1, editIN);
	DDX_Control(pDX, IDC_EDIT7, editOUT);
	DDX_Control(pDX, IDC_EDIT3, editPW);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgSM2Write, CDialogEx)
	ON_BN_CLICKED(IDCANCEL, &CommonToolsDlgSM2Write::OnBnClickedCancel)
	ON_CBN_SELCHANGE(IDC_COMBO1, &CommonToolsDlgSM2Write::OnCbnSelchangeCombo1)
END_MESSAGE_MAP()


// CommonToolsDlgSM2Write ÏûÏ¢´¦Àí³ÌÐò


void CommonToolsDlgSM2Write::OnBnClickedCancel()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	//CDialogEx::OnCancel();

	unsigned char data_value[BUFFER_LEN_1K * 4] = {0};
	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};

	wchar_t data_value_pw[BUFFER_LEN_1K * 4] = {0};
	wchar_t data_value_file[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len = BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;

	OpenSSL_Initialize();

	// pubkey xy
	editIN.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	OPF_WStr2Bin(data_value_tmp,data_len_tmp, (unsigned char *)data_value,&data_len);

	unsigned int ulRet = 0;

	editPW.GetWindowText(data_value_pw,BUFFER_LEN_1K * 4);

	editOUT.GetWindowText(data_value_file,BUFFER_LEN_1K * 4);
	
	unsigned int type = 0;

	type = comboBoxType.GetCurSel();

	unsigned int encode = 0;

	encode = comboBoxEncode.GetCurSel();

	ulRet = OpenSSL_SM2Write(data_value, data_len, type, (char *)utf8_encode(data_value_file).c_str() , encode, (char *)utf8_encode(data_value_pw).c_str());

	if (ulRet)
	{
		MessageBox(L"操作失败");
		goto err;
	}
	else
	{
		MessageBox(L"操作成功");
		goto err;
	}
err:

	OpenSSL_Finalize();

}


BOOL CommonToolsDlgSM2Write::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  ÔÚ´ËÌí¼Ó¶îÍâµÄ³õÊ¼»¯

	int pos = -1;

	pos = comboBoxType.InsertString(pos + 1, L"私钥");

	pos = comboBoxType.InsertString(pos + 1, L"公钥");

	pos = comboBoxType.InsertString(pos + 1, L"证书");

	pos = -1;

	pos = comboBoxEncode.InsertString(pos + 1, L"DER");
	pos = comboBoxEncode.InsertString(pos + 1, L"PEM");

	comboBoxType.SetCurSel(0);
	comboBoxEncode.SetCurSel(0);


	return TRUE;  // return TRUE unless you set the focus to a control
	// Òì³£: OCX ÊôÐÔÒ³Ó¦·µ»Ø FALSE
}


void CommonToolsDlgSM2Write::OnCbnSelchangeCombo1()
{
	// TODO: Add your control notification handler code here
}
