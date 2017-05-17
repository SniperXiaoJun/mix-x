// CommonToolsDlgSM2KEY.cpp : ÊµÏÖÎÄ¼þ
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgSM2KEY.h"
#include "afxdialogex.h"
#include "encode_switch.h"
#include "common.h"
#include "FILE_LOG.h"
#include "commontoolstypedef.h"
#include "o_all_func_def.h"
#include "openssl_func_def.h"

#include "gm-ecc-512.h"
extern E_KEY_ALG_TYPE g_KeyAlgType;

// CommonToolsDlgSM2KEY ¶Ô»°¿ò

IMPLEMENT_DYNAMIC(CommonToolsDlgSM2KEY, CDialogEx)

CommonToolsDlgSM2KEY::CommonToolsDlgSM2KEY(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgSM2KEY::IDD, pParent)
{

}

CommonToolsDlgSM2KEY::~CommonToolsDlgSM2KEY()
{
}

void CommonToolsDlgSM2KEY::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT2, editXY);
	DDX_Control(pDX, IDC_EDIT1, editPRV);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgSM2KEY, CDialogEx)
	ON_BN_CLICKED(IDOK, &CommonToolsDlgSM2KEY::OnBnClickedOk)
END_MESSAGE_MAP()


// CommonToolsDlgSM2KEY ÏûÏ¢´¦Àí³ÌÐò


void CommonToolsDlgSM2KEY::OnBnClickedOk()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	// CDialogEx::OnOK();

	unsigned char data_value_xy[BUFFER_LEN_1K * 4] = { 0 };
	unsigned int data_len_xy = BUFFER_LEN_1K * 4;

	unsigned char data_value_x[BUFFER_LEN_1K * 4] = { 0 };
	unsigned char data_value_y[BUFFER_LEN_1K * 4] = { 0 };
	unsigned char data_value_prv[BUFFER_LEN_1K * 4] = { 0 };

	unsigned int data_len_x = BUFFER_LEN_1K * 4;
	unsigned int data_len_y = BUFFER_LEN_1K * 4;
	unsigned int data_len_prv = BUFFER_LEN_1K * 4;

	unsigned char data_value_out_hex[BUFFER_LEN_1K * 4] = { 0 };
	unsigned int data_len_out_hex = BUFFER_LEN_1K * 4;

	unsigned int ulRet = 0;

	OpenSSL_Initialize();

	if (g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		ulRet = OpenSSL_GMECC512GenKeys(data_value_x, &data_len_x, data_value_y, &data_len_y, data_value_prv, &data_len_prv);
	}
	else
	{
		ulRet = OpenSSL_SM2GenKeys(data_value_x, &data_len_x, data_value_y, &data_len_y, data_value_prv, &data_len_prv);
	}

	OpenSSL_Finalize();

	if (0 == ulRet)
	{
		memcpy(data_value_xy, data_value_x, data_len_x);
		memcpy(data_value_xy + data_len_x, data_value_y, data_len_y);

		data_len_xy = data_len_x + data_len_y;

		OPF_Bin2Str(data_value_xy, data_len_xy, (char *)data_value_out_hex, &data_len_out_hex);
		editXY.SetWindowText(utf8_decode((char *)data_value_out_hex).c_str());

		OPF_Bin2Str(data_value_prv, data_len_prv, (char *)data_value_out_hex, &data_len_out_hex);
		editPRV.SetWindowText(utf8_decode((char *)data_value_out_hex).c_str());
	}
	else
	{
		MessageBox(L"操作失败");
	}

}
