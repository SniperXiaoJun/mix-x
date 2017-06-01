// CommonToolsDlgDigitalE.cpp : 实现文件
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgDigitalE.h"
#include "afxdialogex.h"
#include "encode_switch.h"
#include "common.h"
#include "FILE_LOG.h"
#include "commontoolstypedef.h"
#include "o_all_func_def.h"
#include "openssl_func_def.h"

#include "gm-ecc-512.h"
extern E_KEY_ALG_TYPE g_KeyAlgType;

// CommonToolsDlgDigitalE 对话框

IMPLEMENT_DYNAMIC(CommonToolsDlgDigitalE, CDialogEx)

CommonToolsDlgDigitalE::CommonToolsDlgDigitalE(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgDigitalE::IDD, pParent)
{

}

CommonToolsDlgDigitalE::~CommonToolsDlgDigitalE()
{
}

void CommonToolsDlgDigitalE::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT2, m_editPK);
	DDX_Control(pDX, IDC_EDIT5, m_editDigitalE);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgDigitalE, CDialogEx)
	ON_BN_CLICKED(IDCANCEL, &CommonToolsDlgDigitalE::OnBnClickedCancel)
END_MESSAGE_MAP()


// CommonToolsDlgDigitalE 消息处理程序


void CommonToolsDlgDigitalE::OnBnClickedCancel()
{
	// TODO: 在此添加控件通知处理程序代码
	//CDialogEx::OnOK();
	char data_value_key[BUFFER_LEN_1K * 4] = {0};
	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_key = BUFFER_LEN_1K * 4;
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;

	unsigned char data_value_out[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_in = BUFFER_LEN_1K * 4;
	unsigned int data_len_out = BUFFER_LEN_1K * 4;
	unsigned char data_value_out_hex[BUFFER_LEN_1K * 4] = { 0 };
	unsigned int data_len_out_hex = BUFFER_LEN_1K * 4;

	OpenSSL_Initialize();

	m_editPK.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(), strlen(utf8_encode(data_value_tmp).c_str()), (unsigned char *)data_value_key,&data_len_key);

	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		if (data_len_key == GM_ECC_512_BYTES_LEN * 2)
		{
			unsigned int ulRet = OpenSSL_GMECC512GenExportEnvelopedKey((unsigned char *)data_value_key,GM_ECC_512_BYTES_LEN,
				(unsigned char *)data_value_key + GM_ECC_512_BYTES_LEN,GM_ECC_512_BYTES_LEN,
				(unsigned char *)data_value_out,&data_len_out);

			if (ulRet)
			{
				MessageBox(L"操作失败！");
			}
		}
	}
	else
	{
		if (data_len_key == SM2_BYTES_LEN * 2)
		{
			unsigned int ulRet = OpenSSL_SM2GenExportEnvelopedKey((unsigned char *)data_value_key,SM2_BYTES_LEN,
				(unsigned char *)data_value_key + SM2_BYTES_LEN,SM2_BYTES_LEN,
				(unsigned char *)data_value_out,&data_len_out);


			if (ulRet)
			{
				MessageBox(L"操作失败！");
			}
		}
	}

	OPF_Bin2Str((unsigned char *)data_value_out, data_len_out, (char *)data_value_out_hex, &data_len_out_hex);
	m_editDigitalE.SetWindowText(utf8_decode((char *)data_value_out_hex).c_str());

	OpenSSL_Finalize();
}
