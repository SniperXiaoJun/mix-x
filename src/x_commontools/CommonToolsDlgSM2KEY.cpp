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
	m_iSelPRV = -1;
	m_iSelXY = -1;
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
	ON_BN_CLICKED(IDC_RADIO1, &CommonToolsDlgSM2KEY::OnBnClickedRadio1)
	ON_BN_CLICKED(IDC_RADIO2, &CommonToolsDlgSM2KEY::OnBnClickedRadio2)
	ON_BN_CLICKED(IDC_RADIO3, &CommonToolsDlgSM2KEY::OnBnClickedRadio3)
	ON_BN_CLICKED(IDC_RADIO4, &CommonToolsDlgSM2KEY::OnBnClickedRadio4)
	ON_BN_CLICKED(IDC_RADIO5, &CommonToolsDlgSM2KEY::OnBnClickedRadio5)
	ON_BN_CLICKED(IDC_RADIO6, &CommonToolsDlgSM2KEY::OnBnClickedRadio6)
END_MESSAGE_MAP()


// CommonToolsDlgSM2KEY ÏûÏ¢´¦Àí³ÌÐò


void CommonToolsDlgSM2KEY::OnBnClickedOk()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	// CDialogEx::OnOK();

	unsigned char data_value_xy[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_xy = BUFFER_LEN_1K * 4;

	unsigned char data_value_x[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_y[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_prv[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len_x = BUFFER_LEN_1K * 4;
	unsigned int data_len_y = BUFFER_LEN_1K * 4;
	unsigned int data_len_prv = BUFFER_LEN_1K * 4;

	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};
	unsigned int data_len_tmp = BUFFER_LEN_1K * 4;

	wchar_t file_xy[BUFFER_LEN_1K * 4] = {0};
	wchar_t file_prv[BUFFER_LEN_1K * 4] = {0};

	unsigned int ulRet = 0;

	OpenSSL_Initialize();

	if(g_KeyAlgType == E_KEY_ALG_ECC_512)
	{
		ulRet = OpenSSL_GMECC512GenKeys(data_value_x,&data_len_x,data_value_y,&data_len_y,data_value_prv, &data_len_prv);
	}
	else
	{
		ulRet = OpenSSL_SM2GenKeys(data_value_x,&data_len_x,data_value_y,&data_len_y,data_value_prv, &data_len_prv);
	}

	

	OpenSSL_Finalize();

	if (0 == ulRet)
	{
		memcpy(data_value_xy, data_value_x,data_len_x);
		memcpy(data_value_xy+data_len_x, data_value_y,data_len_y);

		data_len_xy = data_len_x + data_len_y;

		switch(m_iSelXY)
		{
		case E_INPUT_TYPE_FILE:
			{
				editXY.GetWindowText(file_xy,BUFFER_LEN_1K * 4);

				FILE_WRITE("", (char *)utf8_encode(file_xy).c_str(),(unsigned char *)data_value_xy,data_len_xy);
			}
			break;
		default:
			{
				OPF_Bin2WStr(data_value_xy,data_len_xy, data_value_tmp,&data_len_tmp);

				editXY.SetWindowText(data_value_tmp);
			}
			break;
		}

		switch(m_iSelPRV)
		{
		case E_INPUT_TYPE_FILE:
			{
				editPRV.GetWindowText(file_prv,BUFFER_LEN_1K * 4);

				FILE_WRITE("", (char *)utf8_encode(file_prv).c_str(),(unsigned char *)data_value_prv,data_len_prv);
			}
			break;
		default:
			{
				OPF_Bin2WStr(data_value_prv,data_len_prv, data_value_tmp,&data_len_tmp);

				editPRV.SetWindowText(data_value_tmp);
			}
			break;
		}
	}
	else
	{
		MessageBox(L"操作失败");
	}

}


void CommonToolsDlgSM2KEY::OnBnClickedRadio1()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelPRV = E_INPUT_TYPE_FILE;
}


void CommonToolsDlgSM2KEY::OnBnClickedRadio2()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelPRV = E_INPUT_TYPE_CHAR;
}


void CommonToolsDlgSM2KEY::OnBnClickedRadio3()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelPRV = E_INPUT_TYPE_HEX;
}


void CommonToolsDlgSM2KEY::OnBnClickedRadio4()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelXY = E_INPUT_TYPE_FILE;
}


void CommonToolsDlgSM2KEY::OnBnClickedRadio5()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelXY = E_INPUT_TYPE_CHAR;
}


void CommonToolsDlgSM2KEY::OnBnClickedRadio6()
{
	// TODO: ÔÚ´ËÌí¼Ó¿Ø¼þÍ¨Öª´¦Àí³ÌÐò´úÂë
	m_iSelXY = E_INPUT_TYPE_HEX;
}
