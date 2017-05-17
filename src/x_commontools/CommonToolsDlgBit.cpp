// CommonToolsDlgBit.cpp : 实现文件
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgBit.h"
#include "afxdialogex.h"
#include "common.h"
#include "encode_switch.h"
#include "o_all_func_def.h"


// CommonToolsDlgBit 对话框

IMPLEMENT_DYNAMIC(CommonToolsDlgBit, CDialogEx)

CommonToolsDlgBit::CommonToolsDlgBit(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgBit::IDD, pParent)
{

}

CommonToolsDlgBit::~CommonToolsDlgBit()
{
}

void CommonToolsDlgBit::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_COMBO1, comboBoxType);
	DDX_Control(pDX, IDC_EDIT3, edit_A);
	DDX_Control(pDX, IDC_EDIT1, edit_B);
	DDX_Control(pDX, IDC_EDIT2, edit_Out);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgBit, CDialogEx)
	ON_BN_CLICKED(IDCANCEL, &CommonToolsDlgBit::OnBnClickedCancel)
END_MESSAGE_MAP()


// CommonToolsDlgBit 消息处理程序


void CommonToolsDlgBit::OnBnClickedCancel()
{
	unsigned char data_value_a[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_b[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_out[BUFFER_LEN_1K * 4] = {0};

	unsigned char data_value_out_hex[BUFFER_LEN_1K * 4] = { 0 };

	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = {0};
	unsigned char data_value_type[BUFFER_LEN_1K * 4] = {0};

	unsigned int data_len_a = BUFFER_LEN_1K * 4;
	unsigned int data_len_b = BUFFER_LEN_1K * 4;
	unsigned int data_len_out = BUFFER_LEN_1K * 4;
	unsigned int data_len_out_hex = BUFFER_LEN_1K * 4;


	comboBoxType.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	memcpy(data_value_type, utf8_encode(data_value_tmp).c_str(), strlen(utf8_encode(data_value_tmp).c_str()));

	edit_A.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(),strlen(utf8_encode(data_value_tmp).c_str()), (unsigned char *)data_value_a,&data_len_a);

	// privkey
	edit_B.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	OPF_Str2Bin(utf8_encode(data_value_tmp).c_str(), strlen(utf8_encode(data_value_tmp).c_str()), (unsigned char *)data_value_b,&data_len_b);

	if(0 == strcmp("~", (char *)data_value_type))
	{
		int i = 0;

		for (i = 0; i < data_len_a && i <data_len_b; i++)
		{
			data_value_out[i] = ~data_value_a[i];
		}

		data_len_out = i;
	}
	else if(0 == strcmp("&", (char *)data_value_type))
	{
		int i = 0;

		for (i = 0; i < data_len_a && i <data_len_b; i++)
		{
			data_value_out[i] = data_value_a[i] & data_value_b[i];
		}

		data_len_out = i;
	}
	else if(0 == strcmp("^", (char *)data_value_type))
	{
		int i = 0;

		for (i = 0; i < data_len_a && i <data_len_b; i++)
		{
			data_value_out[i] = data_value_a[i] ^ data_value_b[i];
		}

		data_len_out = i;
	}
	else if(0 == strcmp("|", (char *)data_value_type))
	{
		int i = 0;

		for (i = 0; i < data_len_a && i <data_len_b; i++)
		{
			data_value_out[i] = data_value_a[i] | data_value_b[i];
		}

		data_len_out = i;
	}

	data_len_out_hex = BUFFER_LEN_1K *4;

	OPF_Bin2Str( (unsigned char *)data_value_out,data_len_out, (char *)data_value_out_hex,&data_len_out_hex);

	edit_Out.SetWindowText(utf8_decode((char *)data_value_out_hex).c_str());

	//CDialogEx::OnCancel();
}


BOOL CommonToolsDlgBit::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	int pos = -1;

	pos = comboBoxType.InsertString(pos + 1,L"&");

	pos = comboBoxType.InsertString(pos + 1, L"|");

	pos = comboBoxType.InsertString(pos + 1, L"~");

	pos = comboBoxType.InsertString(pos + 1, L"^");

	comboBoxType.SetCurSel(0);

	return TRUE;  // return TRUE unless you set the focus to a control
	// ??: OCX ?????? FALSE
}
