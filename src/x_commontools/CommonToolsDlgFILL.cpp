// CommonToolsDlgFILL.cpp : 实现文件
//

#include "stdafx.h"
#include "CommonTools.h"
#include "CommonToolsDlgFILL.h"
#include "afxdialogex.h"
#include "common.h"
#include "encode_switch.h"

// CommonToolsDlgFILL 对话框

IMPLEMENT_DYNAMIC(CommonToolsDlgFILL, CDialogEx)

CommonToolsDlgFILL::CommonToolsDlgFILL(CWnd* pParent /*=NULL*/)
	: CDialogEx(CommonToolsDlgFILL::IDD, pParent)
{

}

CommonToolsDlgFILL::~CommonToolsDlgFILL()
{
}

void CommonToolsDlgFILL::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT1, editInput);
	DDX_Control(pDX, IDC_EDIT4, editFill);
	DDX_Control(pDX, IDC_EDIT2, editOutput);
}


BEGIN_MESSAGE_MAP(CommonToolsDlgFILL, CDialogEx)
	ON_BN_CLICKED(IDOK, &CommonToolsDlgFILL::OnBnClickedOk)
END_MESSAGE_MAP()


// CommonToolsDlgFILL 消息处理程序


void CommonToolsDlgFILL::OnBnClickedOk()
{
	unsigned char data_value_in[BUFFER_LEN_1K * 4] = { 0 };
	unsigned char data_value_fill[BUFFER_LEN_1K * 4] = { 0 };

	unsigned char * data_value_out = NULL;

	wchar_t data_value_tmp[BUFFER_LEN_1K * 4] = { 0 };

	int length = 0;
	int pos = 0;
	int i = 0;

	editInput.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	memcpy(data_value_in, utf8_encode(data_value_tmp).c_str(), strlen(utf8_encode(data_value_tmp).c_str()));
	editFill.GetWindowText(data_value_tmp,BUFFER_LEN_1K * 4);
	memcpy(data_value_fill, utf8_encode(data_value_tmp).c_str(), strlen(utf8_encode(data_value_tmp).c_str()));

	length = strlen((char *)data_value_in) + strlen((char *)data_value_in)/2 * strlen((char *)data_value_fill);

	data_value_out = (unsigned char *)malloc(length*2 + 2);

	memset(data_value_out, 0, length*2 + 2);

	pos = 0;

	for(i = 0; i <  strlen((char *)data_value_in)/2 ; i++)
	{
		memcpy(data_value_out+pos, data_value_fill, strlen((char *)data_value_fill));
		pos += strlen((char *)data_value_fill);
		data_value_out[pos] = data_value_in[i*2];
		pos += 1;
		data_value_out[pos] = data_value_in[i*2+1];
		pos += 1;
	}

	editOutput.SetWindowText(utf8_decode((char *)data_value_out).c_str());

	free(data_value_out);
}
