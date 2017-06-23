
#include<iostream>
#include <fstream>
#include<string>
#include<io.h>
#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <smb_qtui.h>
#include <smb_cs.h>

int main(int argc, char * argv[])
{
	unsigned int ulCertLen = 0;
	unsigned char pbCert[1024] = { 0 };

	SMB_CS_SetPath("smb_cs.db");
	SMB_CS_Init();

	FILE * file = fopen("d:/show.cer", "r+b");

	if (file)
	{
		int pos = 0;
		do
		{
			pos = fread(pbCert + ulCertLen, 1, 8, file);
			ulCertLen += pos;
		} while ((pos>0));
		fclose(file);
	}

	printf("%d", ulCertLen);

	SMB_QTUI_ShowUI(pbCert, ulCertLen);

	return 0;
}