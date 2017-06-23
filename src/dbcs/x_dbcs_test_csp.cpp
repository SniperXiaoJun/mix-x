
#include<iostream>
#include <fstream>
#include<string>
#include<io.h>
#include <Windows.h>
#include <wincrypt.h>
#include <stdio.h>

using namespace std;

int main(int argc, char * argv[])
{
	HCRYPTPROV	hCryptProv = NULL;
	DWORD dwError;
	char csp_name[128] = { 0 };

	SetLastError(0);

	std::fstream _file;

	_file.open("csp.conf", ios::binary | ios::in);

	if (_file)
	{
		std::ios::pos_type length;
		unsigned int ulAlgType = 0;
		char * pbSqlData = NULL;
		int pos = 0;

		// get length of file:
		_file.seekg(0, ios::end);
		length = _file.tellg();
		_file.seekg(0, ios::beg);

		pbSqlData = new char[length];

		// read data as a block:
		_file.read(pbSqlData + pos, length);

		memcpy(csp_name,pbSqlData, length);

		delete[]pbSqlData;

		_file.close();
	}
	else
	{

	}

	printf("cspname=%s\n", csp_name);

	if (!CryptAcquireContextA(&hCryptProv, NULL,
		csp_name, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
	{
		dwError = GetLastError();
		printf("CryptAcquireContextA use CRYPT_VERIFYCONTEXT errorecode dwError=%x\n", dwError);
	}
	else
	{
		dwError = GetLastError();
		printf("CryptAcquireContextA use CRYPT_VERIFYCONTEXT successcode dwError=%x\n", dwError);

		CryptReleaseContext(hCryptProv, 0);
	}

	SetLastError(0);
	if (!CryptAcquireContextA(&hCryptProv, NULL,
		csp_name, PROV_RSA_FULL, 0))
	{
		dwError = GetLastError();
		printf("CryptAcquireContextA use 0 errorecode dwError=%x\n", dwError);
	}
	else
	{
		dwError = GetLastError();
		printf("CryptAcquireContextA use 0 successcode dwError=%x\n", dwError);
		CryptReleaseContext(hCryptProv, 0);
	}

	return getchar();
}