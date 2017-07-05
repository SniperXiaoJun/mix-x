
#include <Windows.h>
#include <string>

using namespace std;

BOOL IsRunAsAdmin()
{
	BOOL fIsRunAsAdmin = FALSE;
	DWORD dwError = ERROR_SUCCESS;
	PSID pAdministratorsGroup = NULL;

	// Allocate and initialize a SID of the administrators group.  
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	if (!AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&pAdministratorsGroup))
	{
		dwError = GetLastError();
		goto Cleanup;
	}

	// Determine whether the SID of administrators group is enabled in   
	// the primary access token of the process.  
	if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin)) {
		dwError = GetLastError();
		goto Cleanup;
	}

Cleanup:
	// Centralized cleanup for all allocated resources.  
	if (pAdministratorsGroup) {
		FreeSid(pAdministratorsGroup);
		pAdministratorsGroup = NULL;
	}

	// Throw the error if something failed in the function.  
	if (ERROR_SUCCESS != dwError) {
		throw dwError;
	}

	return fIsRunAsAdmin;
}

BOOL ElevateCurrentProcess(string strPath,string strParameters)
{
	// Launch itself as administrator.  
	SHELLEXECUTEINFO sei = { 0 };
	sei.lpVerb = "runas";
	sei.lpFile = strPath.c_str();
	sei.lpParameters = strParameters.c_str();
	//  sei.hwnd = hWnd;  
	sei.nShow = SW_SHOWNORMAL;
	sei.cbSize = sizeof(SHELLEXECUTEINFO);
	sei.fMask = SEE_MASK_NOCLOSEPROCESS;
	sei.hwnd = NULL;
	sei.lpDirectory = NULL;
	sei.hInstApp = NULL;

	if (!ShellExecuteEx(&sei)) {
		DWORD dwStatus = GetLastError();
		if (dwStatus == ERROR_CANCELLED) {
			return FALSE;
		}
		else if (dwStatus == ERROR_FILE_NOT_FOUND) {
			return FALSE;
		}
		return FALSE;
	}

	DWORD res = WaitForSingleObject(sei.hProcess, 30000);

	if (WAIT_OBJECT_0 == res)
	{
		return TRUE;
	}
	else if (WAIT_TIMEOUT == res)
	{
		TerminateProcess(sei.hProcess, 0);
		return FALSE;
	}
	else
	{
		TerminateProcess(sei.hProcess, 0);
		return FALSE;
	}

	return TRUE;

}

int main()
{
	if (!IsRunAsAdmin())
	{
		printf("IsRunAsAdmin false!\n");

		if (!ElevateCurrentProcess("D:\\Program Files\\VMware-Workstation\\VMware\\vmware.exe",""))
		{
			printf("ElevateCurrentProcess fail!\n");
		}
		else
		{
			printf("ElevateCurrentProcess success!\n");
		}
	}
	else
	{
		printf("IsRunAsAdmin true!\n");
	}

	return getchar();
}





