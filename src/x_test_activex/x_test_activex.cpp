#include "objbase.h"
#include "atlcomcli.h"
#include "limits"
#include <Windows.h>
#import "C:/Windows/SysWOW64/msscript.ocx" no_namespace

extern "C" { typedef HRESULT(__stdcall *FuncDllGetClassObject)(REFCLSID rclsid, REFIID riid, LPVOID * ppv); }


struct IScriptControl;
int main(int argc, char * argv[])
{
	try
	{
		::CoInitialize(NULL);
		HMODULE h = ::LoadLibrary("msscript.ocx");
		if (h == NULL)return 0;
		FuncDllGetClassObject func = (FuncDllGetClassObject)::GetProcAddress(h, "DllGetClassObject");
		if (func == NULL)return 0;
		IClassFactory *pFactory = NULL;
		func(__uuidof (ScriptControl), IID_IClassFactory, (void**)&pFactory);
		if (pFactory == NULL)return 0;
		IScriptControl *pScript = NULL;

		IID id;//=__uuidof(IScriptControl);  
		id.Data1 = 0x0e59f1d3;
		id.Data2 = 0X1fbe;
		id.Data3 = 0X11d0;

		id.Data4[0] = 0X8f;
		id.Data4[1] = 0Xf2;
		id.Data4[2] = 0X00;
		id.Data4[3] = 0Xa0;
		id.Data4[4] = 0Xd1;
		id.Data4[5] = 0X00;
		id.Data4[6] = 0X38;
		id.Data4[7] = 0Xbc;

		pFactory->CreateInstance(NULL, id, (void**)&pScript);
		pFactory->Release();

		pScript->put_AllowUI(VARIANT_FALSE);
		pScript->PutLanguage(L"JScript");

		_variant_t v = pScript->Eval("1+2+3+4+5");

		int i = pScript->Release();

		::FreeLibrary(h);
		::CoUninitialize();
		return 0;
	}
	catch (...)
	{
		//::FreeLibrary(h);   
		::CoUninitialize();
	}


	return 0;
}
