#include <windowsx.h>
#include "plugin.h"
#include "PluginObject.h"

CPlugin::CPlugin(NPP pNPInstance) :
	m_pNPInstance(pNPInstance),
	m_pNPStream(NULL),
	m_bInitialized(false),
	m_pScriptableObject(NULL)
{
	m_hWnd = NULL;
	Dlg =  NULL;
}

CPlugin::~CPlugin()
{
  if (m_pScriptableObject)
    NPN_ReleaseObject(m_pScriptableObject);
}

static LRESULT CALLBACK PluginWinProc(HWND, UINT, WPARAM, LPARAM);
static WNDPROC lpOldProc = NULL;

NPBool CPlugin::init(NPWindow* pNPWindow)
{
	if(pNPWindow == NULL)
		return false;
	m_hWnd = (HWND)pNPWindow->window;
	if(m_hWnd == NULL)
		return false;

	lpOldProc = SubclassWindow(m_hWnd, (WNDPROC)PluginWinProc);
	SetWindowLongPtr(m_hWnd, GWLP_USERDATA, (LONG_PTR)this);
	m_Window = pNPWindow;

	Dlg=new DLDialog();
	Dlg->Create(GetModuleHandleA("npsafeinput.dll"),MAKEINTRESOURCE(IDD_INPUT),m_hWnd);
	Dlg->ShowDlg();
	SetWindowPos(Dlg->hWnd,HWND_TOPMOST,0,0,m_Width,m_Height,SWP_NOZORDER|SWP_NOMOVE);

	m_bInitialized = true;
	return true;
}

void CPlugin::shut()
{
	// subclass it back
	SubclassWindow(m_hWnd, lpOldProc);
	m_hWnd = NULL;
	Dlg = NULL;
	m_bInitialized = false;
}

NPBool CPlugin::isInitialized()
{
  return m_bInitialized;
}

int16_t CPlugin::handleEvent(void* event)
{
	return 0;
}

NPObject *
CPlugin::GetScriptableObject()
{
	if (!m_pScriptableObject) {
		m_pScriptableObject =
		NPN_CreateObject(m_pNPInstance,&objectClass);
	}

	if (m_pScriptableObject) {
		NPN_RetainObject(m_pScriptableObject);
	}

	return m_pScriptableObject;
}

char *
CPlugin::GetValue()
{
	return Dlg->GetVal();
}

const char * CPlugin::GetMac(){
	GetMacAddress *addr=new GetMacAddress();
	return addr->GetMac();
}

static LRESULT CALLBACK PluginWinProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc(hWnd, msg, wParam, lParam);
}
