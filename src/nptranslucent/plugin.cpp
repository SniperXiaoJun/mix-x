#include <windowsx.h>
#include "plugin.h"
#include "PluginObject.h"
#include "resource.h"
//#include "DemoBackDialog.h"

CPlugin::CPlugin(NPP pNPInstance) :
	m_pNPInstance(pNPInstance),
	m_pNPStream(NULL),
	m_bInitialized(false),
	m_pScriptableObject(NULL)
{
	m_hWnd = NULL;
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

	HDC hDC = GetDC(m_hWnd);     //获得系统绘图设备  

	HDC memDC = CreateCompatibleDC(0);  //创建辅助绘图设备  

	HBITMAP bmpBack = CreateCompatibleBitmap(hDC, m_Width, m_Height);//创建掩码位图（画布）  
	SelectObject(memDC, bmpBack);    //将画布贴到绘图设备上  

	HPEN penBack = CreatePen(PS_SOLID, 1, RGB(255, 0, 255));//创建画笔  
	SelectObject(memDC, penBack);    //将画笔选到绘图设备上  

	HBRUSH brushBack = CreateSolidBrush(RGB(255, 255, 255));//创建画刷  
	SelectObject(memDC, brushBack);  //将画刷选到绘图设备上  

									 //擦除背景  
	RECT rcClient;//区域结构  
	GetClientRect(m_hWnd, &rcClient);//获得客户区域  
	HBRUSH brushTemp = (HBRUSH)GetStockObject(WHITE_BRUSH);//获得库存物体，白色画刷。  
	FillRect(memDC, &rcClient, brushTemp);//填充客户区域。  
										  //////////////////////////////////////////////////////////////////////////      
	HBRUSH brushObj = CreateSolidBrush(RGB(0, 255, 0));//创建物体画刷  
													   //绘制维网格，矩形画法。  
	int dw = 30;
	int rows = m_Width / dw;
	int cols = m_Height / dw;
	for (int r = 0; r<rows; ++r)
	{
		for (int c = 0; c<cols; ++c)
		{
			if (r == c)
			{
				SelectObject(memDC, brushObj);
			}
			else
			{
				SelectObject(memDC, brushBack);
			}
			Rectangle(memDC, c*dw, r*dw, (c + 1)*dw, (r + 1)*dw);
		}
	}

	DeleteObject(brushObj);
	//////////////////////////////////////////////////////////////////////////  
	BitBlt(hDC, 0, 0, m_Width, m_Height, memDC, 0, 0, SRCCOPY);//复制到系统设备上显示  
	DeleteObject(penBack);  //释放画笔资源  
	DeleteObject(brushBack);//释放画刷资源  
	DeleteObject(bmpBack);  //释放位图资源  
	DeleteDC(memDC);        //释放辅助绘图设备  
	ReleaseDC(m_hWnd, hDC);   //归还系统绘图设备  

	m_bInitialized = true;
	return true;
}

void CPlugin::shut()
{
	// subclass it back
	SubclassWindow(m_hWnd, lpOldProc);
	m_hWnd = NULL;
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
	return "1.1.1.1";
}

static LRESULT CALLBACK PluginWinProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc(hWnd, msg, wParam, lParam);
}
