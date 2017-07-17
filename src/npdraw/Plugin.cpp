#include "plugin.h"
#include "PluginObject.h"
#include "resource.h"

CPlugin::CPlugin(NPP pInstance):
m_pInstance(pInstance),
m_bInitialized(false),
m_pWindow(NULL),
m_pScriptableObject(NULL)
{
	// 创建对象
	if (m_pScriptableObject == NULL) 
	{
		m_pScriptableObject = NPN_CreateObject(m_pInstance, &objectClass);
	}
}

CPlugin::~CPlugin()
{	
	// 释放对象的引用计数
	if (m_pScriptableObject != NULL)
	{
		NPN_ReleaseObject(m_pScriptableObject);
	}
}

NPBool CPlugin::init(NPWindow *pWindow)
{
	m_pWindow = pWindow;
	m_bInitialized = true;
	
	return true;
}

void CPlugin::shut()
{
	m_bInitialized = false;
}

NPBool CPlugin::isInitialized()
{
	return m_bInitialized;
}

NPObject* CPlugin::GetScriptableObject()
{
	// 增加对象的引用计数
	if (m_pScriptableObject != NULL)
	{
		NPN_RetainObject(m_pScriptableObject);
	}

	return m_pScriptableObject;
}


bool LoadBitmapFromPNG(UINT uResourceID,
	Gdiplus::Bitmap** ppBitmapOut, HINSTANCE hInstance /*= NULL*/)
{
	bool bRet = false;

	if (!hInstance)
		hInstance = GetModuleHandleA("npdraw.dll");


	HRSRC hResourceHandle = ::FindResource(
		hInstance, MAKEINTRESOURCE(uResourceID), L"PNG");
	if (0 == hResourceHandle)
	{
		return bRet;
	}

	DWORD nImageSize = ::SizeofResource(hInstance, hResourceHandle);
	if (0 == nImageSize)
	{
		return bRet;
	}

	HGLOBAL hResourceInstance = ::LoadResource(hInstance, hResourceHandle);
	if (0 == hResourceInstance)
	{
		return bRet;
	}

	const void* pResourceData = ::LockResource(hResourceInstance);
	if (0 == pResourceData)
	{
		FreeResource(hResourceInstance);
		return bRet;
	}

	HGLOBAL hBuffer = ::GlobalAlloc(GMEM_MOVEABLE, nImageSize);
	if (0 == hBuffer)
	{
		FreeResource(hResourceInstance);
		return bRet;
	}

	void* pBuffer = ::GlobalLock(hBuffer);
	if (0 != pBuffer)
	{
		CopyMemory(pBuffer, pResourceData, nImageSize);

		{
			char buffer[1024] = { 0 };

			sprintf(buffer, "*nImageSize= %d", nImageSize);
			MessageBoxA(NULL, buffer, "info", 0);
		}

		IStream* pStream = 0;
		if (S_OK == ::CreateStreamOnHGlobal(hBuffer, FALSE, &pStream))
		{
			*ppBitmapOut = new Gdiplus::Bitmap(pStream);
			{
				char buffer[1024] = { 0 };

				sprintf(buffer, "*ppBitmapOut= %d", *ppBitmapOut);
				MessageBoxA(NULL, buffer, "info", 0);
			}

			/*Gdiplus::Bitmap::GetLastStatus();*/

			pStream->Release();
			bRet = true;
		}
		::GlobalUnlock(hBuffer);
	}
	::GlobalFree(hBuffer);

	UnlockResource(hResourceInstance);
	FreeResource(hResourceInstance);

	return bRet;
}

int16_t CPlugin::handleEvent(void *pEvent)
{
	NPEvent* pNPEnent = (NPEvent*)pEvent;

	switch (pNPEnent->event)
	{
	case WM_PAINT:
	{
		HDC hDC = NULL;
		HDC hMemDC = NULL;
		HBITMAP hMemBitmap = NULL;
		HBRUSH hBackBrush = NULL;
		int nSealWidth = 0;
		int nSealHeigth = 0;
		RECT rcSealRect = { 0 };

		BOOL bResult = FALSE;
		Gdiplus::Status enStatus = Gdiplus::GenericError;

		hDC = (HDC)pNPEnent->wParam;

		bResult = LoadBitmapFromPNG(IDB_PNG1,&m_pSealImage, NULL);

		{
			char buffer[1024] = { 0 };

			sprintf(buffer, "bResult= %d", bResult);
			MessageBoxA(NULL, buffer, "info", 0);
		}

		{
			char buffer[1024] = { 0 };

			sprintf(buffer, "m_pSealImage= %d", m_pSealImage);
			MessageBoxA(NULL, buffer, "info", 0);
		}

		nSealWidth = m_pSealImage->GetWidth();
		nSealHeigth = m_pSealImage->GetHeight();

		{
			char buffer[1024] = { 0 };

			sprintf(buffer, "m_pSealImage= %d", m_pSealImage);
			MessageBoxA(NULL, buffer, "info", 0);
		}

		{
			char buffer[1024] = { 0 };

			sprintf(buffer, "nSealWidth= %d", nSealWidth);
			MessageBoxA(NULL, buffer, "info", 0);
		}

		{
			char buffer[1024] = { 0 };

			sprintf(buffer, "nSealHeigth= %d", nSealHeigth);
			MessageBoxA(NULL, buffer, "info", 0);
		}

		rcSealRect.left = 0;
		rcSealRect.top = 0;
		rcSealRect.right = 0 + nSealWidth;
		rcSealRect.bottom = 0 + nSealHeigth;

		hMemDC = ::CreateCompatibleDC(hDC);
		hMemBitmap = ::CreateCompatibleBitmap(hDC, nSealWidth, nSealHeigth);
		::SelectObject(hMemDC, hMemBitmap);

		{
			char buffer[1024] = { 0 };

			sprintf(buffer, "hMemDC= %d", hMemDC);
			MessageBoxA(NULL, buffer, "info", 0);
		}

		// Draw background
		hBackBrush = ::CreateSolidBrush(RGB(255, 255, 255));
		::FillRect(hMemDC, &rcSealRect, hBackBrush);
		::DeleteObject(hBackBrush);

		// Draw Seal image
		Gdiplus::Graphics GdiplusGraphics(hMemDC);
		Gdiplus::Rect destRect(0, 0, nSealWidth, nSealHeigth);
		enStatus = GdiplusGraphics.DrawImage(m_pSealImage,
			destRect,
			0, 0, nSealWidth, nSealHeigth,
			Gdiplus::UnitPixel,
			NULL, NULL, NULL);

		{
			char buffer[1024] = { 0 };

			sprintf(buffer, "enStatus= %d", enStatus);
			MessageBoxA(NULL, buffer, "info", 0);
		}

		// Copy memory DC to the drawable.
		bResult = StretchBlt(hDC,
			m_pWindow->x, m_pWindow->y, nSealWidth, nSealHeigth,
			hMemDC,
			0, 0, nSealWidth, nSealHeigth,
			SRCAND); //Use SRCAND to achieve a transparent effect.

		{
			char buffer[1024] = { 0 };

			sprintf(buffer, "bResult= %d", bResult);
			MessageBoxA(NULL, buffer, "info", 0);
		}

		break;
	}
	default:
		return false;
	}

	return true;
}