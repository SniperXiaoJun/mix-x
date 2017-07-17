
#include <Windows.h>
#include <gdiplus.h>
#include "resource.h"

class CGdiPlusBitmap
{
public:
	Gdiplus::Bitmap* m_pBitmap;

public:
	CGdiPlusBitmap() { m_pBitmap = NULL; }
	CGdiPlusBitmap(LPCWSTR pFile) { m_pBitmap = NULL; Load(pFile); }
	virtual ~CGdiPlusBitmap() { Empty(); }

	void Empty() { delete m_pBitmap; m_pBitmap = NULL; }

	bool Load(LPCWSTR pFile)
	{
		Empty();
		m_pBitmap = Gdiplus::Bitmap::FromFile(pFile);
		return m_pBitmap->GetLastStatus() == Gdiplus::Ok;
	}

	operator Gdiplus::Bitmap*() const { return m_pBitmap; }
};


class CGdiPlusBitmapResource : public CGdiPlusBitmap
{
protected:
	HGLOBAL m_hBuffer;

public:
	CGdiPlusBitmapResource() { m_hBuffer = NULL; }
	CGdiPlusBitmapResource(LPCTSTR pName, LPCTSTR pType, HMODULE hInst = NULL)
	{
		m_hBuffer = NULL; Load(pName, pType, hInst);
	}
	CGdiPlusBitmapResource(UINT id, LPCTSTR pType, HMODULE hInst = NULL)
	{
		m_hBuffer = NULL; Load(id, pType, hInst);
	}
	CGdiPlusBitmapResource(UINT id, UINT type, HMODULE hInst = NULL)
	{
		m_hBuffer = NULL; Load(id, type, hInst);
	}
	virtual ~CGdiPlusBitmapResource() { Empty(); }

	void Empty();

	bool Load(LPCTSTR pName, LPCTSTR pType = RT_RCDATA, HMODULE hInst = NULL);
	bool Load(UINT id, LPCTSTR pType = RT_RCDATA, HMODULE hInst = NULL)
	{
		return Load(MAKEINTRESOURCE(id), pType, hInst);
	}
	bool Load(UINT id, UINT type, HMODULE hInst = NULL)
	{
		return Load(MAKEINTRESOURCE(id), MAKEINTRESOURCE(type), hInst);
	}
};

inline
void CGdiPlusBitmapResource::Empty()
{
	CGdiPlusBitmap::Empty();
	if (m_hBuffer)
	{
		::GlobalUnlock(m_hBuffer);
		::GlobalFree(m_hBuffer);
		m_hBuffer = NULL;
	}
}

inline
bool CGdiPlusBitmapResource::Load(LPCTSTR pName, LPCTSTR pType, HMODULE hInst)
{
	Empty();

	HRSRC hResource = ::FindResource(hInst, pName, pType);
	if (!hResource)
		return false;

	DWORD imageSize = ::SizeofResource(hInst, hResource);
	if (!imageSize)
		return false;

	const void* pResourceData = ::LockResource(::LoadResource(hInst, hResource));
	if (!pResourceData)
		return false;

	m_hBuffer = ::GlobalAlloc(GMEM_MOVEABLE, imageSize);
	if (m_hBuffer)
	{
		void* pBuffer = ::GlobalLock(m_hBuffer);
		if (pBuffer)
		{
			CopyMemory(pBuffer, pResourceData, imageSize);

			IStream* pStream = NULL;
			if (::CreateStreamOnHGlobal(m_hBuffer, FALSE, &pStream) == S_OK)
			{
				m_pBitmap = Gdiplus::Bitmap::FromStream(pStream);
				pStream->Release();
				if (m_pBitmap)
				{
					if (m_pBitmap->GetLastStatus() == Gdiplus::Ok)
						return true;

					delete m_pBitmap;
					m_pBitmap = NULL;
				}
			}
			::GlobalUnlock(m_hBuffer);
		}
		::GlobalFree(m_hBuffer);
		m_hBuffer = NULL;
	}
	return false;
}

int main()
{
	HINSTANCE hResInstance;
	HRSRC     hResLocation;
	HGLOBAL   hResResource;


	Gdiplus::Bitmap* pBitmap = NULL;

	if ((hResInstance = GetModuleHandle(NULL)))
	{

		CGdiPlusBitmapResource* m_image = new CGdiPlusBitmapResource();
		m_image->Load(IDB_PNG1, "PNG", GetModuleHandle(0));

		if ((hResLocation = FindResource(hResInstance, MAKEINTRESOURCE(IDB_PNG1), "PNG")))
		{
			if ((hResResource = LoadResource(hResInstance, hResLocation)))
			{
				LPVOID  lpRes = LockResource(hResResource);
				DWORD   nBufSize = SizeofResource(hResInstance, hResLocation);
				HGLOBAL pResBuffer = GlobalAlloc(GMEM_MOVEABLE, nBufSize);

				if (lpRes && nBufSize && pResBuffer)
				{
					void* pBuffer = GlobalLock(pResBuffer);

					if (pBuffer)
					{
						CopyMemory(pBuffer, lpRes, nBufSize);
						IStream* pIStream = NULL;

						if (CreateStreamOnHGlobal(pResBuffer, FALSE, &pIStream) == S_OK)
						{
							Gdiplus::Image *image = Gdiplus::Image::FromStream(pIStream);

							pBitmap = Gdiplus::Bitmap::FromStream(pIStream);
							pIStream->Release();
						}

						GlobalUnlock(pBuffer);
					}

					GlobalFree(pResBuffer);
					UnlockResource(hResResource);
				}
			}
		}
	}

	// Löschen, wenn das Bitmap nicht mehr gebraucht wird

	if (pBitmap)
	{
		delete pBitmap;
	}

}