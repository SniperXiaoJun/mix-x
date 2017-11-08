
#include "smb_qtui.h"
#include "smb_dev.h"

COMMON_API unsigned int CALL_CONVENTION SMB_QTUI_ShowUI(unsigned char *pCertContent, unsigned int uiCertContentLen)
{
	return SMB_UI_ShowCert(pCertContent, uiCertContentLen);
}