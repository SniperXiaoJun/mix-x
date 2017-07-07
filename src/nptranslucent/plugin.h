#include "pluginbase.h"

class CPlugin:public nsPluginInstanceBase
{
private:
	NPP m_pNPInstance;
	HWND m_hWnd; 
	NPWindow * m_Window;
	NPStream * m_pNPStream;
	NPBool m_bInitialized;
	NPObject *m_pScriptableObject;

public:
	int m_Width;
	int m_Height;

public:
	CPlugin(NPP pNPInstance);
	~CPlugin();

	NPBool init(NPWindow* pNPWindow);
	void shut();
	NPBool isInitialized();
  
	int16_t handleEvent(void* event);
	NPObject *GetScriptableObject();

	char * GetValue();
	const char * GetMac();
};