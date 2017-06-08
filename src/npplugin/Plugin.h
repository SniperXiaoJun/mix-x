#pragma once
#include <pluginbase.h>

class CPlugin : public nsPluginInstanceBase
{
public:
	CPlugin(NPP pInstance);
	~CPlugin();
public:
	void shut();
	NPBool isInitialized();
	NPBool init(NPWindow* aWindow);
public:
	int16_t handleEvent(void*);
	NPObject *GetScriptableObject();
private:
	NPP m_pInstance;
	NPBool m_bInitialized;
	NPWindow *m_pWindow;
	NPObject* m_pScriptableObject;
};

