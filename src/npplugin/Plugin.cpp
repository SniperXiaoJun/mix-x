#include "plugin.h"
#include "PluginObject.h"




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

int16_t CPlugin::handleEvent(void *pEvent)
{
	return 0;
}