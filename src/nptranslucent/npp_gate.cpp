/* -*- Mode: C++; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* ***** BEGIN LICENSE BLOCK *****
 * Version: NPL 1.1/GPL 2.0/LGPL 2.1
 *
 * The contents of this file are subject to the Netscape Public License
 * Version 1.1 (the "License"); you may not use this file except in
 * compliance with the License. You may obtain a copy of the License at
 * http://www.mozilla.org/NPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is mozilla.org code.
 *
 * The Initial Developer of the Original Code is 
 * Netscape Communications Corporation.
 * Portions created by the Initial Developer are Copyright (C) 1998
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *
 * Alternatively, the contents of this file may be used under the terms of
 * either the GNU General Public License Version 2 or later (the "GPL"), or 
 * the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
 * in which case the provisions of the GPL or the LGPL are applicable instead
 * of those above. If you wish to allow use of your version of this file only
 * under the terms of either the GPL or the LGPL, and not to allow others to
 * use your version of this file under the terms of the NPL, indicate your
 * decision by deleting the provisions above and replace them with the notice
 * and other provisions required by the GPL or the LGPL. If you do not delete
 * the provisions above, a recipient may use your version of this file under
 * the terms of any one of the NPL, the GPL or the LGPL.
 *
 * ***** END LICENSE BLOCK ***** */

////////////////////////////////////////////////////////////
//
// Implementation of plugin entry points (NPP_*)
// most are just empty stubs for this particular plugin 
//
#include "plugin.h"

char*
NPP_GetMIMEDescription(void)
{
  return "application/mozilla-npruntime-scriptable-plugin:.foo:Scriptability Demo Plugin";
}



NPError NPP_Initialize(void)
{
  return NPERR_NO_ERROR;
}

void NPP_Shutdown(void)
{
}

// here the plugin creates an instance of our CPlugin object which 
// will be associated with this newly created plugin instance and 
// will do all the neccessary job
NPError NPP_New(NPMIMEType pluginType,
                NPP instance,
                uint16_t mode,
                int16_t argc,
                char* argn[],
                char* argv[],
                NPSavedData* saved)
{   
  if(instance == NULL)
    return NPERR_INVALID_INSTANCE_ERROR;

  NPError rv = NPERR_NO_ERROR;

  CPlugin * pPlugin = new CPlugin(instance);
  if(pPlugin == NULL)
    return NPERR_OUT_OF_MEMORY_ERROR;
  for(int i=0;i<argc;i++)
  {
	  if(strcmp(argn[i],"width")==0)
	  {
		  pPlugin->m_Width=atoi(argv[i]);
	  }

	  if(strcmp(argn[i],"height")==0)
	  {
		  pPlugin->m_Height=atoi(argv[i]);
	  }
  }
  instance->pdata = (void *)pPlugin;

  NPN_SetValue(instance, NPPVpluginWindowBool, NULL);

  return rv;
}

// here is the place to clean up and destroy the CPlugin object
NPError NPP_Destroy (NPP instance, NPSavedData** save)
{
  if(instance == NULL)
    return NPERR_INVALID_INSTANCE_ERROR;

  NPError rv = NPERR_NO_ERROR;

  CPlugin * pPlugin = (CPlugin *)instance->pdata;
  if(pPlugin != NULL) {
    pPlugin->shut();
    delete pPlugin;
  }
  return rv;
}

// during this call we know when the plugin window is ready or
// is about to be destroyed so we can do some gui specific
// initialization and shutdown
NPError NPP_SetWindow (NPP instance, NPWindow* pNPWindow)
{    
  if(instance == NULL)
    return NPERR_INVALID_INSTANCE_ERROR;

  NPError rv = NPERR_NO_ERROR;

  if(pNPWindow == NULL)
    return NPERR_GENERIC_ERROR;

  CPlugin * pPlugin = (CPlugin *)instance->pdata;

  if(pPlugin == NULL) 
    return NPERR_GENERIC_ERROR;

  // window just created
  if(!pPlugin->isInitialized() && (pNPWindow->window != NULL)) { 
    if(!pPlugin->init(pNPWindow)) {
      delete pPlugin;
      pPlugin = NULL;
      return NPERR_MODULE_LOAD_FAILED_ERROR;
    }
  }

  // window goes away
  if((pNPWindow->window == NULL) && pPlugin->isInitialized())
    return NPERR_NO_ERROR;

  // window resized
  if(pPlugin->isInitialized() && (pNPWindow->window != NULL))
    return NPERR_NO_ERROR;

  // this should not happen, nothing to do
  if((pNPWindow->window == NULL) && !pPlugin->isInitialized())
    return NPERR_NO_ERROR;

  return rv;
}

NPError	NPP_GetValue(NPP instance, NPPVariable variable, void *value)
{
  if(instance == NULL)
    return NPERR_INVALID_INSTANCE_ERROR;

  NPError rv = NPERR_NO_ERROR;

  if(instance == NULL)
    return NPERR_GENERIC_ERROR;

  CPlugin * plugin = (CPlugin *)instance->pdata;
  if(plugin == NULL)
    return NPERR_GENERIC_ERROR;

  switch (variable) {
  case NPPVpluginNameString:
    *((char **)value) = "NPRuntimeTest";
    break;
  case NPPVpluginDescriptionString:
    *((char **)value) = "NPRuntime scriptability API test plugin";
    break;

  // Here we indicate that the plugin is scriptable. See this page for details:
  // https://developer.mozilla.org/en/Gecko_Plugin_API_Reference/Scripting_plugins
  case NPPVpluginScriptableNPObject:
    *(NPObject **)value = plugin->GetScriptableObject();
    break;
  default:
    rv = NPERR_GENERIC_ERROR;
  }

  return rv;
}

NPError NPP_NewStream(NPP instance,
                      NPMIMEType type,
                      NPStream* stream, 
                      NPBool seekable,
                      uint16_t* stype)
{
  if(instance == NULL)
    return NPERR_INVALID_INSTANCE_ERROR;

  NPError rv = NPERR_NO_ERROR;
  return rv;
}

int32_t NPP_WriteReady (NPP instance, NPStream *stream)
{
  if(instance == NULL)
    return NPERR_INVALID_INSTANCE_ERROR;

  int32_t rv = 0x0fffffff;
  return rv;
}

int32_t NPP_Write (NPP instance, NPStream *stream, int32_t offset, int32_t len, void *buffer)
{   
  if(instance == NULL)
    return NPERR_INVALID_INSTANCE_ERROR;

  int32_t rv = len;
  return rv;
}

NPError NPP_DestroyStream (NPP instance, NPStream *stream, NPError reason)
{
  if(instance == NULL)
    return NPERR_INVALID_INSTANCE_ERROR;

  NPError rv = NPERR_NO_ERROR;
  return rv;
}

void NPP_StreamAsFile (NPP instance, NPStream* stream, const char* fname)
{
  if(instance == NULL)
    return;
}

void NPP_Print (NPP instance, NPPrint* printInfo)
{
  if(instance == NULL)
    return;
}

void NPP_URLNotify(NPP instance, const char* url, NPReason reason, void* notifyData)
{
  if(instance == NULL)
    return;
}

NPError NPP_SetValue(NPP instance, NPNVariable variable, void *value)
{
  if(instance == NULL)
    return NPERR_INVALID_INSTANCE_ERROR;

  NPError rv = NPERR_NO_ERROR;
  return rv;
}

int16_t	NPP_HandleEvent(NPP instance, void* event)
{
  if(instance == NULL)
    return 0;

  int16_t rv = 0;
  CPlugin * pPlugin = (CPlugin *)instance->pdata;
  if (pPlugin)
  {
	  rv = pPlugin->handleEvent(event);
  }

  if (true)
  {
	  switch (((NPEvent*)event)->event) {
	  case WM_PAINT:
	  {
		  HDC hDC = (HDC)((NPEvent*)event)->wParam;
		  RECT * drc = (RECT *)((NPEvent*)event)->lParam;
		  HDC memDC = CreateCompatibleDC(0);  //创建辅助绘图设备  

		  int m_Width = drc->right - drc->left;
		  int m_Height = drc->top - drc->bottom;

		  if (m_Width < 0)
		  {
			  m_Width = -m_Width;
		  }

		  if (m_Height < 0)
		  {
			  m_Height = -m_Height;
		  }

		  HBITMAP bmpBack = CreateCompatibleBitmap(hDC, m_Width, m_Height);//创建掩码位图（画布）  
		  SelectObject(memDC, bmpBack);    //将画布贴到绘图设备上  

		  HPEN penBack = CreatePen(PS_SOLID, 3, RGB(255, 0, 255));//创建画笔  
		  SelectObject(memDC, penBack);    //将画笔选到绘图设备上  

		  HBRUSH brushBack = CreateSolidBrush(RGB(255, 255, 255));//创建画刷  
		  SelectObject(memDC, brushBack);  //将画刷选到绘图设备上  

										   //擦除背景  

		  HBRUSH brushTemp = (HBRUSH)GetStockObject(BLACK_BRUSH);//获得库存物体，白色画刷。  
		  FillRect(memDC, drc, brushTemp);//填充客户区域。  
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
		  // ReleaseDC(m_hWnd, hDC);   //归还系统绘图设备  
	  }
	  break;
	  default:
		  break;
	  }
  }

  return rv;
}

NPObject *NPP_GetScriptableInstance(NPP instance)
{
  if(!instance)
    return 0;

  NPObject *npobj = 0;
  CPlugin * pPlugin = (CPlugin *)instance->pdata;
  if (!pPlugin)
    npobj = pPlugin->GetScriptableObject();

  return npobj;
}
