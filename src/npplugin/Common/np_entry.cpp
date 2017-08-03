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

//////////////////////////////////////////////////////////////
//
// Main plugin entry point implementation
//
#include<pluginbase.h>
#include <stddef.h>
#include "../plugin.h"
#include <fstream>

#ifndef HIBYTE
#define HIBYTE(x) ((((uint32_t)(x)) & 0xff00) >> 8)
#endif

NPNetscapeFuncs NPNFuncs;

#ifdef XP_WIN

// ä¯ÀÀÆ÷»ñÈ¡ËùÓÐ¿ÉÄÜÐèÒªµ÷ÓÃµÄAPIº¯ÊýÖ¸Õë
NPError  OSCALL NP_GetEntryPoints(NPPluginFuncs *pFuncs)
{
	if(pFuncs == NULL)
	{
		return NPERR_INVALID_FUNCTABLE_ERROR;
	}
	
	if(pFuncs->size < (offsetof(NPPluginFuncs, setvalue) + sizeof(void*)))
	{
		return NPERR_INVALID_FUNCTABLE_ERROR;
	}
	
	pFuncs->newp          = NPP_New;
	pFuncs->destroy       = NPP_Destroy;
	pFuncs->setwindow     = NPP_SetWindow;
	pFuncs->newstream     = NPP_NewStream;
	pFuncs->destroystream = NPP_DestroyStream;
	pFuncs->asfile        = NPP_StreamAsFile;
	pFuncs->writeready    = NPP_WriteReady;
	pFuncs->write         = NPP_Write;
	pFuncs->print         = NPP_Print;
	pFuncs->event         = NPP_HandleEvent;
	pFuncs->urlnotify     = NPP_URLNotify;
	pFuncs->getvalue      = NPP_GetValue;
	pFuncs->setvalue      = NPP_SetValue;

	return NPERR_NO_ERROR;
}

#endif /* XP_WIN */

char *NPP_GetMIMEDescription();

char *NP_GetMIMEDescription()
{
	return NPP_GetMIMEDescription();
}

NPError NP_GetValue(void *future, NPPVariable variable, void *value)
{
	return NPP_GetValue((NPP_t *)future, variable, value);
}


HMODULE GetSelfModuleHandle()
{
	MEMORY_BASIC_INFORMATION mbi;
	return ((::VirtualQuery(GetSelfModuleHandle, &mbi, sizeof(mbi)) != 0) ? (HMODULE)mbi.AllocationBase : NULL);
}

//-----------------------------------------------------------------------------
// 开始修改方法
//-----------------------------------------------------------------------------

typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);

BOOL Is64Bit_OS()
{
	BOOL bRetVal = FALSE;
	SYSTEM_INFO si = { 0 };
	PGNSI pGNSI = (PGNSI)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetNativeSystemInfo");

	if (NULL != pGNSI)
		pGNSI(&si);
	else
		GetSystemInfo(&si);

	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
	{
		bRetVal = TRUE;
	}
	else
	{

	}
	return bRetVal;
}


unsigned int GetPathDbFileOut(char pDbPath[1024])
{
	char smb_db_path_prefix[1024] = { 0 };
	char smb_db_path[1024] = { 0 };
	int i = 0;

	GetModuleFileNameA(NULL, smb_db_path_prefix, 1024);
	for (i = strlen(smb_db_path_prefix); i > 0; i--)
	{
		if ('\\' == smb_db_path_prefix[i])
		{
			break;
		}
	}

	GetEnvironmentVariableA("APPDATA", smb_db_path, MAX_PATH);
	strcat(smb_db_path, &smb_db_path_prefix[i]);

	for (i = strlen(smb_db_path); i > 0; i--)
	{
		if ('.' == smb_db_path[i])
		{
			smb_db_path[i] = 0;
			break;
		}
	}

	strcat(smb_db_path, ".smb_cs.db");

	strcpy(pDbPath, smb_db_path);

	return 0;
}


unsigned int GetPathDbFileIn(char *pDbPath)
{
	char smb_db_path[1024] = { 0 };
	int i = 0;

	//无权限
	//GetModuleFileNameA(GetSelfModuleHandle(), smb_db_path, 1024);
	GetModuleFileNameA(NULL, smb_db_path, 1024);
	for (i = strlen(smb_db_path); i > 0; i--)
	{
		if ('\\' == smb_db_path[i])
		{
			smb_db_path[i] = '\0';
			break;
		}
	}

	if (Is64Bit_OS())
	{
		strcat(smb_db_path, "\\smb_cs.db.64");
	}
	else
	{
		strcat(smb_db_path, "\\smb_cs.db.32");
	}

	strcpy(pDbPath, smb_db_path);

	return 0;
}

// ²å¼þ²¿·ÖÒ»Ð©³õÊ¼»¯²Ù×÷
NPError OSCALL NP_Initialize(NPNetscapeFuncs* pFuncs
#ifdef XP_UNIX
              , NPPluginFuncs* pluginFuncs
#endif
              )
{
	if(pFuncs == NULL)
	{
		return NPERR_INVALID_FUNCTABLE_ERROR;
	}
	
	if(HIBYTE(pFuncs->version) > NP_VERSION_MAJOR)
	{
		return NPERR_INCOMPATIBLE_VERSION_ERROR;
	}
	
	if(pFuncs->size < sizeof(NPNetscapeFuncs))
	{
		return NPERR_INVALID_FUNCTABLE_ERROR;
	}
	

	NPNFuncs.size                    = pFuncs->size;
	NPNFuncs.version                 = pFuncs->version;
	NPNFuncs.geturlnotify            = pFuncs->geturlnotify;
	NPNFuncs.geturl                  = pFuncs->geturl;
	NPNFuncs.posturlnotify           = pFuncs->posturlnotify;
	NPNFuncs.posturl                 = pFuncs->posturl;
	NPNFuncs.requestread             = pFuncs->requestread;
	NPNFuncs.newstream               = pFuncs->newstream;
	NPNFuncs.write                   = pFuncs->write;
	NPNFuncs.destroystream           = pFuncs->destroystream;
	NPNFuncs.status                  = pFuncs->status;
	NPNFuncs.uagent                  = pFuncs->uagent;
	NPNFuncs.memalloc                = pFuncs->memalloc;
	NPNFuncs.memfree                 = pFuncs->memfree;
	NPNFuncs.memflush                = pFuncs->memflush;
	NPNFuncs.reloadplugins           = pFuncs->reloadplugins;
	NPNFuncs.getJavaEnv              = NULL;
	NPNFuncs.getJavaPeer             = NULL;
	NPNFuncs.getvalue                = pFuncs->getvalue;
	NPNFuncs.setvalue                = pFuncs->setvalue;
	NPNFuncs.invalidaterect          = pFuncs->invalidaterect;
	NPNFuncs.invalidateregion        = pFuncs->invalidateregion;
	NPNFuncs.forceredraw             = pFuncs->forceredraw;
	NPNFuncs.getstringidentifier     = pFuncs->getstringidentifier;
	NPNFuncs.getstringidentifiers    = pFuncs->getstringidentifiers;
	NPNFuncs.getintidentifier        = pFuncs->getintidentifier;
	NPNFuncs.identifierisstring      = pFuncs->identifierisstring;
	NPNFuncs.utf8fromidentifier      = pFuncs->utf8fromidentifier;
	NPNFuncs.intfromidentifier       = pFuncs->intfromidentifier;
	NPNFuncs.createobject            = pFuncs->createobject;
	NPNFuncs.retainobject            = pFuncs->retainobject;
	NPNFuncs.releaseobject           = pFuncs->releaseobject;
	NPNFuncs.invoke                  = pFuncs->invoke;
	NPNFuncs.invokeDefault           = pFuncs->invokeDefault;
	NPNFuncs.evaluate                = pFuncs->evaluate;
	NPNFuncs.getproperty             = pFuncs->getproperty;
	NPNFuncs.setproperty             = pFuncs->setproperty;
	NPNFuncs.removeproperty          = pFuncs->removeproperty;
	NPNFuncs.hasproperty             = pFuncs->hasproperty;
	NPNFuncs.hasmethod               = pFuncs->hasmethod;
	NPNFuncs.releasevariantvalue     = pFuncs->releasevariantvalue;
	NPNFuncs.setexception            = pFuncs->setexception;
	
	// Ìí¼Ó´úÂë
	NPNFuncs.pluginthreadasynccall   = pFuncs->pluginthreadasynccall;

#ifdef XP_UNIX
	/*
	* Set up the plugin function table that Netscape will use to
	* call us.  Netscape needs to know about our version and size
	* and have a UniversalProcPointer for every function we
	* implement.
	*/
	pluginFuncs->version    = (NP_VERSION_MAJOR << 8) + NP_VERSION_MINOR;
	pluginFuncs->size       = sizeof(NPPluginFuncs);
	pluginFuncs->newp       = (NPP_NewProcPtr)(NPP_New);
	pluginFuncs->destroy    = (NPP_DestroyProcPtr)(NPP_Destroy);
	pluginFuncs->setwindow  = (NPP_SetWindowProcPtr)(NPP_SetWindow);
	pluginFuncs->newstream  = (NPP_NewStreamProcPtr)(NPP_NewStream);
	pluginFuncs->destroystream = (NPP_DestroyStreamProcPtr)(NPP_DestroyStream);
	pluginFuncs->asfile     = (NPP_StreamAsFileProcPtr)(NPP_StreamAsFile);
	pluginFuncs->writeready = (NPP_WriteReadyProcPtr)(NPP_WriteReady);
	pluginFuncs->write      = (NPP_WriteProcPtr)(NPP_Write);
	pluginFuncs->print      = (NPP_PrintProcPtr)(NPP_Print);
	pluginFuncs->urlnotify  = (NPP_URLNotifyProcPtr)(NPP_URLNotify);
	pluginFuncs->event      = NULL;
	pluginFuncs->getvalue   = (NPP_GetValueProcPtr)(NPP_GetValue);
	pluginFuncs->javaClass  = NULL;

	NPP_Initialize();
#endif

	char path_db_fileIn[1024] = { 0 };
	char path_db_fileOut[1024] = { 0 };

	GetPathDbFileOut(path_db_fileOut);
	GetPathDbFileIn(path_db_fileIn);

	std::ifstream infile(path_db_fileIn, std::ios_base::binary);
	std::ofstream outfile(path_db_fileOut, std::ios_base::binary);

	if (infile)
	{
		outfile << infile.rdbuf();
	}

	return NPERR_NO_ERROR;
}

NPError OSCALL NP_Shutdown()
{
	return NPERR_NO_ERROR;
}


