#include "PluginObject.h"
#include "plugin.h"

PluginObject::PluginObject(NPP npp){	this->npp = npp;	this->id_property_version = NPN_GetStringIdentifier("version");}
PluginObject::~PluginObject(void)
{
}
void PluginObject::deallocate()
{
}

void PluginObject::invalidate()
{
}

bool PluginObject::hasMethod(NPIdentifier methodName)
{
	return false;
}

bool PluginObject::invokeDefault(const NPVariant *args, uint32_t argCount, NPVariant *result)
{
	return true;
}

bool PluginObject::invoke(NPIdentifier methodName, const NPVariant *args, uint32_t argCount, NPVariant *result)
{
	if(false){
	
	}
	else{
		NPN_InvokeDefault(npp,this,args,argCount,result);	
	}
	return true;
}

bool PluginObject::hasProperty(NPIdentifier propertyName)
{
	if(propertyName == this->id_property_version)
		return true;
	return false;
}

bool PluginObject::getProperty(NPIdentifier propertyName, NPVariant *result)
{
	if(propertyName == this->id_property_version)
	{
		CPlugin * pPlugin=(CPlugin*)npp->pdata;
		if(pPlugin)
		{
			//pPlugin->Dlg->GetVal();
			VOID_TO_NPVARIANT(*result);
			char *outString=pPlugin->GetValue();

			char *npOutString=(char *)NPN_MemAlloc(strlen(outString)+1);

			if(!npOutString)
				return false;
			strcpy(npOutString,outString);

			STRINGZ_TO_NPVARIANT(npOutString,*result);
		}

		//VOID_TO_NPVARIANT(*result);
		//char *outString=pPlugin->Dlg->GetVal();
		//char *npOutString=(char *)NPN_MemAlloc(strlen(outString)+1);

		//if(!npOutString)
		//	return false;
		//strcpy(npOutString,outString);

		//STRINGZ_TO_NPVARIANT(npOutString,*result);

		//int plugin_major, plugin_minor, netscape_major,netscape_minor;
		//NPN_Version(&plugin_major,&plugin_minor,&netscape_major,&netscape_minor);
		//NPString version = "";
		//char plugin_major_str[10];
		//itoa(plugin_major,plugin_major_str,10);

		//char plugin_minor_str[10];
		//itoa(plugin_minor,plugin_minor_str,10);

		//char netscape_major_str[10];
		//itoa(netscape_major,netscape_major_str,10);

		//char netscape_minor_str[10];
		//itoa(netscape_minor,netscape_minor_str,10);
		//version.append("plugin_major:").append(plugin_major_str);
		//version.append("\nplugin_minor:").append(plugin_minor_str);
		//version.append("\nnetscape_major:").append(netscape_major_str);
		//version.append("\nnetscape_minor:").append(netscape_minor_str);
		//MessageBoxA(NULL,version.c_str(),"",NULL);
		return true;
	}
	return false;
}
bool PluginObject::setProperty(NPIdentifier name,const NPVariant *value)
{
	return true;
}
bool PluginObject::removeProperty(NPIdentifier name)
{
	return true;
}
//这玩意折腾不少时间了!
bool PluginObject::enumerate(NPIdentifier **identifier,uint32_t *count){	return false;}
bool PluginObject::construct(const NPVariant *args,uint32_t argCount, NPVariant *result){	return true;}
NPObject* PluginObject::_allocate(NPP npp,NPClass* aClass){	return new PluginObject(npp);}

void PluginObject::_deallocate(NPObject *npobj)
{
	((PluginObject*)npobj)->deallocate();
	if(npobj)
		delete npobj;
}

void PluginObject::_invalidate(NPObject *npobj)
{
	((PluginObject*)npobj)->invalidate();
}

bool PluginObject::_hasMethod(NPObject* obj, NPIdentifier methodName)
{
	return ((PluginObject*)obj)->hasMethod(methodName);
}

bool PluginObject::_invokeDefault(NPObject *obj, const NPVariant *args, uint32_t argCount, NPVariant *result)
{
	return ((PluginObject*)obj)->invokeDefault(args,argCount,result);
}

bool PluginObject::_invoke(NPObject* obj, NPIdentifier methodName, const NPVariant *args, uint32_t argCount, NPVariant *result)
{
	return ((PluginObject*)obj)->invoke(methodName,args,argCount,result);
}

bool PluginObject::_hasProperty(NPObject *obj, NPIdentifier propertyName)
{
	return ((PluginObject*)obj)->hasProperty(propertyName);
}

bool PluginObject::_getProperty(NPObject *obj, NPIdentifier propertyName, NPVariant *result)
{
	return ((PluginObject*)obj)->getProperty(propertyName,result);
}

bool PluginObject::_setProperty(NPObject *npobj, NPIdentifier name,const NPVariant *value)
{
	return ((PluginObject*)npobj)->setProperty(name,value);
}

bool PluginObject::_removeProperty(NPObject *npobj, NPIdentifier name)
{
	return ((PluginObject*)npobj)->removeProperty(name);
}

bool PluginObject::_enumerate(NPObject *npobj, NPIdentifier **identifier,uint32_t *count)
{
	return ((PluginObject*)npobj)->enumerate(identifier,count);
}

bool PluginObject::_construct(NPObject *npobj, const NPVariant *args,uint32_t argCount, NPVariant *result)
{
	return ((PluginObject*)npobj)->construct(args,argCount,result);
}
