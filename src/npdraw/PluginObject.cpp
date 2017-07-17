#include "PluginObject.h"

#include <string>
#include <sstream>
#include <Windows.h>
#include <fstream>
#include "plugin.h"
#include <algorithm>
#include <list>

using namespace std;

extern NPNetscapeFuncs NPNFuncs;


#define NPVARIANT_TO_INT32(_v) (NPVARIANT_IS_INT32(_v)?(_v).value.intValue:(_v).value.doubleValue)

// 1 声明 Javascript 可以调用的方法名
const char* Function = "Function";
const char* Callback = "Callback";
const char* Property = "Property";

//-----------------------------------------------------------------------------
// 开始修改方法
//-----------------------------------------------------------------------------

// 2. 初始化回调引用
PluginObject::PluginObject(NPP npp):
	npp(npp),
	hThread(0)
{

}

// 3. 析构方法
void PluginObject::deallocate(){

}

// 4.1 告诉JS本插件可以调用的属性
bool PluginObject::hasProperty(NPIdentifier propertyName){
	bool bRev = false;
	NPUTF8 *pName = NPNFuncs.utf8fromidentifier(propertyName);
	return bRev;
}

// 4.2 返回给JS某个属性
bool PluginObject::getProperty(NPIdentifier propertyName, NPVariant *result){
	return false;
}

// 4.3 通过JS设置某个属性
bool PluginObject::setProperty(NPIdentifier name,const NPVariant *value){
	bool bRev = false;
	return bRev;
}

// 4.1 告诉JS本插件可以调用的方法
bool PluginObject::hasMethod(NPIdentifier methodName){
	bool bRev = false;
	NPUTF8 *pName = NPNFuncs.utf8fromidentifier(methodName);

	if (
		strcmp(pName, Function)==0 
		|| strcmp(pName, Property)==0
		){
			return true;
	}
	else {
		return false;
	}
}

// 4.2 通过JS调用方法的入口 
bool PluginObject::invoke(NPIdentifier methodName,
	const NPVariant* args, uint32_t argCount, NPVariant* result) { 

		char* name = NPNFuncs.utf8fromidentifier(methodName);
		bool ret_val = false;
		std::string outString;

		if (!name) {
			return ret_val;
		}

		if (strcmp(name, Function)==0 ) {
			ret_val = true;
			
			outString = "Hello World";
		} 
	
		else {
			// Exception handling. 
			outString = "Called an invalid method.";
		}
		char* npOutString = (char *)NPNFuncs.memalloc(outString.length() + 1);
		if (!npOutString)
			return false;
		strcpy_s(npOutString, outString.length()+1, outString.c_str());
		STRINGZ_TO_NPVARIANT(npOutString, *result);

		NPNFuncs.memfree(name);
		return ret_val;
}

// 4.3 本插件异步回调JS的方法
void PluginObject::ExecuteJSCallback(NPObject* callback, std::string msg){
	int iRev = 0;
	std::string msgUTF8 = msg;

	if (callback != NULL){
		// 转换参数列表
		NPVariant relements[1];
		STRINGZ_TO_NPVARIANT(msgUTF8.c_str(), relements[0]);

		// 调用JS函数
		NPVariant jsResult; 
		NPN_InvokeDefault(npp, callback, relements, 1, &jsResult);

		if (NPVARIANT_IS_STRING(jsResult)){
			NPString rString = NPVARIANT_TO_STRING(jsResult);
			char revBuf[255] = {0};
			memcpy(revBuf, rString.UTF8Characters, rString.UTF8Length);
		}

		// 释放结果变量 当从浏览器那获取的结果
		NPN_ReleaseVariantValue(&jsResult);
	}

	return;
}


//-----------------------------------------------------------------------------
//    下面的方法一般不需要修改
//-----------------------------------------------------------------------------

PluginObject::~PluginObject(void)
{

}

void PluginObject::invalidate(){}

bool PluginObject::invokeDefault(const NPVariant *args, uint32_t argCount, NPVariant *result){
	return true;
}

bool PluginObject::removeProperty(NPIdentifier name){
	return true;
}

bool PluginObject::enumerate(NPIdentifier **identifier,uint32_t *count){
	return false;
}

bool PluginObject::construct(const NPVariant *args,uint32_t argCount, NPVariant *result){
	return true;
}

// ========================================静态函数===============================================================

NPObject *PluginObject::_allocate(NPP npp,NPClass *aClass){
	return new PluginObject(npp);
}

void PluginObject::_deallocate(NPObject *npobj){
	
	((PluginObject*)npobj)->deallocate();
	if(npobj){
		delete npobj;
	}
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
