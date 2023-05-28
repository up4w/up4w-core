#include "nat_passthrough.h"

#define MINIUPNP_STATICLIB
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

extern "C"
{
// lib miniupnpc
#include "../externs/miniupnpc/miniupnpc_declspec.h"
#include "../externs/miniupnpc/miniupnpc.h"
#include "../externs/miniupnpc/upnpcommands.h"
#include "../externs/miniupnpc/upnperrors.h"

#pragma warning(disable:4244) // warning C4244: '=' : conversion from 'crypto_int64' to 'crypto_int32', possible loss of data
#pragma warning(disable:4267) 
#pragma warning(disable:4838) // warning C4838: conversion from 'int' to 'uint32_t' requires a narrowing conversion

// lib miniupnpc
#include "../externs/miniupnpc/connecthostport.c"
#include "../externs/miniupnpc/igd_desc_parse.c"
#undef COMPARE

#include "../externs/miniupnpc/minisoap.c"
#include "../externs/miniupnpc/miniupnpc.c"
#include "../externs/miniupnpc/miniwget.c"
#include "../externs/miniupnpc/minixml.c"
#include "../externs/miniupnpc/portlistingparse.c"
#include "../externs/miniupnpc/receivedata.c"
#include "../externs/miniupnpc/upnpcommands.c"
#include "../externs/miniupnpc/upnperrors.c"
#include "../externs/miniupnpc/upnpreplyparse.c"
#include "../externs/miniupnpc/minissdpc.c"
#include "../externs/miniupnpc/addr_is_reserved.c"
#include "../externs/miniupnpc/upnpdev.c"
}

namespace upw
{


bool UPnpRouter::GetExternalIP(rt::String& ex_ip)
{
	if(IsDiscovered())
	{
		char exIP[256];
		if(0 == UPNP_GetExternalIPAddress(_ControlURL, _ServiceType, exIP))
		{	
			ex_ip = exIP;
			return true;
		}
	}
	
	return false;
}

void UPnpRouter::_AddExtPortsMapped(DWORD proto, int port)
{
	auto& p = _ExtPortsMapped.push_back();
	p.port = port;
	p.proto = proto;
}

bool UPnpRouter::AddPortMapping(int internal_port, int external_port, DWORD protocal)
{
	if(IsDiscovered())
	{
		int err = UPNP_AddPortMapping(	_ControlURL, _ServiceType, 
										rt::tos::Number(external_port).Begin(), 
										rt::tos::Number(internal_port).Begin(),
										_InternalIP,
										_ClientDesc, 
										(LPCSTR)&protocal, 
										nullptr, 
										nullptr);

		if(err == 0)
		{	_AddExtPortsMapped(protocal, external_port);
			return true;
		}

		if(err == 718)  // ConflictInMappingEntry
		{
			char intClient[100];
            char intPort[100];
            char desc[100];
            char enabled[100];
            char leaseDuration[100];

			UPNP_GetSpecificPortMappingEntry(	_ControlURL, _ServiceType, 
												rt::tos::Number(external_port).Begin(), 
												(LPCSTR)&protocal, 
												nullptr,
												intClient, 
												intPort, 
												desc, 
												enabled,
												leaseDuration
			);

			int inport = 0;
			rt::String_Ref(intPort).ToNumber(inport);
			if(_InternalIP == rt::String_Ref(intClient) && internal_port == inport)
			{
				_AddExtPortsMapped(protocal, external_port);
				return true;
			}
		}
	}

	return false;
}

void UPnpRouter::PopulateAllPortMapping(rt::String& out)
{
	out.Empty();
	for(UINT i=0; ;i++)
	{
		char extPort[100];
		char intClient[100];
        char intPort[100];
		char proto[100];
        char desc[100];
		char enabled[100];
        char host[100];
        char leaseDuration[100];

		if(0 != UPNP_GetGenericPortMappingEntry(_ControlURL, _ServiceType, 
												rt::tos::Number(i).Begin(), 
												extPort,
												intClient,
												intPort,
												proto,
												desc,
												enabled,
												host,
												leaseDuration
			)
		)break;

		out +=	rt::SS() + rt::tos::Number(i).RightAlign(5) + ": " + 
				extPort + '/' + proto + " => " + intPort + " (" + intClient + ") " + enabled + ' ' + leaseDuration + ' ' + desc + '\n';
	}

	out.TrimRight(1);
}

void UPnpRouter::RemoveAllPortMapping()
{
	for(UINT i=0; i<_ExtPortsMapped.GetSize(); i++)
	{
		UPNP_DeletePortMapping(_ControlURL, _ServiceType, rt::tos::Number(_ExtPortsMapped[i].port).Begin(), (LPCSTR)&_ExtPortsMapped[i].proto, nullptr);
	}

	_ExtPortsMapped.SetSize(0);
}

bool UPnpRouter::RemovePortMapping(int external_port, DWORD protocal)
{
	return 0 == UPNP_DeletePortMapping(_ControlURL, _ServiceType, rt::tos::Number(external_port).Begin(), (LPCSTR)&protocal, nullptr);
}

UPnpRouter::UPnpRouter()
{
	_AppName = "upnpMap";
}

void UPnpRouter::SetAppName(const rt::String_Ref& name)
{
	_AppName = name;
}

bool UPnpRouter::Discover(bool ipv6)
{
#if defined(OXD_SIMULATE_RESTRICTED_NETWORK)
	return false;
#endif

	int err = 0;
	struct UPNPDev * dev = upnpDiscover(1000, nullptr, nullptr, 0, ipv6, 2, &err);
	if(!dev)return false;

	UPNPDev* pd = dev;
	while(pd)
	{
		struct UPNPUrls urls;
		struct IGDdatas data;

		char inIP[256];
		if(	strstr(pd->st, "device:InternetGatewayDevice") &&
			UPNP_GetIGDFromUrl(pd->descURL, &urls, &data, inIP, sizeof(inIP))
		)
		{
			_ControlURL = urls.controlURL;
			_ServiceType = data.first.servicetype;
			_ClientDesc = _AppName+ '-' + os::GetProcessId();
			_InternalIP = inIP;

			break;
		}

		pd = pd->pNext;
	}

	freeUPNPDevlist(dev);
	return true;
}

bool UPnPIPv6FirewallControl::AddPinhole(IPv6 internalIPPort)
{
	int err = 0;
	struct UPNPDev * dev = upnpDiscover(1000, nullptr, nullptr, 0, 1, 2, &err);

	char ipStr[64];
	inet_ntop(AF_INET6, &internalIPPort, ipStr, 47);

	bool ret = false;
	UPNPDev* pd = dev;
	while(pd)
	{
		struct UPNPUrls urls;
		struct IGDdatas data;

		char inIP[256];
		if(strstr(pd->st, "device:InternetGatewayDevice")
			&& UPNP_GetIGDFromUrl(pd->descURL, &urls, &data, inIP, sizeof(inIP))
			&& data.IPv6FC.servicetype[0] != '\0')
		{
			int firewallEnabled = -1;
			int inboundPinholeAllowed = -1;
			int res;
			res = UPNP_GetFirewallStatus(urls.controlURL, data.first.servicetype, &firewallEnabled, &inboundPinholeAllowed);

			char uniqueId[8];
			res = UPNP_AddPinhole(urls.controlURL, data.first.servicetype,
				"empty", rt::tos::Number(0).Begin(),
				ipStr, rt::tos::Number(internalIPPort.Port()).Begin(),
				rt::tos::Number(IPPROTO_UDP).Begin(),
				rt::tos::Number(86400).Begin(),
				uniqueId);
			ret = true;
			break;
		}

		pd = pd->pNext;
	}

	if(dev)freeUPNPDevlist(dev);
	return ret;
}

}