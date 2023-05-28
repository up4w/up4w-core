#pragma once
#include "../externs/miniposix/core/inet/inet.h"
#include "net_types.h"


namespace upw
{

class UPnpRouter
{
	struct Port
	{	DWORD	proto;
		int		port;
	};
protected:
	rt::String			_AppName;
	rt::String			_ControlURL;
	rt::String			_ServiceType;
	rt::String			_InternalIP;
	rt::String			_ClientDesc;
	rt::BufferEx<Port>	_ExtPortsMapped;
	void				_AddExtPortsMapped(DWORD proto, int port);

public:
	enum _tagProtocal
	{	UDP = 0x504455,
		TCP = 0x504354
	};

	UPnpRouter();
	~UPnpRouter(){ RemoveAllPortMapping(); }
	void SetAppName(const rt::String_Ref& name);

	bool	IsDiscovered() const { return !_ControlURL.IsEmpty(); }
	bool	Discover(bool ipv6 = false);

	bool	GetExternalIP(rt::String& ex_ip);
	auto&	GetInternalIP() const { return _InternalIP; }

	bool	AddPortMapping(int internal_port, int external_port, DWORD protocal = UDP); // return mapped external port, 0 for error
	bool	RemovePortMapping(int external_port, DWORD protocal = UDP);
	void	RemoveAllPortMapping();
	void	PopulateAllPortMapping(rt::String& out);
};

class UPnPIPv6FirewallControl
{
public:
	bool AddPinhole(IPv6 internalIPPort);
};

} // namespace upw
