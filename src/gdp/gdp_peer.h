#pragma once

#include "gdp_base.h"

namespace upw
{

struct ResourcePeer
{
	NetworkAddress	addr;
	rt::String		addr_string;
	UINT			timestamp = 0;	// start timestamp

	int				quota	= 16;			// total quota
	int				best	= 16;			// max quota
	int				used	= 0;			// used quota

	int				min_rt	= 100000;		// min response time
	int				max_rt	= 0;			// max response time

	UINT			lastest_finished_request = 0;

	int				first_timeout	= 0;	// the timestamp of first timeout

	int				this_tick_timeout	= 0;		
	int				this_tick_finished	= 0;		
	int				this_tick_quota		= 0;
	int				this_tick_used		= 0;

	int				this_tick_min_rt	= 100000;
	int				this_tick_max_rt	= 0;

	
	inline bool		InUse() { return timestamp; }
	void			Start(const NetworkAddress& na)
	{
		timestamp = os::TickCount::Get();
		addr = na;

		char buf[64];
		if(addr.Type() == NADDRT_IPV6)
		{
			inet::InetAddrV6 bindV6;
			addr.IPv6().Export(bindV6);
			addr_string = bindV6.GetDottedDecimalAddress(buf);
			addr_string += rt::SS(":") + rt::tos::Number(bindV6.GetPort());
		}
		else
		{
			inet::InetAddr bindV4;
			addr.IPv4().Export(bindV4);
			addr_string = bindV4.GetDottedDecimalAddress(buf);
			addr_string += rt::SS(":") + rt::tos::Number(bindV4.GetPort());
		}

	}
	inline void		Stop() { timestamp = 0; }
};

}