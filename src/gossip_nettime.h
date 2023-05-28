#pragma once
#include "../externs/miniposix/essentials.h"
#include "net_types.h"


namespace upw
{

class NetworkServiceCore;

class GossipNetworkTime
{
	NetworkServiceCore*		_pCore;
	os::Timestamp			__LocalClockSource;

protected:
	LONGLONG				_NetworkTimeDrift;	// Nettime = LocalTime + _NetworkTimeDrift
	int						_TimeStablizationDegree;
	bool					_bTimeCasting;
	bool					_bNetworkBootstrap;
	int						_TimeDriftVariance;
	int						_OutlierSampleCount;

	struct Sample
	{
		LONGLONG	Drift;
		int			Count;
		bool		IpRestricted;
		Sample(){ rt::Zero(*this); }
	};
	typedef ext::fast_map<NetworkAddress, Sample>	t_CollectedSamples;
	t_CollectedSamples		_CollectedSamples;
	os::CriticalSection		_CollectedSamplesCS;

	void					_AdjustByCollectedSamples();

public:
	GossipNetworkTime(NetworkServiceCore* c);

	void			OnTick(UINT tick);

	bool			IsStablized() const { return _TimeStablizationDegree; }
	bool			IsCasting() const { return _bTimeCasting; } // stable and the local time is not outlier
	bool			IsAvailable() const { return IsStablized() || _CollectedSamples.size() > NET_TIME_SAMPLE_COUNT_MIN; }
	UINT			GetSampleCount() const { return (UINT)_CollectedSamples.size(); }

	LONGLONG		GetTime(LONGLONG local_time) const { return local_time + _NetworkTimeDrift; }
	LONGLONG		GetTime() const { return GetTime(__LocalClockSource.Get()); }

	LONGLONG		GetTimeDrift() const { return _NetworkTimeDrift; }
	int				GetTimeDriftVariance() const { return _TimeDriftVariance; }
	UINT			GetStablizationDegree() const { return _TimeStablizationDegree; }
	void			Reset(bool genesis = false);
	void			SetBootstrap(){ _bNetworkBootstrap = true; }
	void			GetState(NetworkState_GNT& ns);

	bool			OnPeerTimeSample(DWORD nt32, int latency, const PacketRecvContext& ctx);
	DWORD			GetTimeToReportDword() const;
};

} // namespace upw

