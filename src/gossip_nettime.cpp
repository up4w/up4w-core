#include "gossip_nettime.h"
#include "netsvc_events.h"
#include "netsvc_core.h"


namespace upw
{

GossipNetworkTime::GossipNetworkTime(NetworkServiceCore* c)
	:_pCore(c)
{
	Reset();
}

void GossipNetworkTime::Reset(bool genesis)
{
	EnterCSBlock(_CollectedSamplesCS);

	_NetworkTimeDrift = 0;
	_CollectedSamples.clear();
	_OutlierSampleCount = 0;
	_TimeDriftVariance = 0;

	if(genesis)
	{
		_TimeStablizationDegree = 1;
		_bTimeCasting = true;
	}
	else
	{
		_TimeStablizationDegree = 0;
		_bTimeCasting = false;
	}

	_bNetworkBootstrap = false;
	rt::_CastToNonconst(_pCore->GetNodeDesc()).LocalTime32 = 0;
}

bool GossipNetworkTime::OnPeerTimeSample(DWORD nt32, int latency, const PacketRecvContext& ctx)
{
	if(latency < 0)return false;

	LONGLONG lt = __LocalClockSource.Get();
	LONGLONG nt = GetTime(lt);

	DWORD local_nt32 = (DWORD)nt;
	LONGLONG remote_nt = (nt&0xffffffff00000000ULL)|nt32;

	if(local_nt32 > nt32 && (local_nt32 - nt32)>0x7fffffff)
		remote_nt += 0x100000000LL;
	else if(local_nt32 < nt32 && (nt32 - local_nt32)>0x7fffffff)
		remote_nt -= 0x100000000LL;

	remote_nt += latency/2;

	EnterCSBlock(_CollectedSamplesCS);
	if(IsStablized())
	{
		if(rt::abs(remote_nt - nt) > NET_TIME_DIFF_MAX_FOR_CASTING) // outlier
		{
			_OutlierSampleCount++;
			_LOGC("Outlier Sampled: "<<(remote_nt - lt)<<" from "<<tos(ctx.RecvFrom));
			return false;
		}
	}
	else
	{
		if(rt::abs(remote_nt - nt) > NET_TIME_DIFF_MAX_FOR_CASTING*10) // outlier
		{
			_OutlierSampleCount++;
			_LOGC("Outlier Sampled: "<<(remote_nt - lt)<<" from "<<tos(ctx.RecvFrom));
			return false;
		}
	}

	auto& s = _CollectedSamples[ctx.RecvFrom];

	if(ctx.SendingFlag&PSF_IP_RESTRICTED_VERIFIED)
		s.IpRestricted = true;

	s.Drift += remote_nt - lt;
	s.Count++;

	//_LOGC("Sampled: "<<(remote_nt - lt)<<" from "<<tos(ctx.RecvFrom));

	if(!IsStablized())
		_AdjustByCollectedSamples();

	return true;
}

void GossipNetworkTime::OnTick(UINT tick)
{
	if((tick&0x7f) == 0)
	{
		EnterCSBlock(_CollectedSamplesCS);
		_AdjustByCollectedSamples();
	}
}

DWORD GossipNetworkTime::GetTimeToReportDword() const
{
	return _bTimeCasting?rt::max((DWORD)1, (DWORD)(__LocalClockSource.Get() + _NetworkTimeDrift/2)):0;
}

void GossipNetworkTime::_AdjustByCollectedSamples()
{
	ASSERT(_CollectedSamplesCS.IsLockedByCurrentThread());

	if(_CollectedSamples.size() >= NET_TIME_SAMPLE_COUNT_MIN || _bNetworkBootstrap)
	{
		LONGLONG drift_mean = 0;
		double drift_var = 0;
		int count_total = 0;
		{
			int mean_w = 0;
			for(auto& s : _CollectedSamples)
			{
				if(s.second.IpRestricted)
				{
					drift_mean += 10*s.second.Drift/s.second.Count;
					mean_w += 10;
				}
				else
				{
					drift_mean += 1*s.second.Drift/s.second.Count;
					mean_w += 1;
				}

				count_total += s.second.Count;
			}
			drift_mean /= mean_w;
			
			if(IsStablized())
			{	if(count_total < NET_TIME_SAMPLE_COUNT_STABLE)return;
			}
			else
			{	if(count_total < NET_TIME_SAMPLE_COUNT_MIN)return;
			}

			// compute variance
			for(auto& s : _CollectedSamples)
			{
				if(s.second.IpRestricted)
				{
					drift_var += 10*rt::Sqr(s.second.Drift/s.second.Count - drift_mean);
				}
				else
				{
					drift_var += 1*rt::Sqr(s.second.Drift/s.second.Count - drift_mean);
				}
			}

			drift_var = sqrt(drift_var/(double)mean_w);
		}

		//_LOG("drift_mean: "<<drift_mean<<" var:"<<_TimeDriftVariance);

		if(IsStablized())
		{
			if(_OutlierSampleCount > NET_TIME_SAMPLE_COUNT_STABLE*2 && _CollectedSamples.size() < NET_TIME_SAMPLE_COUNT_MIN*2)
			{
				Reset();
				_NetworkTimeDrift = drift_mean;
				_LOGC_WARNING("[GNT]: Network time significant inconsistency detected, resolving network again");
				return;
			}

			if(count_total >= NET_TIME_SAMPLE_COUNT_STABLE)
			{
				_NetworkTimeDrift += (drift_mean - _NetworkTimeDrift)/_TimeStablizationDegree;
				_TimeDriftVariance += (int)((drift_var + 0.5 - _TimeDriftVariance)/_TimeStablizationDegree);
				_CollectedSamples.clear();
				_OutlierSampleCount = 0;

				if(_TimeStablizationDegree < 128)
					_TimeStablizationDegree = rt::min(_TimeStablizationDegree + _TimeStablizationDegree/2, 128);

				_LOGC_VERBOSE("[GNT]: Network time adjusted D/V="<<_NetworkTimeDrift<<'/'<<_TimeDriftVariance<<" S="<<_TimeStablizationDegree);
			}
		}
		else
		{
			_NetworkTimeDrift = drift_mean;
			_TimeDriftVariance = (int)(drift_var + 0.5);
			if(	count_total >= NET_TIME_SAMPLE_COUNT_STABLE || 
				(_bNetworkBootstrap && count_total >= 3)
			)
			{
				_TimeStablizationDegree = 2;
				_CollectedSamples.clear();
				_OutlierSampleCount = 0;

				if(abs(_NetworkTimeDrift) < NET_TIME_DIFF_MAX_FOR_CASTING && _TimeDriftVariance < NET_TIME_DIFF_MAX_FOR_CASTING/2)
				{
					_LOGC("[GNT]: Network time stablized D/V="<<_NetworkTimeDrift<<'/'<<_TimeDriftVariance<<" and start casting");
					_bTimeCasting = true;
				}
				else
				{
					_LOGC("[GNT]: Network time stablized D/V="<<_NetworkTimeDrift<<'/'<<_TimeDriftVariance<<" but muted");
					_bTimeCasting = false;
				}

				CoreEvent(MODULE_NETWORK, NETWORK_TIME_STABLIZED);
			}
		}
	}
}

void GossipNetworkTime::GetState(NetworkState_GNT& ns)
{
	ns.GNT_Available = IsAvailable();
	ns.GNT_Casting = IsCasting();
	ns.GNT_Stablized = IsStablized();

	ns.GNT_LocalClockDrift = GetTimeDrift();
	ns.GNT_NetworkTime = GetTime();
}

} // namespace upw
