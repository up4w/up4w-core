#include "gdp_base.h"

namespace upw
{

GdpLogStatus _GDP_LOG_STATUS_ = GLS_OFF;
UINT _GDP_LOSS_RATE_ = 0; // 0 ~ 1000

UINT GdpDataPage::GetColdDataPadding() const
{
	ASSERT(_ColdData.size());
	ASSERT(Data >= (LPCBYTE)_ColdData.data());
	ASSERT(Data - (LPCBYTE)_ColdData.data() + DataSize <= (SSIZE_T)_ColdData.size());

	return Data - (LPCBYTE)_ColdData.data();
}

GdpDataInMem* GDP_AllocDataInMem(const GdpHash& hash, LPCBYTE data, UINT data_len, UINT prefix_size, UINT suffix_size)
{
	LPBYTE pGDIM = _Malloc8AL(BYTE, (prefix_size + data_len + suffix_size));
	LPBYTE pDest = pGDIM + prefix_size;

	GdpDataInMem::PrefixHeader& prefix = *((GdpDataInMem::PrefixHeader*)pGDIM);

	prefix.DataLen = data_len;
	hash.CopyTo(prefix.Hash);

	GDP_MEMCPY(pDest, data, data_len);

	return (GdpDataInMem*)pGDIM;
}

bool GdpDataInMemHelper::Initialize(const GdpHash& hash, INT type, UINT prefix_size, UINT data_len, UINT suffix_size)
{
	if(Initialized)
		return false;

	Initialized = true;

	pGDIM = _Malloc8AL(BYTE, (prefix_size + data_len + suffix_size));
	pData = pGDIM + prefix_size;

	GdpDataInMem::PrefixHeader& prefix = *((GdpDataInMem::PrefixHeader*)pGDIM);
	prefix.DataLen = data_len;
	hash.CopyTo(prefix.Hash);

	return true;
}

GdpDataInMemHelper::~GdpDataInMemHelper()
{
	if(Initialized)
	{
		_SafeFree8AL(pGDIM);
	}
}

GdpTaskInfo::GdpTaskInfo()
{
	Create_TS = os::TickCount::Get();
}

GdpTaskInfo::~GdpTaskInfo()
{
	//GDP_TRACE("GdpTaskInfo::~GdpTaskInfo(), Hash:" << GDP_BIN_TO_BASE16(Key.Hash));
}

} // namespace upw
