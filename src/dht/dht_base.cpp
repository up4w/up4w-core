#include "dht_base.h"
#include "../../externs/miniposix/core/ext/botan/botan.h"


namespace upw
{

const UINT DHT_SWARM_QUERY_TRANSID_LENGTH = 9;

bool DhtAddress::FromString(const rt::String_Ref& s)
{
	static const int len_b16 = (int)os::Base16EncodeLength(DHT_ADDRESS_SIZE);
	static const int len_b32 = (int)os::Base32EncodeLength(DHT_ADDRESS_SIZE);
	static const int len_b64 = (int)os::Base64EncodeLength(DHT_ADDRESS_SIZE);

	SIZE_T out_len = DHT_ADDRESS_SIZE;
	if(s.GetLength() == len_b64)
		return os::Base64Decode(addr, &out_len, s.Begin(), len_b64);
	else if(s.GetLength() == len_b16)
		return os::Base16Decode(addr, out_len, s.Begin(), len_b16);
	else if(s.GetLength() == len_b32)
		return os::Base32Decode(addr, out_len, s.Begin(), len_b32);
	else
		return false;
}

void DhtAddress::Random()
{
	rt::Randomizer rng(os::TickCount::Get());
	rng.Randomize(*this);
}

#if defined(OXD_USE_ADVANCED_CPU_ABM_HASWELL)
UINT DhtAddress::Match(const DhtAddress& a, const DhtAddress& b)
{
	ASSERT(0 == (DHT_ADDRESS_SIZE&0x3));

	const ULONGLONG* pa = (const ULONGLONG*)&a.addr;
	const ULONGLONG* pb = (const ULONGLONG*)&b.addr;

	for(UINT i=0; i<DHT_ADDRESS_SIZE/8; i++)
	{
		ULONGLONG xor = rt::ByteOrderSwap(pa[i]^pb[i]);
		if(xor)
		{
			return i*64 + rt::LeadingZeroBits(xor);
		}
	}

	return (DHT_ADDRESS_SIZE&(~0x7U))*8 + 
			rt::LeadingZeroBits( rt::ByteOrderSwap((*(DWORD*)&a.addr[DHT_ADDRESS_SIZE-4]) ^ (*(DWORD*)&b.addr[DHT_ADDRESS_SIZE-4])) );
}

#else

UINT DhtAddress::Match(const DhtAddress& a, const DhtAddress& b)
{
	ASSERT(0 == (DHT_ADDRESS_SIZE&0x3));

	int i=0;
	for(;i<DHT_ADDRESS_SIZE;i++)
	{
		if(a.addr[i] != b.addr[i])goto LAST_BYTE_MATCH;
	}
	return DHT_ADDRESS_SIZE*8;

LAST_BYTE_MATCH:
	static const int sigcount[16] = 
	{	4, 3, 2, 2, 1, 1, 1, 1, 
		0, 0, 0, 0, 0, 0, 0, 0
	};
	int v_xor = a.addr[i]^b.addr[i];
	if((v_xor&0xf0) == 0x00)
	{	
		return i*8 + 4 + sigcount[v_xor&0xf];
	}
	else
	{
		return i*8 + sigcount[v_xor>>4];
	}
}
#endif // OXD_USE_ADVANCED_CPU_ABM_HASWELL

void DhtAddress::FromHash(LPCVOID p, UINT sz)
{
	sec::Hash<sec::HASH_SHA1>().Calculate(p, sz, this);
}

} // namespace upw
