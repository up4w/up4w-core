#include "mrc_base.h"
#include "../../externs/miniposix/core/ext/botan/botan.h"


namespace upw
{

namespace _details
{
const UINT	__HiddenBytesMaskSize = MRC_HIDDENBYTES_MASKSIZE;
LPCBYTE		__HiddenBytesMaskBytes = NULL;
uint32_t	__ContactPointSubbandCounter = ::time(nullptr);

struct _free_ProtectedBytesMaskBytes
{	
	_free_ProtectedBytesMaskBytes()
	{
		__HiddenBytesMaskBytes = (LPCBYTE)malloc(__HiddenBytesMaskSize);
		sec::Randomize((LPVOID)__HiddenBytesMaskBytes, __HiddenBytesMaskSize);
	}
	~_free_ProtectedBytesMaskBytes()
	{
		rt::Zero((LPVOID)__HiddenBytesMaskBytes, __HiddenBytesMaskSize);
		free((LPVOID)__HiddenBytesMaskBytes);
	}
};
_free_ProtectedBytesMaskBytes ___free_ProtectedBytesMaskBytes;

} // namespace _details

void MrcPowDifficulty::Set(UINT expected_hash_count, UINT e2_shift)
{
	ULONGLONG num = 0x8000'0000'0000'0000ULL/expected_hash_count;   // << _HashSize*8 - 63 + e2_shift
	int shift = rt::LeadingZeroBits(num);
	num <<= shift;	// << _HashSize*8 - 63 - shift + e2_shift

	int exp = HASHSIZE*8 - 63 + e2_shift - shift;
	int bytes = exp/8;
	int residue = exp%8;
	if(residue){ bytes ++; num >>= (8 - residue); }

	_TargetNum = (UINT)(num>>32);
	_NonZeroBytes = bytes + sizeof(ULONGLONG);
}

void MrcPowDifficulty::Set(ULONGLONG expected_hash_count)
{
	int e2_shift = rt::LeadingZeroBits(expected_hash_count);
	if(e2_shift > 32){ e2_shift = 0; }
	else
	{	e2_shift = 32 - e2_shift;
		expected_hash_count >>= e2_shift;
	}

	Set((UINT)expected_hash_count, e2_shift);
}

bool MrcPowDifficulty::IsFulfilled(LPCVOID hashval) const // pointing to HASHSIZE bytes
{
	const BYTE* p = (const BYTE*)hashval;
	const BYTE* end = p + HASHSIZE;
	p += _NonZeroBytes;

	if(_TargetNum <= *(((UINT*)p)-1))return false;
	for(; p<end; p++)
		if(*p)return false;

	return true;
}

bool MrcPowDifficulty::IsFulfilled(BYTE data[64], uint64_t nonce) const
{
	*(uint64_t*)data = nonce;

	BYTE hash[HASHSIZE];
	HashCalculate(data, 64, hash);

	return IsFulfilled(hash);
}

uint64_t MrcPowDifficulty::SearchNonce(BYTE data[64], uint64_t nonce_init) const
{
	auto& nonce = *(uint64_t*)data;
	if(nonce_init)
		nonce = nonce_init;
	else
	{
		thread_local rt::Randomizer rand(os::Timestamp::Get());
		nonce = rand.GetNext();
		nonce <<= 32;
		nonce += rand.GetNext();
	}

	BYTE hash[HASHSIZE];

	for(;;nonce++)
	{
		HashCalculate(data, 64, hash);
		if(IsFulfilled(hash))
			return nonce;
	}

	return 0;
}

MrcContactPointNum GetContactPointByEpochWithSubband(LPCVOID secret, UINT secret_size, DWORD epoch, uint32_t subband)
{ 
	DWORD ret[2]; 
	thread_local sec::Hash<sec::HASH_CRC32>	h;

	subband &= MRC_CONTACTPOINT_SUBBAND_BITS;
 
	h.Reset(); 
	h.Update(&epoch, 4); 
	h.Update(secret, secret_size/2); 
	h.Update(&subband, 4); 
	h.Update(&epoch, 4); 
	h.Finalize(&ret[0]); 
 
	h.Reset(); 
	h.Update(&ret[0], 4); 
	h.Update(&subband, 4); 
	h.Update(((LPCBYTE)secret) + secret_size/2, secret_size/2); 
	h.Update(&epoch, 4); 
	h.Finalize(&ret[1]); 
				 
	auto r = *(MrcContactPointNum*)ret; 
	if(r == MrcContactPointZero)return (MrcContactPointNum)(0x1000000000000000ULL|(epoch*epoch*(1 + subband))); 
	if(r == MrcContactPointVoid)return (MrcContactPointNum)(0x1100000000000000ULL|(epoch*epoch*(1 + subband))); 
	return r; 
}

MrcContactPointNum GetContactPointByEpoch(LPCVOID secret, UINT secret_size, DWORD epoch)
{
	_details::__ContactPointSubbandCounter += ((uint32_t&)secret)>>16;
	return GetContactPointByEpochWithSubband(secret, secret_size, epoch, _details::__ContactPointSubbandCounter);
}

MrcRecvContext::MrcRecvContext(MrcMsgHash hash, SourceType s, const DhtAddress* swarm, MrcContact conv)
	: SwarmAddr(swarm)
	, Conversation(conv)
{
	MsgHash = hash;
	s = Source;
}

void MrcRootSecretSeed::DeriveDataKeypair(const rt::String_Ref& name, MrcKeyPair& out) const
{
	auto& hash = GetHasher();
	hash.Update(this, EffectiveLength);
	hash.Update(name.Begin(), (UINT)name.GetLength());
	hash.Update(this, EffectiveLength);

	rt::PodOnHeap<SecretSeed> d;
	hash.Finalize(d);

	do
	{
		out.Generate(*d);
		d->DWords[0]++;
	}while(!((MrcDataKey&)out.Public()).IsValid());
}

void MrcRootSecretSeed::DeriveSocialIdKeypair(MrcKeyPair& out) const
{
	auto& hash = GetHasher();
	hash.Update(this, EffectiveLength);

	rt::PodOnHeap<SecretSeed> d;
	hash.Finalize(d);
	out.Generate(*d);
}

void MrcContactPoints::ContactPointMap::AddContact(DWORD epoch, MrcContact id, const SecretType** secrets, uint32_t secret_count)
{
	for(uint32_t subband=0; subband<=MRC_CONTACTPOINT_SUBBAND_BITS; subband++)
	{
		for(uint32_t s = 0; s<secret_count; s++)
		{
			auto cpt = GetContactPointByEpochWithSubband(*secrets[s], sizeof(SecretType), epoch, subband);
#if defined(PLATFORM_DEBUG_BUILD)
			insert(std::make_pair(cpt, ContactPointMapValue({id, *secrets[s], epoch, subband})));
			//_LOGC("AddContact: "<<cpt<<", id="<<id);
#else
			insert(std::make_pair(cpt, id));
#endif		
		}
	}
}

void MrcContactPoints::ContactPointMap::ReplaceContact(DWORD epoch, MrcContact id, const SecretType** secrets, uint32_t secret_count, MrcContact prev_id)
{
	for(uint32_t subband=0; subband<=MRC_CONTACTPOINT_SUBBAND_BITS; subband++)
	{
		for(uint32_t s = 0; s<secret_count; s++)
		{
			auto cpt = GetContactPointByEpochWithSubband(*secrets[s], sizeof(SecretType), epoch, subband);
			auto it = find(cpt);
			if(it != end())
			{
				ASSERT(it->second == prev_id);
				it->second = id;
			}
		}
	}
}

MrcContactPoints::ContactPointMap* MrcContactPoints::_Set(DWORD epoch, ContactPointMap* new_map)
{
	ASSERT(epoch>=_BaseEpoch && epoch-_BaseEpoch<sizeofArray(_Maps));

	auto* ret = _Maps[epoch-_BaseEpoch];
	_Maps[epoch-_BaseEpoch] = new_map;
	return ret;
}

MrcContactPoints::~MrcContactPoints()
{
	if(!_MapWasTaken)
		for(auto& it : _Maps)
			_SafeDel(it);
}

bool MrcContactPoints::IsEpochShifting(int64_t net_time) const
{
	NetTimestamp tm = net_time + MRC_CONTACTPOINT_INTERVAL/2;
	UINT epoch = GetEpochForContactPoint(tm);

	return _BaseEpoch != epoch - FullContactPointMapsLength + 1 + FullContactPointMapsPreSlot;
}

void MrcContactPoints::Update(MrcContactsRepository* contacts, int64_t net_time, bool contact_dirty)
{
	NetTimestamp tm = net_time + MRC_CONTACTPOINT_INTERVAL/2;
	UINT epoch = GetEpochForContactPoint(tm);
	UINT epoch_base = epoch - FullContactPointMapsLength + 1 + FullContactPointMapsPreSlot;
 
    if(contact_dirty)
    {   // modify all maps
        for(uint32_t i=0; i<FullContactPointMapsLength; i++)
        {
			 _SafeDel_Delayed(_Maps[i], 2500);
            _Maps[i] = _CreateContactPointMap(contacts, i + epoch_base);
        }

        _BaseEpoch = epoch_base;
        return;
    }
    
    if(_BaseEpoch == epoch_base)return;

	ContactPointMap*	Maps[FullContactPointMapsLength];
	memcpy(Maps, _Maps, sizeof(Maps));

    // insert new map and carry old ones
	for(UINT i=0; i<FullContactPointMapsLength; i++)
	{
		int idx = EpochToIndex(i + epoch_base);
		if(idx >=0 && Maps[idx])
		{
			_Maps[i] = Maps[idx];
			Maps[idx] = nullptr;
		}
		else
			_Maps[i] = _CreateContactPointMap(contacts, i + epoch_base);
	}

	_BaseEpoch = epoch_base;

	for(UINT i=0; i<FullContactPointMapsLength; i++)
		_SafeDel_Delayed(Maps[i], 2500);
}

void MrcContactPoints::AddContactPoint(const MrcContactPoints::SecretType& s, MrcContact id)
{
	SecretTypePtr p = &s;
	for(uint32_t i=0; i<FullContactPointMapsLength; i++)
		_Maps[i]->AddContact(i + _BaseEpoch, id, (const SecretType**)&p, 1);
}

void MrcContactPoints::ReplaceContact(MrcContactsRepository* contacts, MrcContact new_id, MrcContact prev_id)
{
	SecretTypePtr secret_out[SECRET_PERCONTACT_MAX];
	auto count = _GetContactPointSecrets(contacts, new_id, secret_out);

	if(count)
		for(uint32_t i=0; i<FullContactPointMapsLength; i++)
			_Maps[i]->ReplaceContact(i + _BaseEpoch, new_id, (const SecretType**)secret_out, count, prev_id);
}

uint32_t MrcContactPoints::_GetContactPointSecrets(MrcContactsRepository* r, MrcContact c, SecretTypePtr secret_out[SECRET_PERCONTACT_MAX])
{
	uint32_t ret = 0;
	switch(r->GetType(c))
	{
	case MCT_USER:
		{
			auto relation = r->GetRelationship(c);
			
			if(relation&MCR_KNOWN)
				secret_out[ret++] = r->GetSecret(c); // normal conversation, secret decrypted using ContactUser::SealBox
			
			if((r->GetSocialPreference(c)&MSP_FOLLOWER_CAST) && (relation&MCR_FRIENDED))
				secret_out[ret++] = r->GetPublicKey(c); // public friend feed, secret can be Address or Secrets.Profile

			if((relation&MCR_FOLLOWED) && !(relation&MCR_FRIENDED))
				secret_out[ret++] = r->GetUserGreetingSecret(c); // normal conversation but peer yet connected back, secret decrypted using ContactUser::SealBox
		}
		break;
	case MCT_COMMUNITY:
		{
			secret_out[ret++] = r->GetPublicKey(c); // for activity stats messages in the community (as EVLP_BROADCAST)

			// todo: enable it when MSP_LOCAL_OPEN_FRIENDING can be set by UI
			//if(r->GetSocialPreference(c)&MSP_LOCAL_OPEN_FRIENDING)
				secret_out[ret++] = r->GetSecret(c); // for receiving greeting from community members, it is a local option
		}
		break;
	case MCT_GROUP:
		{	// nothing so far
		}
		break;
	case MCT_USER_GREETING:
		{
			secret_out[ret++] = r->GetSecret(c); // secret is Mutual
		}
		break;
	}

	return ret;
}

MrcContactPoints::ContactPointMap* MrcContactPoints::_CreateContactPointMap(MrcContactsRepository* r, DWORD epoch) const
{
	auto* ret = _New(ContactPointMap);
	int64_t time = GetTimeFromEpoch(epoch);

	ASSERT(r);

	// add myself
	{	auto myself = r->GetMyself();
		if(myself)
		{
			SecretTypePtr secrets[2] = { r->GetSecret(myself), r->GetPublicKey(myself) };

			ret->AddContact(epoch, myself, 
							(const SecretType**)secrets, 
							(r->GetSocialPreference(myself) & MSP_FOLLOWER_CAST)? // public friend feed, secret can be Address or Secrets.Profile
								2:1
			);
		}
	}

	struct iter: public MrcContactIterator
	{
		ContactPointMap* ret;
		MrcContactsRepository* r;
		DWORD epoch;
		iter(ContactPointMap* map, MrcContactsRepository* x, DWORD e):ret(map), r(x), epoch(e){}
		bool OnContact(MrcContact c) override
		{	
			ASSERT(c);
			SecretTypePtr secret_out[SECRET_PERCONTACT_MAX];
			auto count = MrcContactPoints::_GetContactPointSecrets(r, c, secret_out);
			if(count)
				ret->AddContact(epoch, c, (const SecretType**)secret_out, count);

			return true;
		}
	};

	iter it(ret, r, epoch);
	r->ScanContacts(&it, time);

	return ret;
}

void MrcIdenticon(DWORD crc, rt::String& image_data, int background_brightness)
{
	static const char PngHeader[] = "\x89\x50\x4e\x47\x0d\x0a\x1a\x0a\x00\x00\x00\x0d\x49\x48\x44\x52\x00\x00\x01\x40\x00\x00\x01\x40\x08\x03\x00\x00\x00\xfa\x4e\x55\x98";
	static const char PngData[] = "\x00\x00\x01\xb4\x49\x44\x41\x54\x78\xda\xec\xd0\xc1\x11\x82\x00\x14\x43\x41\x50\x14\x15\xd4\xfe\xbb\xb5\x85\xe4\xf8\xc7\x7d\x05\x64\x32\xbb\x2c\x92\x24\x49\x92\x24\x49\x92\x24\x49\x92\x24\x49\x92\x24\x49\x92\x24\x49\x92\x24\x49\x92\x24\x49\x7f\xd2\x3d\x6f\xcd\xfb\xe6\x15\xab\xc5\x57\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x9c\x04\xf8\xca\xbb\xe4\xbd\xf3\x8a\xd5\xe2\x2b\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x4e\x02\xbc\xe5\x3d\xf2\xce\xbc\x62\xb5\xf8\x0a\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x93\x00\xf7\xbc\x67\xde\x91\x57\xac\x16\x5f\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x70\x12\xe0\x35\x6f\xcb\xfb\xe4\x15\xab\xc5\x57\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x04\x08\x10\x20\x40\x80\x00\x01\x02\x9c\x04\x28\x49\x92\x24\x49\x92\x24\x49\x92\x24\x49\x92\x24\x49\x92\x24\x49\x92\x24\x49\x92\x24\x49\x92\xa4\xd9\xfd\x04\x18\x00\x95\xcc\xf0\x34\x48\xab\xf6\xd5\x00\x00\x00\x00\x49\x45\x4e\x44\xae\x42\x60\x82";

	BYTE col_plat[8 + 3*16 + 4];
	memcpy(&col_plat[0], "\x00\x00\x00\x30\x50\x4c\x54\x45", 8);

	auto* cols = (rt::Vec3b*)&col_plat[8];

	cols[0] = background_brightness;
	
	bool dark_mode = background_brightness<120;
	rt::Vec3b one( (crc&0xf)<<3, ((crc>>5)&0x1f)<<2, ((crc>>11)&0xf)<<3 );
	one += dark_mode?120:60;

	rt::Vec3b zero;
	zero.Interpolate(cols[0], one, dark_mode?0.175f:0.075f);

	WORD last_byte = crc>>16;
	if (!last_byte) last_byte = crc;
	for(UINT i=1; i<16; i++)
	{
		if(last_byte&1)
			cols[i] = one;
		else
			cols[i] = zero;

		last_byte >>= 1;
	}
    sec::Hash<sec::HASH_CRC32>().Calculate(&col_plat[4], (4 + 3*16), &col_plat[8 + 3*16]);
	image_data = rt::SS(PngHeader) + rt::DS(col_plat, sizeof(col_plat)) + rt::SS(PngData);
}

} // namespace upw