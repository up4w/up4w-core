#pragma once
#include "../externs/miniposix/core/ext/botan/botan.h"
#include "../externs/miniposix/core/ext/ipp/ipp_core.h"

extern "C"
{
#define SODIUM_STATIC
#include "../externs/libsodium/libsodium/src/libsodium/include/sodium.h"
}

namespace upw
{

// AES for data encryption
typedef sec::DataBlock<32, true> AesSecret;

class AesCipher
{
	typedef sec::Cipher<sec::CIPHER_AES256> t_Cipher;
	t_Cipher	_Enc;
public:	
	static const UINT	InplaceBlockSize = t_Cipher::DataBlockSize*512;
	static const UINT	DataBlockSize = t_Cipher::DataBlockSize;
	static const UINT	NativeKeySize = t_Cipher::NativeKeySize;
	template<typename T>
	static T			AlignSize(T in){ return (in + DataBlockSize - 1)&(~(DataBlockSize-1)); }
	template<typename T>
	static bool			IsAligned(T in){ return (in&(DataBlockSize-1)) == 0; }

	template<typename T>
	explicit			AesCipher(const T& key){ SetKey(key); }
						AesCipher() = default;
	void				SetKey(LPCVOID key, UINT len){ _Enc.SetKey(key,len); }
	template<typename T>
	void				SetKey(const T& key){ SetKey(rt::GetDataPtr(key), rt::GetDataSize(key)); }
	// block chained encryption
	void				Encode(LPCVOID pPlain, LPVOID pCipher, UINT Len, UINT nonce){ ASSERT((Len&(DataBlockSize-1)) == 0); _Enc.EncryptBlockChained(pPlain, pCipher, Len, nonce); }
	void				Decode(LPCVOID pCipher, LPVOID pPlain, UINT Len, UINT nonce){ ASSERT((Len&(DataBlockSize-1)) == 0); _Enc.DecryptBlockChained(pCipher, pPlain, Len, nonce); }
	static void			ComputeKey(LPVOID pKey, LPCVOID data, UINT size){ t_Cipher::ComputeKey(pKey, data, size); }
};

typedef AesCipher		Cipher;
typedef AesSecret		CipherSecret;

#pragma pack(push, 1)
// ed25519 for user identity and key exchange

typedef sec::DataBlock<crypto_sign_ed25519_SEEDBYTES, true> ED_Seed;
typedef sec::DataBlock<crypto_sign_ed25519_BYTES, false> ED_Signature;
typedef sec::DataBlock<24, false> EC_Nonce;

struct ED_PublicKey: public sec::DataBlock<crypto_sign_ed25519_PUBLICKEYBYTES, false> // 32
{
	bool Verify(const ED_Signature& signature, const rt::String_Ref& str) const { return Verify(signature, str.Begin(), str.GetLength()); }
	bool Verify(const ED_Signature& signature, LPCVOID pMessage, SIZE_T MessageLen) const {	return 0 == crypto_sign_ed25519_verify_detached(signature, (LPCBYTE)pMessage, MessageLen, *this); }
};

struct ED_PrivateKey: public sec::DataBlock<crypto_sign_ed25519_SECRETKEYBYTES, true>
{
public:
	auto&	GetPublicKey() const { return *((const ED_PublicKey*)(&Bytes[crypto_sign_ed25519_SEEDBYTES])); } // crypto_sign_ed25519_sk_to_pk(key, *this);
	void	Sign(ED_Signature& signature_out, const rt::String_Ref& str) const { Sign(signature_out, str.Begin(), str.GetLength()); }
	void	Sign(ED_Signature& signature_out, LPCVOID pMessage, SIZE_T MessageLen) const { crypto_sign_ed25519_detached(signature_out, NULL, (LPCBYTE)pMessage, MessageLen, *this); }
};

struct EC_PublicKey: public sec::DataBlock<32, false>
{
	static const UINT SealSize = crypto_box_SEALBYTES;
	EC_PublicKey() = default;
	EC_PublicKey(const ED_PublicKey& x){ *this = x; }
	const ED_PublicKey& operator = (const ED_PublicKey& x){ crypto_sign_ed25519_pk_to_curve25519(*this, x);	return x; }
	void	Encrypt(LPCVOID msg, UINT msg_len, LPVOID cipher_out) const	{ crypto_box_seal((LPBYTE)cipher_out, (LPCBYTE)msg, msg_len, (LPCBYTE)this); }
};

struct EC_PrivateKey: public sec::DataBlock<32, true>
{
	static const UINT SealSize = crypto_box_SEALBYTES;
	EC_PrivateKey() = default;
	EC_PrivateKey(const ED_PrivateKey& x){ *this = x; }
	const ED_PrivateKey& operator = (const ED_PrivateKey& x){ crypto_sign_ed25519_sk_to_curve25519(*this, x); return x;	}
	bool	Decrypt(LPCVOID cipher, UINT cipher_len, LPVOID plain_out, const EC_PublicKey& pk) const { return crypto_box_seal_open((LPBYTE)plain_out, (LPCBYTE)cipher, cipher_len, (LPCBYTE)&pk, (LPCBYTE)this) == 0; }
};

struct EC_SharedSecret: public sec::DataBlock<32, true>
{
	EC_SharedSecret() = default;
	EC_SharedSecret(const EC_PublicKey& pub, const EC_PrivateKey& pri){ Compute(pub, pri); }
	void	Compute(const EC_PublicKey& pub, const EC_PrivateKey& pri);
};

class EC_Cryptography
{
	sec::DataBlock<32, true>	_nm;
public:
	static const UINT BoxSize = crypto_box_MACBYTES;
	EC_Cryptography() = default;
	EC_Cryptography(const EC_PublicKey& other, const EC_PrivateKey& mine){ SetKeys(other, mine); }

	void	SetKeys(const EC_PublicKey& other, const EC_PrivateKey& mine){ crypto_box_beforenm(_nm, other, mine); }
	void	Encrypt(const EC_Nonce& n, const rt::String_Ref& plaintext, LPVOID cipher) const { Encrypt(n, plaintext.Begin(), plaintext.GetLength(), cipher); }
	template<typename t_Plain, typename T>
	void	Encrypt(const EC_Nonce& n, t_Plain& plaintext, T& cipher) const { ASSERT(sizeof(plaintext) + BoxSize == sizeof(cipher));  Encrypt(n, &plaintext, sizeof(t_Plain), rt::_CastToNonconst(&cipher)); }
	bool	Encrypt(const EC_Nonce& n, LPCVOID plaintext, SIZE_T plaintext_len, LPVOID cipher) const { return 0 == crypto_box_detached_afternm(((LPBYTE)cipher) + crypto_box_MACBYTES, (LPBYTE)cipher, (LPCBYTE)plaintext, plaintext_len, n, _nm); }
	bool	Decrypt(const EC_Nonce& n, const rt::String_Ref& cipher, LPVOID plaintext) const { return Decrypt(n, cipher.Begin(), cipher.GetLength(), plaintext); }
	template<typename t_Cipher, typename T>
	bool	Decrypt(const EC_Nonce& n, t_Cipher& cipher, T& plaintext) const { ASSERT(sizeof(plaintext) + BoxSize == sizeof(cipher)); return Decrypt(n, &cipher, sizeof(t_Cipher), rt::_CastToNonconst(&plaintext)); }
	bool	Decrypt(const EC_Nonce& n, LPCVOID cipher, SIZE_T cipher_len, LPVOID plaintext) const;
};

struct PublicKey: public ED_PublicKey // 32-byte POD
{	
	TYPETRAITS_DECLARE_POD;
	static const UINT DWORD_SIZE = 8;

    DWORD			CRC32() const { return ipp::crc32(this, sizeof(PublicKey)); }
	void			GetDefaultName(rt::String& name) const { name = rt::SS("#") + rt::tos::Number(CRC32()%100000000); }
	DWORD			GetShardDword() const { return DWords[0]^DWords[DWORD_SIZE-2]^DWords[DWORD_SIZE/2-1]; }
	UINT			GetShardIndex(UINT shard_order) const { return GetShardDword()&GetShardBitmask(shard_order); }
	static DWORD	GetShardBitmask(UINT shard_order){ return ~(((DWORD)(-1))<<shard_order); }
	auto&			operator = (const ED_PublicKey& pk){ *(ED_PublicKey*)this = pk; return pk; }
	operator		const CipherSecret& () const { return *(const CipherSecret*)this; }

	PublicKey() = default;
	PublicKey(const PublicKey& pk) = default;
	PublicKey(const ED_PublicKey& pk):ED_PublicKey(pk){}
	PublicKey(const rt::String_Ref& str){ FromString(str); }
};

typedef ED_PrivateKey		PrivateKey;			// 64-byte POD
typedef EC_PublicKey		PublicEncryptor;	// 32-byte POD
typedef EC_PrivateKey		PrivateDecryptor;	// 32-byte POD
typedef ED_Seed				SecretSeed;			// 32-byte POD
typedef ED_Signature		SignatureData;		// 64-byte POD
typedef EC_Cryptography		Cryptography;		// 32-byte POD
typedef EC_SharedSecret		MutualSecret;		// 32-byte POD
typedef EC_Nonce			NonceData;			// 24-byte POD

static const uint32_t		SealBoxSize = Cryptography::BoxSize;
typedef sec::DataBlock<sizeof(CipherSecret) + SealBoxSize>					SealedCipherSecret;		// Send: receiver's PK + Sender's SK, Recv: receiver's SK + Sender's PK
typedef sec::DataBlock<sizeof(CipherSecret) + PublicEncryptor::SealSize>	EncryptedCipherSecret;	// Send: receiver's PK, Recv: receiver's SK

static_assert(sizeof(CipherSecret) == 32, "CipherSecret is not 32-bytes");
static_assert(sizeof(PublicKey) == 32, "PublicKey is not 32-bytes");

typedef sec::Hash<sec::HASH_SHA256>	Hasher;
inline Hasher&				GetHasher(){ thread_local Hasher _; _.Reset(); return _; }
inline void					HashCalculate(const void* d, uint32_t s, void* out){ auto&h=GetHasher(); h.Update(d,s); h.Finalize(out); }
inline auto&				GetSha512Hasher() { thread_local sec::Hash<sec::HASH_SHA512> _; _.Reset(); return _; }

struct HashValue: public sec::DataBlock<Hasher::HASHSIZE>
{
	void Hash(const void* d, uint32_t s){ HashCalculate(d, s, this); }
};

extern bool			MnemonicEncode(LPCVOID data, UINT size, rt::String& out);
extern bool			MnemonicDecode(const rt::String_Ref& code, LPVOID data, UINT size);
extern uint32_t		MnemonicAutoComplete(const rt::String_Ref& prefix, rt::String_Ref* out, UINT out_size);

typedef rt::tos::Base16OnStack<>					tos_base16;
typedef rt::tos::Base32CrockfordLowercaseOnStack<>	tos_base32;
typedef rt::tos::Base64OnStack<>					tos_base64;

#pragma pack(pop)
} // namespace upw

namespace std
{
template<>
struct hash<::upw::HashValue>: public rt::_details::hash_compare_fix<::upw::HashValue> {};
} // namespace std
