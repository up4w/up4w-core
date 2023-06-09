#pragma warning(disable: 4146)
#pragma warning(disable: 4267)
#pragma warning(disable: 4244)
#pragma warning(disable: 4838)

#include "../../externs/miniposix/core/rt/runtime_base.h"

extern "C"
{
#define SODIUM_STATIC
#include "./libsodium/src/libsodium/include/sodium.h"
// Doc:  https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html
}

namespace upw
{

namespace _details
{
struct _libsodium_init
{	_libsodium_init(){
		ASSERT(crypto_box_NONCEBYTES == 24);
		ASSERT(crypto_box_MACBYTES == 16);
		ASSERT(crypto_box_BEFORENMBYTES == 32);
		ASSERT(32 == crypto_pwhash_scryptsalsa208sha256_SALTBYTES);
		sodium_init(); 
	}
};
_libsodium_init __libsodium_init;

}
} // namespace dkm



#include "libs_inline_c.h"

extern "C"
{

#include "./libsodium/src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c"
#include "./libsodium/src/libsodium/crypto_auth/crypto_auth.c"
#include "./libsodium/src/libsodium/crypto_box/crypto_box.c"
#include "./libsodium/src/libsodium/crypto_box/crypto_box_easy.c"
#include "./libsodium/src/libsodium/crypto_box/crypto_box_seal.c"
#include "./libsodium/src/libsodium/crypto_core/hsalsa20/core_hsalsa20_api.c"
//#include "./libsodium/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20.c"
#include "./libsodium/src/libsodium/crypto_core/salsa20/core_salsa20_api.c"
//#include "./libsodium/src/libsodium/crypto_core/salsa20/ref/core_salsa20.c"
#include "./libsodium/src/libsodium/crypto_core/salsa2012/core_salsa2012_api.c"
//#include "./libsodium/src/libsodium/crypto_core/salsa2012/ref/core_salsa2012.c"
#include "./libsodium/src/libsodium/crypto_core/salsa208/core_salsa208_api.c"
//#include "./libsodium/src/libsodium/crypto_core/salsa208/ref/core_salsa208.c"
#include "./libsodium/src/libsodium/crypto_generichash/crypto_generichash.c"
#include "./libsodium/src/libsodium/crypto_generichash/blake2/generichash_blake2_api.c"
#include "./libsodium/src/libsodium/crypto_generichash/blake2/ref/blake2b-ref.c"
#include "./libsodium/src/libsodium/crypto_generichash/blake2/ref/generichash_blake2b.c"
#include "./libsodium/src/libsodium/crypto_hash/crypto_hash.c"
#include "./libsodium/src/libsodium/crypto_hash/sha256/hash_sha256_api.c"
//#include "./libsodium/src/libsodium/crypto_hash/sha256/cp/hash_sha256.c"
#include "./libsodium/src/libsodium/crypto_hash/sha512/hash_sha512_api.c"
//#include "./libsodium/src/libsodium/crypto_hash/sha512/cp/hash_sha512.c"
#include "./libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c"
#include "./libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c"
#include "./libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c"
#include "./libsodium/src/libsodium/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c"



//#include "./libsodium/src/libsodium/crypto_scalarmult/crypto_scalarmult.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519_api.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/donna_c64/base_curve25519_donna_c64.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/donna_c64/smult_curve25519_donna_c64.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/base_curve25519_ref10.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_0_curve25519_ref10.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_1_curve25519_ref10.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_add_curve25519_ref10.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_copy_curve25519_ref10.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_cswap_curve25519_ref10.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_frombytes_curve25519_ref10.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_invert_curve25519_ref10.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_mul121666_curve25519_ref10.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_mul_curve25519_ref10.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_sq_curve25519_ref10.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_sub_curve25519_ref10.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/fe_tobytes_curve25519_ref10.c"
//#include "./libsodium/src/libsodium/crypto_scalarmult/curve25519/ref10/scalarmult_curve25519_ref10.c"
#include "./libsodium/src/libsodium/crypto_secretbox/crypto_secretbox.c"
#include "./libsodium/src/libsodium/crypto_secretbox/crypto_secretbox_easy.c"
#include "./libsodium/src/libsodium/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305_api.c"
#include "./libsodium/src/libsodium/crypto_secretbox/xsalsa20poly1305/ref/box_xsalsa20poly1305.c"
#include "./libsodium/src/libsodium/crypto_shorthash/crypto_shorthash.c"
#include "./libsodium/src/libsodium/crypto_shorthash/siphash24/shorthash_siphash24_api.c"
#include "./libsodium/src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphash24.c"
#include "./libsodium/src/libsodium/crypto_sign/crypto_sign.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/sign_ed25519_api.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_0.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_1.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_add.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_cmov.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_copy.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_frombytes.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_invert.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_isnegative.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_isnonzero.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_mul.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_neg.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_pow22523.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_sq.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_sq2.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_sub.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/fe_tobytes.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_add.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_double_scalarmult.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_frombytes.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_madd.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_msub.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p1p1_to_p2.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p1p1_to_p3.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p2_0.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p2_dbl.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_0.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_dbl.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_tobytes.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_to_cached.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_p3_to_p2.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_precomp_0.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_scalarmult_base.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_sub.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/ge_tobytes.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/keypair.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/open.c"
//#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/sc_muladd.c"
//#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/sc_reduce.c"
#include "./libsodium/src/libsodium/crypto_sign/ed25519/ref10/sign.c"
#include "./libsodium/src/libsodium/crypto_sign/edwards25519sha512batch/sign_edwards25519sha512batch_api.c"
//#include "./libsodium/src/libsodium/crypto_sign/edwards25519sha512batch/ref/fe25519_edwards25519sha512batch.c"
//#include "./libsodium/src/libsodium/crypto_sign/edwards25519sha512batch/ref/ge25519_edwards25519sha512batch.c"
//#include "./libsodium/src/libsodium/crypto_sign/edwards25519sha512batch/ref/sc25519_edwards25519sha512batch.c"
//#include "./libsodium/src/libsodium/crypto_sign/edwards25519sha512batch/ref/sign_edwards25519sha512batch.c"
#include "./libsodium/src/libsodium/crypto_stream/crypto_stream.c"
#include "./libsodium/src/libsodium/crypto_stream/aes128ctr/stream_aes128ctr_api.c"
#include "./libsodium/src/libsodium/crypto_stream/chacha20/stream_chacha20_api.c"
//#include "./libsodium/src/libsodium/crypto_stream/chacha20/ref/stream_chacha20_ref.c"
#include "./libsodium/src/libsodium/crypto_stream/salsa20/stream_salsa20_api.c"
//#include "./libsodium/src/libsodium/crypto_stream/salsa20/ref/stream_salsa20_ref.c"
//#include "./libsodium/src/libsodium/crypto_stream/salsa20/ref/xor_salsa20_ref.c"
#include "./libsodium/src/libsodium/crypto_stream/salsa2012/stream_salsa2012_api.c"
//#include "./libsodium/src/libsodium/crypto_stream/salsa2012/ref/stream_salsa2012.c"
//#include "./libsodium/src/libsodium/crypto_stream/salsa2012/ref/xor_salsa2012.c"
#include "./libsodium/src/libsodium/crypto_stream/salsa208/stream_salsa208_api.c"
//#include "./libsodium/src/libsodium/crypto_stream/salsa208/ref/stream_salsa208.c"
//#include "./libsodium/src/libsodium/crypto_stream/salsa208/ref/xor_salsa208.c"
#include "./libsodium/src/libsodium/crypto_stream/xsalsa20/stream_xsalsa20_api.c"
//#include "./libsodium/src/libsodium/crypto_stream/xsalsa20/ref/stream_xsalsa20.c"
//#include "./libsodium/src/libsodium/crypto_stream/xsalsa20/ref/xor_xsalsa20.c"
#include "./libsodium/src/libsodium/crypto_verify/16/verify_16_api.c"
#include "./libsodium/src/libsodium/crypto_verify/16/ref/verify_16.c"
#include "./libsodium/src/libsodium/crypto_verify/32/verify_32_api.c"
#include "./libsodium/src/libsodium/crypto_verify/32/ref/verify_32.c"
#include "./libsodium/src/libsodium/crypto_verify/64/verify_64_api.c"
#include "./libsodium/src/libsodium/crypto_verify/64/ref/verify_64.c"
#include "./libsodium/src/libsodium/sodium/core.c"
#include "./libsodium/src/libsodium/sodium/runtime.c"
#include "./libsodium/src/libsodium/sodium/utils.c"
#include "./libsodium/src/libsodium/sodium/version.c"

#include "./libsodium/src/libsodium/randombytes/randombytes.c"
#include "./libsodium/src/libsodium/randombytes/nativeclient/randombytes_nativeclient.c"
//#include "./libsodium/src/libsodium/randombytes/salsa20/randombytes_salsa20_random.c"

#include "./libsodium/src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305_api.c"


#include "./libsodium/src/libsodium/crypto_auth/hmacsha256/auth_hmacsha256_api.c"
#include "./libsodium/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512_api.c"
//#include "./libsodium/src/libsodium/crypto_auth/hmacsha256/cp/hmac_hmacsha256.c"
//#include "./libsodium/src/libsodium/crypto_auth/hmacsha256/cp/verify_hmacsha256.c"
#include "./libsodium/src/libsodium/crypto_auth/hmacsha512256/auth_hmacsha512256_api.c"
//#include "./libsodium/src/libsodium/crypto_auth/hmacsha512/cp/hmac_hmacsha512.c"
//#include "./libsodium/src/libsodium/crypto_auth/hmacsha512/cp/verify_hmacsha512.c"
//#include "./libsodium/src/libsodium/crypto_auth/hmacsha512256/cp/hmac_hmacsha512256.c"
//#include "./libsodium/src/libsodium/crypto_auth/hmacsha512256/cp/verify_hmacsha512256.c"

}

