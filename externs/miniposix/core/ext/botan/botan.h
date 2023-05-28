#pragma once


/** \defgroup botan botan
 * @ingroup ext
 *  @{
 */

#include "./inc/datablock.h"
#include "./inc/big_int.h"
#include "./inc/hash.h"
#include "./inc/cipher.h"
#include "./inc/ecc.h"
#include "./inc/botan_inc.h"

#if defined(PLATFORM_ANDROID) && defined (__aarch64__)
#include "./platforms/android_arm64/openssl_crypto.h"
#endif


namespace sec
{
/** \defgroup botan botan
 * @ingroup ext
 *  @{
 */

class TLS: protected Botan::TLS::Callbacks
{
	rt::BufferEx<BYTE>		__RecvBuf;
	UINT					__RecvAteSize;
	
protected:
	virtual void tls_emit_data(const uint8_t data[], size_t size);
	virtual void tls_record_received(Botan::u64bit seq_no, const uint8_t data[], size_t size);
	virtual void tls_alert(Botan::TLS::Alert alert){}
	virtual bool tls_session_established(const Botan::TLS::Session& session);
	virtual void tls_session_activated(){};
	virtual void tls_verify_cert_chain(	const std::vector<Botan::X509_Certificate>& cert_chain,
										const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp_responses,
										const std::vector<Botan::Certificate_Store*>& trusted_roots,
										Botan::Usage_Type usage,
										const std::string& hostname,
										const Botan::TLS::Policy& policy);

	rt::Buffer<BYTE>		_ExpectedPubKey;

public:
	typedef bool (*TLS_SocketRecv_CB)(LPVOID buf, UINT buf_size, UINT&read, LPVOID cookie);
	typedef bool (*TLS_SocketSend_CB)(LPCVOID buf, UINT buf_size, LPVOID cookie);

protected:
	bool	_NoErrorOccurred;
	bool	_CertificateError;
	bool	_Init;
	BYTE	_BotanRngObject[sizeof(Botan::AutoSeeded_RNG)];
	BYTE	_BotanTLSObject[sizeof(Botan::TLS::Client)];

	TLS_SocketRecv_CB	_RecvCB;
	TLS_SocketSend_CB	_SendCB;
	LPVOID				_CB_Cookie;

public:
	TLS(TLS_SocketRecv_CB recv_cb, TLS_SocketSend_CB send_cb, LPVOID cookie = nullptr);
	~TLS();
	bool	Recv(LPVOID buf, UINT buf_size, UINT&read);
	bool	Send(LPCVOID buf, UINT buf_size);
	bool	Create(const rt::String_Ref& hostname);
	void	Destroy();
	bool	IsCreate() const { return _Init; }
	void	SetExpectedServerPublicKey(LPCVOID data = 0, UINT data_size = 0);
	bool	HasCertificateError() const { return _CertificateError; }
};

/** \defgroup Functions_Botan Functions_Botan
* @ingroup botan
*  @{
*/

inline void Randomize(LPVOID p, UINT len) { if(os::Randomize(p, len))return; Botan::AutoSeeded_RNG().randomize((LPBYTE)p, len); }

template<typename T>
inline void Randomize(T& d){ Randomize(&d, sizeof(T)); }

/** @}*/
/** @}*/
} // namespace sec
/** @}*/
