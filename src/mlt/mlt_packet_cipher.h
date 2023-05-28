#pragma once
#include <shared_mutex>

#include "../netsvc_core.h"
#include "../netsvc_types.h"
#include "../../src/dht/dht_base.h"
#include "../../externs/miniposix/core/os/multi_thread.h"
#include "../../externs/miniposix/core/ext/botan/inc/datablock.h"
#include "../../externs/miniposix/core/ext/sparsehash/sparsehash.h"
#include "../../externs/miniposix/core/ext/botan/botan.h"

#include "mlt_common.h"

namespace upw
{

struct MLT_PlainBodyBuffer
{
private:
	static const constexpr uint16_t BUFFER_LEN = 2048;
	union {
		uint16_t offset = sizeof(offset);
		uint8_t buffer[BUFFER_LEN];
	};
	static const constexpr uint16_t MIN_LEN = sizeof(offset);

public:
	template<typename T>
	T* Allocate()
	{
		return (T*)Allocate(sizeof(T));
	}
	uint8_t* Allocate(uint16_t numBytes)
	{
		if(numBytes <= BUFFER_LEN - offset)
		{
			offset += numBytes;
			return buffer + offset - numBytes;
		}

		return nullptr;
	}
	void Deallocate(uint16_t numBytes)
	{
		if(numBytes <= offset - MIN_LEN)
			offset -= numBytes;
	}
	uint16_t GetLength()
	{
		return offset - MIN_LEN;
	}
	uint8_t* GetBuffer()
	{
		return buffer + MIN_LEN;
	}

	bool CipherAndAppendToPacket(PacketBuf<> &inoutPacketBuf, const MLT_TunnelCipherSecret &secret, uint32_t nonce)
	{
		MLT_TunnelCipher cipher;

		// pad to multiple of cipher-block-size
		uint16_t cipheredSize = offset;
		if(offset % MLT_TunnelCipher::DataBlockSize != 0)
		{
			uint8_t numPaddingBytes = MLT_TunnelCipher::DataBlockSize - offset % MLT_TunnelCipher::DataBlockSize;
			uint8_t *pPadding = Allocate(numPaddingBytes);
			if(!pPadding)
				return false;
			memset(pPadding, 0, numPaddingBytes);
			Deallocate(numPaddingBytes);
			cipheredSize += numPaddingBytes;
		}

		// claim buffer for the data
		// output buffer needs to have extra space to nonce at the beginning
		uint8_t *pDst = (uint8_t *)inoutPacketBuf.Claim(sizeof(nonce) + cipheredSize);
		if(!pDst)
			return false;

		// write out nonce
		*(uint32_t*)pDst = nonce;

		// cipher to destination buffer
		cipher.SetKey(rt::GetDataPtr(secret), rt::GetDataSize(secret));
		cipher.EncryptBlockChained(buffer, pDst + sizeof(nonce), cipheredSize, nonce);

		// commit 
		inoutPacketBuf.Commit(sizeof(nonce) + cipheredSize);

		return true;
	}

	bool DecipherFromPacket(const uint8_t *pCipherBlock, uint16_t cipherBlockLen, const MLT_TunnelCipherSecret &secret)
	{
		uint32_t nonce;
		if(cipherBlockLen < sizeof(nonce))
			return false;
		nonce = *(uint32_t*)pCipherBlock;
		pCipherBlock += sizeof(nonce);
		cipherBlockLen -= sizeof(nonce);

		if(cipherBlockLen % MLT_TunnelCipher::DataBlockSize != 0)
			return false;

		if(cipherBlockLen > BUFFER_LEN)
			return false;

		MLT_TunnelCipher cipher;
		cipher.SetKey(rt::GetDataPtr(secret), rt::GetDataSize(secret));
		cipher.DecryptBlockChained(pCipherBlock, buffer, cipherBlockLen, nonce);

		if(offset > cipherBlockLen)
			return false;

		return true;
	}
};

} // namespace upw