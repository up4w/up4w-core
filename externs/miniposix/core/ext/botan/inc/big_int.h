#pragma once




#include "botan_inc.h"

namespace Botan
{
/** \defgroup botan botan
 * @ingroup ext
 *  @{
*/
/** \defgroup Functions_botan Functions_botan
* @ingroup botan
*  @{
*/
INLFUNC void BigIntAssign(BigInt& bi, LPCVOID p, SIZE_T len)
{	
	auto& raw = bi.get_word_vector();
	raw.resize((len/sizeof(Botan::word) + 1 + 7)&~7);
	memcpy(raw.data(), p, len);
	memset(len + (LPBYTE)raw.data(), 0, raw.size()*sizeof(Botan::word) - len);
}

template<typename T_POD>
INLFUNC void BigIntAssign(BigInt& bi, const T_POD& x){ BigIntAssign(bi, &x, sizeof(x)); }
INLFUNC void BigIntAssign(BigInt& bi, const rt::String_Ref& x){ BigIntAssign(bi, x.Begin(), x.GetLength()); }

INLFUNC void BigIntToString(const BigInt& x, rt::String& out)
{
	out = "0x";
	if(x.is_nonzero())
	{
		auto& raw = x.get_word_vector();
		LPCBYTE end = (LPCBYTE)raw.data();
		LPCBYTE p = end + raw.size()*sizeof(Botan::word) - 1;
		for(; p>=end; p--)
		{
			BYTE v = *p;
			int c1 = v>>4;
			int c2 = v&0xf;
			out += (char)((c1>9)?('a'+c1-10):('0'+c1));
			out += (char)((c1>9)?('a'+c2-10):('0'+c2));
		}
	}
}
/** @}*/
/** @}*/
} // namespace Botan


