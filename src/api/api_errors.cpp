#include "local_api.h"

namespace upw
{

namespace _details
{
struct _api_error
{
	uint32_t	err_num;
	rt::SS		err_msg;
	operator uint32_t () const { return err_num; }
};

static const _api_error _api_errors[] = 
{
	{ 1,	"`module.action` is ill-formatted" },
	{ 2,	"unavailable module in `$`" },
	{ 3,	"unsupported action in `$`" },
	{ 4,	"`arg` must be the last url query parameter" },
	{ 5,	"the action is not supported on synchronous connection" },
	{ 6,	"the action is not supported on asynchronous connection" },
	{ 7,	"internal error" },
	{ 101,	"core has been shutdown" },
	{ 102,	"core has been initialized already" },
	{ 103,	"`$` should be specified as a storage directory" },
	//{ 104,	"`kvs.kv_dir` is not specified" },
	{ 105,	"key `$` is unexpected" },
	{ 106,	"`mrc.default_swarm` should be specified, since default swarm is not specified in the command line (/default_swarm:<dht_address_base16>)" },
	{ 107,	"\"$\" is not a well-formatted encoding of a DHT address" },
	{ 108,	"core is not initialized yet" },
	{ 109,	"`$` is not specified or is ill-formatted" },
	{ 110,	"`seed` or `mnemonic` should be specified for user sign-in" },
	{ 111,	"`seed` or `mnemonic` is ill-formatted" },
	{ 112,	"corrupted sign-in secret data derived from `seed` or `mnemonic`" },
	{ 113,	"recipient \"$\" is not found" },
	{ 114,	"`$` is not a well-formatted base64 encoding of 32-byte data" },
	{ 115,	"contact is not exist" },
	{ 116,	"`$` should be a positive integer of 16 bits"},
	{ 117,	"action is not available without a sign-in user"},
	{ 118,	"swarm \"$\" is not available"},
	{ 119,	"no default swarm available"},
	{ 120,	"media relay core (MDS) is not available"},
	{ 121,	"media blob `$` is not exist"},
	{ 122,	"access to media blob `$` is not authorized"},
	{ 123,	"asynchronous gdp data loading is timeout"},

	{ 0xfffffff,	"" }
};
} // namespace _details

rt::String_Ref LocalApiResponder::GetErrorMessage(uint32_t err_code)
{
	auto pos = rt::BinarySearch(_details::_api_errors, sizeofArray(_details::_api_errors), err_code);
	if(pos >= 0 && pos < sizeofArray(_details::_api_errors) && _details::_api_errors[pos].err_num == err_code)
	{
		return _details::_api_errors[pos].err_msg;
	}

	return nullptr;
}

} // namespace upw