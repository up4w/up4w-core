/* $Id: addr_is_reserved.c,v 1.3 2020/11/09 19:42:42 nanard Exp $ */
/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * Project : miniupnp
 * Web : http://miniupnp.free.fr/ or https://miniupnp.tuxfamily.org/
 * Author : Thomas BERNARD
 * copyright (c) 2005-2020 Thomas Bernard
 * This software is subjet to the conditions detailed in the
 * provided LICENSE file. */
#ifdef _WIN32
/* Win32 Specific includes and defines */
#include <winsock2.h>
#include <ws2tcpip.h>
#if !defined(_MSC_VER)
#include <stdint.h>
#else /* !defined(_MSC_VER) */
//typedef unsigned long uint32_t;
#endif /* !defined(_MSC_VER) */
#else /* _WIN32 */
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif /* _WIN32 */

/* List of IP address blocks which are private / reserved and therefore not suitable for public external IP addresses */
#define IP(a, b, c, d) (((a) << 24) + ((b) << 16) + ((c) << 8) + (d))
#define MSK(m) (32-(m))
static const struct { uint32_t address; uint32_t rmask; } reserved[] = {
	{ IP(  0U,   0,   0, 0), MSK( 8) }, /* RFC1122 "This host on this network" */
	{ IP( 10U,   0,   0, 0), MSK( 8) }, /* RFC1918 Private-Use */
	{ IP(100U,  64,   0, 0), MSK(10) }, /* RFC6598 Shared Address Space */
	{ IP(127U,   0,   0, 0), MSK( 8) }, /* RFC1122 Loopback */
	{ IP(169U, 254,   0, 0), MSK(16) }, /* RFC3927 Link-Local */
	{ IP(172U,  16,   0, 0), MSK(12) }, /* RFC1918 Private-Use */
	{ IP(192U,   0,   0, 0), MSK(24) }, /* RFC6890 IETF Protocol Assignments */
	{ IP(192U,   0,   2, 0), MSK(24) }, /* RFC5737 Documentation (TEST-NET-1) */
	{ IP(192U,  31, 196, 0), MSK(24) }, /* RFC7535 AS112-v4 */
	{ IP(192U,  52, 193, 0), MSK(24) }, /* RFC7450 AMT */
	{ IP(192U,  88,  99, 0), MSK(24) }, /* RFC7526 6to4 Relay Anycast */
	{ IP(192U, 168,   0, 0), MSK(16) }, /* RFC1918 Private-Use */
	{ IP(192U, 175,  48, 0), MSK(24) }, /* RFC7534 Direct Delegation AS112 Service */
	{ IP(198U,  18,   0, 0), MSK(15) }, /* RFC2544 Benchmarking */
	{ IP(198U,  51, 100, 0), MSK(24) }, /* RFC5737 Documentation (TEST-NET-2) */
	{ IP(203U,   0, 113, 0), MSK(24) }, /* RFC5737 Documentation (TEST-NET-3) */
	{ IP(224U,   0,   0, 0), MSK( 4) }, /* RFC1112 Multicast */
	{ IP(240U,   0,   0, 0), MSK( 4) }, /* RFC1112 Reserved for Future Use + RFC919 Limited Broadcast */
};
#undef IP
#undef MSK

/**
 * @return 1 or 0
 */
int addr_is_reserved(const char * addr_str)
{
	uint32_t addr_n, address;
	size_t i;

#if defined(_WIN32) && (!defined(_WIN32_WINNT_VISTA) || (_WIN32_WINNT < _WIN32_WINNT_VISTA))
	addr_n = inet_addr(addr_str);
	if (addr_n == INADDR_NONE)
		return 1;
#else
	/* was : addr_n = inet_addr(addr_str); */
	if (inet_pton(AF_INET, addr_str, &addr_n) < 0) {
		/* error */
		return 1;
	}
#endif

	address = ntohl(addr_n);

	for (i = 0; i < sizeof(reserved)/sizeof(reserved[0]); ++i) {
		if ((address >> reserved[i].rmask) == (reserved[i].address >> reserved[i].rmask))
			return 1;
	}

	return 0;
}
