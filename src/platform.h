/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
***********************************************************/

#ifndef PLATFORM_H
#define PLATFORM_H "The Daemon Of SixXS"

#ifdef _LINUX
#include <features.h>
#endif

#define __FAVOR_BSD 42

#ifdef __GNUC__
#define PACKED __attribute__((packed))
#define ALIGNED __attribute__((aligned))
#define UNUSED __attribute__ ((__unused__))
#else
#define PACKED
#define ALIGNED
#define UNUSED
#endif

#ifndef ATTR_FORMAT
#if defined(__GNUC__)
#define ATTR_RESTRICT __restrict
#define ATTR_FORMAT(type, x, y) __attribute__ ((format(type, x, y)))
#else
#define ATTR_FORMAT(type, x, y)	/* nothing */
#define ATTR_RESTRICT		/* nothing */
#endif
#endif

/* MD5 routines require the correct types */
#define __USE_BSD 1

/* Get the PRI* and SCN* formats from inttypes.h */
#define __STDC_FORMAT_MACROS 1

#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#ifdef _DARWIN
#include <netinet/in_systm.h>
#define O_LARGEFILE 0
#define ENODATA EFTYPE
#define _BSD_SOCKLEN_T_
#include <mach/mach_host.h>
#include <mach/mach_port.h>
#include <mach/clock.h>
#include <sys/uio.h>
/*
 * Darwin doesn't have TUN/TAP support per default
 * Use Homebrew (http://brew.sh) to install it:
 *   brew install tuntap
 * for compiling convienience we have included the ioctl's here
 */
#define TUNSIFHEAD _IOW('t', 96, int)
#define TUNGIFHEAD _IOR('t', 97, int)
#endif

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/resource.h>
#include <net/ethernet.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#ifndef ICMP_PKT_FILTERED
#ifdef ICMP_UNREACH_FILTER_PROHIB
#define ICMP_PKT_FILTERED ICMP_UNREACH_FILTER_PROHIB
#else
#error "No definition for ICMP_PKT_FILTERED"
#endif
#endif

#ifndef ICMP_DEST_UNREACH
#ifdef ICMP_UNREACH
#define ICMP_DEST_UNREACH ICMP_UNREACH
#else
#error "No definition for ICMP_DEST_UNREACH"
#endif
#endif

#ifndef ICMP_NET_UNREACH
#ifdef ICMP_UNREACH_NET
#define ICMP_NET_UNREACH ICMP_UNREACH_NET
#else
#error "No definition for ICMP_NET_UNREACH"
#endif
#endif

#ifndef ICMP_PARAMETERPROB
#ifdef ICMP_PARAMPROB
#define ICMP_PARAMETERPROB ICMP_PARAMPROB
#else
#error "No definition for ICMP_PARAMETERPROB"
#endif
#endif

#ifndef ICMP_TIME_EXCEEDED
#ifdef ICMP_TIMXCEED
#define ICMP_TIME_EXCEEDED ICMP_TIMXCEED
#else
#error "No definition for ICMP_TIME_EXCEEDED"
#endif
#endif

#ifndef ICMP_EXC_TTL
#ifdef ICMP_TIMXCEED_INTRANS
#define ICMP_EXC_TTL ICMP_TIMXCEED_INTRANS
#else
#error "No definition for ICMP_EXC_TTL"
#endif
#endif

#ifndef ICMP_FRAG_NEEDED
#ifdef ICMP_UNREACH_NEEDFRAG
#define ICMP_FRAG_NEEDED ICMP_UNREACH_NEEDFRAG
#else
#error "No definition for ICMP_FRAG_NEEDED"
#endif
#endif

#ifndef ICMP_PROT_UNREACH
#ifdef ICMP_UNREACH_PROTOCOL
#define ICMP_PROT_UNREACH ICMP_UNREACH_PROTOCOL
#else
#error "No definition for ICMP_PROT_UNREACH"
#endif
#endif

#ifndef ICMP_SOURCE_QUENCH
#ifdef ICMP_SOURCEQUENCH
#define ICMP_SOURCE_QUENCH ICMP_SOURCEQUENCH
#else
#error "No definition for ICMP_SOURCE_QUENCH"
#endif
#endif

#ifndef ICMP_TIMESTAMP
#ifdef ICMP_TSTAMP
#define ICMP_TIMESTAMP ICMP_TSTAMP
#else
#error "No definition for ICMP_TIMESTAMP"
#endif
#endif

#ifndef ICMP_TIMESTAMPREPLY
#ifdef ICMP_TSTAMPREPLY
#define ICMP_TIMESTAMPREPLY ICMP_TSTAMPREPLY
#else
#error "No definition for ICMP_TIMESTAMPREPLY"
#endif
#endif

#ifndef ICMP_INFO_REQUEST
#ifdef ICMP_IREQ
#define ICMP_INFO_REQUEST ICMP_IREQ
#else
#error "No definition for ICMP_INFO_REQUEST"
#endif
#endif

#ifndef ICMP_INFO_REPLY
#ifdef ICMP_IREQREPLY
#define ICMP_INFO_REPLY ICMP_IREQREPLY
#else
#error "No definition for ICMP_INFO_REPLY"
#endif
#endif

#ifndef ICMP_ADDRESS
#ifdef ICMP_MASKREQ
#define ICMP_ADDRESS ICMP_MASKREQ
#else
#error "No definition for ICMP_ADDRESS"
#endif
#endif

#ifndef ICMP_ADDRESSREPLY
#ifdef ICMP_MASKREPLY
#define ICMP_ADDRESSREPLY ICMP_MASKREPLY
#else
#error "No definition for ICMP_ADDRESS_REPLY"
#endif
#endif

#ifndef ICMP6_DST_UNREACH_POLICY
#define ICMP6_DST_UNREACH_POLICY 5
#endif

struct icmp_hdr
{
	uint8_t		icmp_type;
	uint8_t		icmp_code;
	uint16_t	icmp_cksum;
	uint32_t	icmp_param;
};

struct nd_neigh_solicit
{
	struct in6_addr		nd_ns_target;		/* target address */
};

struct nd_neigh_advert
{
	struct in6_addr         nd_na_target;		/* target address */
#if 0
	uint8_t			nd_no_type;		/* Option providing the target MAC address */
	uint8_t			nd_no_len;		/* Length (1) */
	uint8_t			nd_no_mac[6];		/* MAC address */
#endif
};

#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/un.h>
#ifndef _DARWIN
#ifndef _OPENBSD
#include <sys/statvfs.h>
#endif
#endif
#include <sys/wait.h>

#ifdef _LINUX
#include <netpacket/packet.h>
#endif

#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <locale.h>
#include <limits.h>

#include <getopt.h>
#define GOT_GETOPT_LONG 1

#include <net/if_arp.h>
#include <net/if.h>

#ifdef _LINUX
#include <linux/if_tun.h>
#include <linux/ipv6.h>
#endif

#ifdef _FREEBSD
#include <net/if_tun.h>
#endif

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#define SOCKET			int64_t
#define INVALID_SOCKET		-1
#define closesocket(s)		close(s)

/* OS Thread & Mutex Abstraction */
typedef pthread_t		os_thread;
typedef pthread_t		os_thread_id;
typedef pthread_mutex_t		mutex;
#define os_getthisthread	pthread_self
#define os_getthisthreadid	pthread_self
#define os_thread_equal(a,b)	pthread_equal(a,b)
#define mutex_init(m)		{									\
					pthread_mutexattr_t attr;					\
					pthread_mutexattr_init(&attr);					\
					pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);	\
					pthread_mutex_init(&m, &attr);					\
					pthread_mutexattr_destroy(&attr);				\
				}
#define mutex_lock(m)		pthread_mutex_lock(&m)
#define mutex_trylock(m)	pthread_mutex_trylock(&m)
#define mutex_release(m)	pthread_mutex_unlock(&m)
#define mutex_destroy(m)	pthread_mutex_destroy(&m)

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <signal.h>
#include <math.h>
#include <assert.h>

#ifdef _FREEBSD
#include <sys/uio.h>
#endif

#ifndef BYTE_ORDER
#error "BYTE_ORDER not defined"
#endif

#ifndef LITTLE_ENDIAN
#error "LITTLE_ENDIAN not defined"
#endif

#ifndef BIG_ENDIAN
#error "BIG_ENDIAN not defined"
#endif

/* Determine Endianness */
#if BYTE_ORDER == LITTLE_ENDIAN
        /* 1234 machines */
#elif BYTE_ORDER == BIG_ENDIAN
        /* 4321 machines */
#elif BYTE_ORDER == PDP_ENDIAN
        /* 3412 machines */
#error "PDP endianness not supported yet!"
#else
#error "unknown endianness!"
#endif

/* We want 64bit aligned "void *" */
#define SIXXS_POINTERS "SIXXS"
typedef uint64_t	PTR;
typedef void		VOID;

/* Both IPv4 and IPv6 can be stored here */
union ipaddress
{
	struct in6_addr	ip6;
	uint64_t	a64[2];
	uint32_t	a32[4];
	uint16_t	a16[8];
	uint8_t		a8[16];
} PACKED;

typedef union ipaddress IPADDRESS;

#define ipaddress_ipv4(addr) (&(addr)->a8[12])
#define ipaddress_ipv6(addr) (&(addr)->a8[0])

#ifndef ETH_P_IP
#define ETH_P_IP		0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6		0x86dd
#endif

/* VLAN Defines */
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN  6
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q	0x8100
#endif

struct ether_vlan_hdr
{
	u_char		evh_dhost[ETHER_ADDR_LEN];
	u_char		evh_shost[ETHER_ADDR_LEN];
	u_int16_t	evh_encap_proto;
	u_int16_t	evh_tag;
	u_int16_t	evh_proto;
};

/* To make alignment easy, just use a 64bit boolean on 64bit archs */
#ifdef _64BIT
typedef uint64_t	BOOL;
typedef uint64_t	addressnum_t;
#else
typedef uint32_t	BOOL;
typedef uint32_t	addressnum_t;
#endif

#define memzero(obj,len) memset(obj,0,len)

/* Length handling */
#define lengthof(x) ((uint64_t)(sizeof(x)/sizeof(x[0])))

#if !defined(__GNUC__)
    #define __builtin_expect(foo,bar) (foo)
    #define expect(foo,bar) (foo)
#else
#if __GNUC__ < 3
#error Please use GCC 3.x+
#else
    #define expect(foo,bar) __builtin_expect((long)(foo),bar)
#endif
#endif

#define __likely(foo) expect((foo),1)
#define __unlikely(foo) expect((foo),0)

/* Listen queue */
#define LISTEN_QUEUE		128

/* Backlog */
#define BACKLOG			256

/* Not available on some platforms */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL		0
#endif
#ifndef IPPROTO_SCTP
#define IPPROTO_SCTP		132
#endif

#ifndef IPPROTO_EGP
#define IPPROTO_EGP		8
#endif

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY		26
#endif

#ifndef IPPROTO_RSVP
#define IPPROTO_RSVP		46
#endif

#ifndef IPPROTO_IPV4
#define IPPROTO_IPV4		IPPROTO_IP
#endif

#ifndef IPPROTO_ICMPV4
#define IPPROTO_ICMPV4		IPPROTO_ICMP
#endif

#ifndef AF_INET4
#define AF_INET4		AF_INET
#endif

#ifndef SOL_IPV6
#define SOL_IPV6		IPPROTO_IPV6
#endif

#ifndef IPPROTO_PIM
#define IPPROTO_PIM		103
#endif

#ifndef IPPROTO_MH
#define IPPROTO_MH		135
#endif

#ifndef IPPROTO_HIP
#define IPPROTO_HIP		139
#endif

#ifndef IPPROTO_SHIM6
#define IPPROTO_SHIM6		140
#endif

#ifndef O_LARGEFILE
#define O_LARGEFILE		0
#ifdef _LINUX
#warning "O_LARGEFILE not available, while this is a linux platform!?"
#endif
#endif

#ifndef MAP_POPULATE
#define MAP_POPULATE		0
#endif

#ifndef ENODATA
#define ENODATA			ENOENT
#endif

#ifndef SO_REUSEPORT
#define SO_REUSEPORT 15
#endif

#ifndef ntohll
#define ntohll(x) htonll(x)
#endif

#ifndef htonll
#if BYTE_ORDER == LITTLE_ENDIAN
#define htonll(x) ((htonl((x >> 32) & UINT32_MAX) + ((uint64_t) (htonl(x & UINT32_MAX)) << 32)))
#else
#define htonll(x) (x)
#endif
#endif

struct grehdr
{
	uint8_t		chksum_present;		/* Actually only the first bit */
	uint8_t		version;		/* Actually only the last 3 bits */
	uint16_t	proto;			/* The protocol */
	/* opt: uint16_t checksum */
	/* opt: reserved 1 */
};

/* Debug uncommenting mechanism */
#ifdef DEBUG
#define D(x) x
#else
#define D(x) {}
#endif

#ifdef CALLGRIND
#include <valgrind/callgrind.h>
#endif
#include "list.h"
#include "common.h"

#define stddbg stderr

#endif /* PLATFORM_H */

