/***********************************************************
 SixXSd - The Daemon of SixXS
 by Jeroen Massar <jeroen@sixxs.net>
 (C) Copyright SixXS 2000-2013 All Rights Reserved
***********************************************************/

#ifndef STATS_H
#define STATS_H "SixXSd Statistics"

#include "sixxsd.h"

#define stats_in 0
#define stats_out 1

/* Statistics */
struct sixxsd_traffic
{
	uint64_t			last;				/* Last time packet in this direction was seen */
	uint64_t			packets, packets_tot;		/* Number of packets seen (last x min / total) */
	uint64_t			octets, octets_tot;		/* Number of octets seen (last x min / total) */
};

/* The 'last x min' are collected by popstatd and reset */

struct sixxsd_latency
{
	uint16_t			seq, _padding_;			/* Sequence number */
	uint16_t			num_sent, num_recv;		/* Number sent & received */
	uint64_t			min, max, tot;			/* Minimum, Max and Total latency */
	uint64_t			seq_seen;			/* Sequence numbers seen */
};

struct sixxsd_stats
{
	struct sixxsd_traffic		traffic[2];			/* Traffic in/out */
	struct sixxsd_latency		latency;			/* Latency */
};

#define reset_traffic(t)		\
	{				\
		(t)->packets = 0;	\
		(t)->octets = 0;	\
	}

#define reset_traffic_tot(t)		\
	{				\
		(t)->packets_tot = 0;	\
		(t)->octets_tot = 0;	\
	}

#define reset_latency(l)		\
	{				\
		(l)->num_sent = 0;	\
		(l)->num_recv = 0;	\
		(l)->min = UINT64_MAX;	\
		(l)->max = 0;		\
		(l)->tot = 0;		\
	}

#endif /* STATS_H */

