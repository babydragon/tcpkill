/*
 * tcpkill.c
 *
 * Kill TCP connections already in progress.
 *
 * Copyright (c) 2000 Dug Song <dugsong@monkey.org>
 *
 * $Id: tcpkill.c,v 1.17 2001/03/17 08:10:43 dugsong Exp $
 */

#include <sys/types.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>
#include <libnet.h>
#include <pcap.h>
#include <pthread.h>

#include "pcaputil.h"
#include "version.h"

#define DEFAULT_SEVERITY	3

int	Opt_severity = DEFAULT_SEVERITY;
int	pcap_off;
pcap_t  *pd;
int     Opt_max_kill = 0;
int     kill_counter = 0;

struct tcp_connection {
    u_short sport;
    u_short dport;
    char *src;
    char *dst;
    libnet_t *l;
};

static void
usage(void)
{
	fprintf(stderr, "Version: " VERSION "\n"
		"Usage: tcpkill [-i interface] [-m max kills] [-1..9] -s SRC_IP:PORT -d DST_IP:PORT\n");
	exit(1);
}

static void
tcp_kill_cb(u_char *user, const struct pcap_pkthdr *pcap, const u_char *pkt)
{
	struct libnet_ipv4_hdr *ip;
	struct libnet_tcp_hdr *tcp;
	char ctext[64];
	u_int32_t seq, win;
	int i, len;
	libnet_t *l;

	l = (libnet_t *)user;
	pkt += pcap_off;
	len = pcap->caplen - pcap_off;

	ip = (struct libnet_ipv4_hdr *)pkt;
	if (ip->ip_p != IPPROTO_TCP)
		return;
	
	tcp = (struct libnet_tcp_hdr *)(pkt + (ip->ip_hl << 2));
	if (tcp->th_flags & (TH_SYN|TH_FIN|TH_RST))
		return;

	seq = ntohl(tcp->th_ack);
	win = ntohs(tcp->th_win);
	
	snprintf(ctext, sizeof(ctext), "%s:%d > %s:%d:",
		 libnet_addr2name4(ip->ip_src.s_addr, LIBNET_DONT_RESOLVE),
		 ntohs(tcp->th_sport),
		 libnet_addr2name4(ip->ip_dst.s_addr, LIBNET_DONT_RESOLVE),
		 ntohs(tcp->th_dport));
	
	for (i = 0; i < Opt_severity; i++) {
		seq += (i * win);
		
		libnet_clear_packet(l);
		
		libnet_build_tcp(ntohs(tcp->th_dport), ntohs(tcp->th_sport),
				 seq, 0, TH_RST, 0, 0, 0, LIBNET_TCP_H, 
				 NULL, 0, l, 0);
		
		libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0,
				  libnet_get_prand(LIBNET_PRu16), 0, 64,
				  IPPROTO_TCP, 0, ip->ip_dst.s_addr,
				  ip->ip_src.s_addr, NULL, 0, l, 0);
		
		if (libnet_write(l) < 0)
			warn("write");
		
		fprintf(stderr, "%s R %lu:%lu(0) win 0\n",
                        ctext,
                        (unsigned long) seq,
                        (unsigned long) seq);
	}

        ++kill_counter;
        if (Opt_max_kill && kill_counter >= Opt_max_kill) {
          pcap_breakloop(pd);
        }
}

static int build_syn(libnet_t *l, u_short sport, u_short dport, char *srchost, char *dsthost)
{
    printf("send fake sync package from %s:%d to %s:%d\n", dsthost, dport, srchost, sport);
    struct in_addr ip_src, ip_dst;
    ip_src.s_addr = inet_addr(srchost);
    ip_dst.s_addr = inet_addr(dsthost);
    u_int32_t seq = 12345;
    libnet_clear_packet(l);
    libnet_build_tcp(dport, sport,
            seq, 0, TH_SYN, 0, 0, 0, LIBNET_TCP_H,
            NULL, 0, l, 0);
    libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_TCP_H, 0,
            libnet_get_prand(LIBNET_PRu16), 0, 64,
            IPPROTO_TCP, 0, ip_dst.s_addr,
            ip_src.s_addr, NULL, 0, l, 0);

    if (libnet_write(l) < 0) {
        printf("send failed.\n");
        warn("write");
    } else {
        printf("send succ\n");
    }
    return 0;
}

void * trigger(void *data)
{
    struct tcp_connection *d = (struct tcp_connection*)data;
    int count = 5;
    while(count --) {
        sleep(1);
        build_syn(d->l, d->sport, d->dport, d->src, d->dst);
    }
    return NULL;
}

static int split(char *in, int *port, char **host) {
    int i = 0;
    while(in[i] && in[i]!=':') {
        i++;
    }
    if (in[i] == 0) {
        warn("error in addr.");
        exit(1);
    }
    in[i] = 0;
    *port = atoi(in + i + 1);
    *host = in;
    return 0;
}


int
main(int argc, char *argv[])
{
	extern char *optarg;
	extern int optind;
	int c;
	char *p, *intf, *filter, ebuf[PCAP_ERRBUF_SIZE];
	char libnet_ebuf[LIBNET_ERRBUF_SIZE];
	libnet_t *l, *l_sync;
	int sport, dport;
	char *src = NULL, *dst = NULL;
	
	intf = NULL;
	
	while ((c = getopt(argc, argv, "i:m:s:d:123456789h?V")) != -1) {
		switch (c) {
		case 'i':
			intf = optarg;
			break;
		case 'm':
			Opt_max_kill = atoi(optarg);
			break;
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			p = argv[optind - 1];
			if (p[0] == '-' && p[1] == c && p[2] == '\0')
				Opt_severity = atoi(++p);
			else
				Opt_severity = atoi(argv[optind] + 1);
			break;
		case 's':
			split(optarg, &sport, &src);
			break;
		case 'd':
			split(optarg, &dport, &dst);
			break;
		default:
			usage();
			break;
		}
	}
	if (intf == NULL && (intf = pcap_lookupdev(ebuf)) == NULL)
		errx(1, "%s", ebuf);
	
	static char f[1024];
	sprintf(f, "src port %d and dst port %d and src host %s and dst host %s", sport, dport, src, dst);
	filter = f;
	
	if ((pd = pcap_init(intf, filter, 64)) == NULL)
		errx(1, "couldn't initialize sniffing");

	if ((pcap_off = pcap_dloff(pd)) < 0)
		errx(1, "couldn't determine link layer offset");
	
	if ((l = libnet_init(LIBNET_RAW4, intf, libnet_ebuf)) == NULL)
		errx(1, "couldn't initialize sending");

	if ((l_sync = libnet_init(LIBNET_RAW4, intf, libnet_ebuf)) == NULL)
		errx(1, "couldn't initialize sending");
	
	libnet_seed_prand(l);
	
	warnx("listening on %s [%s]", intf, filter);

	// start new thread to send sync package
	struct tcp_connection data;
	data.l = l_sync;
	data.sport = sport;
	data.dport = dport;
	data.src = src;
	data.dst = dst;
	pthread_t tid;
	pthread_create(&tid, NULL, trigger, &data);
	pcap_loop(pd, -1, tcp_kill_cb, (u_char *)l);
  
	/* NOTREACHED */
	
	exit(0);
}
