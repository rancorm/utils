/*
*
* pource.c [PCAP to Gource Log Tool]
*
* Author: Jonathan Cormier <jonathan@cormier.co>
*
* Converts PCAP traffic to Gource Custom Log format for easy viewing
*
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <pcap.h>

/* Capture settings */
#define POURCE_SNAPLEN		0x3c /* 0x22 = 34, 0x3c = 60 */
#define POURCE_FILTER		"ip"
#define POURCE_TIMEOUT		0x1f4 /* 0x1f4 = 500 */
#define POURCE_PROMISC		0x0

/* Program pack to hold state */
typedef struct _pource_pack {
	/* Pource */
	char *filename;
	char *intf;
	char *filter;
	u_char flags;

	/* PCAP */
	pcap_t *p;
	struct pcap_pkthdr ph;
	struct pcap_stat ps;
	struct bpf_program bp;
	int dl;
	int dl_len;

	/* Interface */
	bpf_u_int32 net;
	bpf_u_int32 netmask;
} pource_pack;

/* Pource command line options */
/* IP only flag */
static int iponly_flag;

static struct option pource_options[] = {
	{ "file", required_argument, 0, 'f' },
	{ "interface", required_argument, 0, 'i' },
	{ "filter", required_argument, 0, 'F' },
	{ "ip-only", no_argument, &iponly_flag, 1 },
	{ "list-interfaces", no_argument, 0, 'L' },
	{ "help", no_argument, 0, 'h' },
        { 0, 0, 0, 0 }
};

int option_index = 0;

#define POURCE_OPTS		"f:i:F:Lh"
#define POURCE_OPT_NONE		0x0
#define POURCE_OPT_FILE		0x1
#define POURCE_OPT_INTF		0x2
#define POURCE_OPT_FILTER 	0x4
#define POURCE_OPT_IPONLY	0x8
#define POURCE_OPT_HELP		0x10
#define POURCE_OPT(F, O)	((F) & POURCE_OPT_##O)		
#define POURCE_OPTN(F, O)	(POURCE_OPT(F, O) == 0)
#define POURCE_EXIT_SUCCESS	0x0
#define POURCE_EXIT_FAILURE	0x1

void pource_exit(int);

void
pource_warn(char *fmt, ...) {
	char *traverse;

	va_list arg;
	va_start(arg, fmt);

	vfprintf(stderr, fmt, arg);

	va_end(arg);
}

void
iprint(struct in_addr addr) {
	printf("%s", inet_ntoa(addr));
}

int
catch_sig(int signo, void (*handler)()) {
	struct sigaction action;

	action.sa_handler = handler;
	action.sa_flags = 0;

	sigemptyset(&action.sa_mask);

	if (sigaction(signo, &action, NULL) == -1) {
		return -1;
	}

	return 1;
}

void
pource_pack_dump(pource_pack *pack) {
	if (pack->filename) pource_warn("filename = %s\n", pack->filename);
	if (pack->intf) pource_warn("intf = %s\n", pack->intf);
	if (pack->filter) pource_warn("filter = %s\n", pack->filter);

	pource_warn("dl = %d\n", pack->dl);
	pource_warn("dl_len = %d\n", pack->dl_len);

	pource_warn("flags = %d\n", pack->flags);
}

void
pource_usage(char *progname) {
	printf("Usage: %s [--file <file.pcap> | --interface <int#>] [--filter <filter>] [-h]\n\n", progname);

	printf("  --file, -f <file.pcap>\tCapure file to read\n");
	printf("  --interface, -i <int#>\tInterface to live capture (ie. en1, eth0)\n");
	printf("  --filter, -F <filter>\t\tFilter to apply\n");
	printf("  --ip-only\t\tOnly visualize IP information (exclude TCP/UDP/ICMP)\n");

	printf("\nAuthor: Jonathan Cormier <jonathan@cormier.co>\n");

	return;
}

void
pource_print_ilist() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i = 0;
	
	printf("Found interfaces:\n");
		
	/* Retrieve the device list from the local machine */
	if (pcap_findalldevs(&alldevs,
		errbuf) == -1) {
		fprintf(stderr, "pcap_findalldevs_ex(): %s\n", errbuf);

		pource_exit(POURCE_EXIT_FAILURE);
	}

	/* Print device list */
	for (d = alldevs; d != NULL; d = d->next) {
		printf("%d: %s", ++i, d->name);

		if (d->description)
			printf(" (%s)\n", d->description);
        	else
            		printf(" (No description available)\n");
	}
			
	/* We don't need any more the device list. Free it */
    	pcap_freealldevs(alldevs);		
}

int
datalink2len(int dl) {
        switch (dl) {
                case DLT_EN10MB:
                        return 0xe; /* 14 */
                default:
                        break;
        }

	return -1;
}

pource_pack *
pource_init(char *intf, char *filename, char *filter, u_char flags) {
	pource_pack *pack = (pource_pack *)malloc(sizeof(pource_pack));
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 local_net, netmask;

	/* Bail if memory can't be allocated */
	if (pack == NULL) return NULL;

	/* Save info to pack structure for other functions */
	pack->filename = filename;
	pack->intf = intf;
	pack->filter = filter;
	pack->flags = flags;

	/* Unbuffer stdout */
	setbuf(stdout, NULL);

	/* Live capture */
	if (pack->flags & POURCE_OPT_INTF) {
		fprintf(stderr, "Live capture on interface: %s\n", pack->intf);

		/* Open interface for capture... */
		pack->p = pcap_open_live(pack->intf,
			POURCE_SNAPLEN,
			POURCE_PROMISC,
			POURCE_TIMEOUT,
			errbuf);
		
		/* Did interface open? */
		if (pack->p == NULL) {
			fprintf(stderr, "pcap_open_live(): %s\n", errbuf);

			pource_exit(POURCE_EXIT_FAILURE);
		}		

		/* Network and mask lookup */
		if (pcap_lookupnet(pack->intf, &local_net, &netmask, errbuf) == -1) {
			fprintf(stderr, "pcap_lookupnet(): %s\n", errbuf);
			
			local_net = 0;
			netmask = 0;

			// pcap_close(pack->p);
			//pource_exit(POURCE_EXIT_FAILURE);
		}

		/* Save network and mask info */
		pack->net = local_net;
		pack->netmask = netmask;
	}

	/* Read capture from file system */
	if (pack->flags & POURCE_OPT_FILE) {
		fprintf(stderr, "Read traffic from file %s\n", pack->filename);

		pack->p = pcap_open_offline(pack->filename, errbuf);
	}

	/* Compile and set filter */
	if (pcap_compile(pack->p, &pack->bp, pack->filter, 1, netmask) == - 1) {
		fprintf(stderr, "pcap_compile(): %s\n", errbuf);
		pcap_close(pack->p);
		
		pource_exit(POURCE_EXIT_FAILURE);
	}

	if (pcap_setfilter(pack->p, &pack->bp) == -1) {
		fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(pack->p));
		
		pource_exit(POURCE_EXIT_FAILURE);
	}

	/* Free the memory used for the compiled filteir */
	pcap_freecode(&pack->bp);

	/* Misc */
	pack->dl = pcap_datalink(pack->p);
	pack->dl_len = datalink2len(pack->dl);
	
	return pack;
}

void
pource_stats(pource_pack *pack) {
	return;
}

void
pource_destroy(pource_pack *pack) {
	if (pack) {
		if (pack->filename) free(pack->filename);
		if (pack->intf) free(pack->intf);
		
		/* Free memory if user provided filter on command line */
		if (POURCE_OPT(pack->flags, FILTER) && pack->filter) {
			 free(pack->filter);
		}
		
		free(pack);
	}
}

void
pource_loop_tcp(pource_pack *pack, struct tcphdr *tcph) {
	printf(":%d.tcp|", ntohs(tcph->th_dport));
}

void
pource_loop_udp(pource_pack *pack, struct udphdr *udph) {
	return;
}

void
pource_loop_ip(pource_pack *pack, const struct pcap_pkthdr *h, struct ip *ip) {
	/* Timestamp */
	printf("%ld|", h->ts.tv_sec);

	/* Source */
	iprint(ip->ip_src);
	printf("|A|");
	iprint(ip->ip_dst);
	printf("/");
	iprint(ip->ip_src);
	printf("/");
	iprint(ip->ip_src);

	return;
}

void
pource_loop_cb(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
	int i = 0;
	static int count = 0;
	u_char ip_proto;

	/* Cast user to a pointer pack structure */ 
	pource_pack *pack = (pource_pack *)user;

	/* Pointers to start point of various headers */
	struct ip *ip_h;
	struct tcphdr *tcp_h;
	struct udphdr *udp_h;
	const u_char *payload;

	/* Header lengths in bytes */
	int eth_h_len; 
	int ip_h_len;
	int payload_len;

 	/* Layer 2/hardware header */
	struct ether_header *eth_h = (struct ether_header *)bytes;

	/* First, lets make sure we have an IP packet */
	if (ntohs(eth_h->ether_type) != ETHERTYPE_IP) {
		pource_warn("Not an IP packet, skipping...\n");

		return;
    	}

	/* Retrieve datalink length from pack structure */
	/* Previous retrieved in pource_init function */
	eth_h_len = pack->dl_len;

	/* Find start of IP header */
	ip_h = (struct ip *)(bytes + eth_h_len);
    
	/* The second-half of the first byte in ip_header contains the IP header length (IHL). */
	/* The IHL is number of 32-bit segments. Multiple by four to get a byte count for pointer arithmetic */
	ip_h_len = (ip_h->ip_hl & 0x0f) << 2;

	/* IP protocol */
	ip_proto = ip_h->ip_p;

	
	/* Handle TCP/UDP/ICMP protocols */
	switch(ip_proto) {
		case IPPROTO_TCP:
			/* Calculate TCP header */	
			tcp_h = (struct tcphdr *)(bytes + eth_h_len + ip_h_len);
			
			/* Handle IP */
			pource_loop_ip(pack, h, ip_h);
			pource_loop_tcp(pack, tcp_h);
		
			printf("\n");
			break;
		case IPPROTO_UDP:
			udp_h = (struct udphdr *)(bytes + eth_h_len + ip_h_len);

			pource_loop_ip(pack, h, ip_h);
			pource_loop_udp(pack, udp_h);
			printf("\n");
			break;
		case IPPROTO_ICMP:
			break;
		default:
			break;
	}

}

int
pource(pource_pack *pack) {
#ifdef EBUG
	pource_warn("Live capture started...\n");
#endif /* EBUG */

	/* Capture packets forever... */
	pcap_loop(pack->p, -1, pource_loop_cb, (u_char *)pack);

	return 0;
}

void
pource_exit(int code) {
	exit(code);
}

int
main(int argc, char *argv[]) {
	pource_pack *p;
	char *filename, *intf, *filter, *argv0;
	u_char flags;
	int ch;

	/* Init some basic variables */
	argv0 = argv[0];
	flags = POURCE_OPT_NONE;
	filter = POURCE_FILTER;
	filename = intf = NULL;

	/* Parse command line */
	while ((ch = getopt_long(argc,
		argv,
		POURCE_OPTS,
		pource_options,
		&option_index)) != -1) {
		switch (ch) {
		        case 0: {
				/* IP only flag */
				if (iponly_flag) {
					flags |= POURCE_OPT_IPONLY;
				}
          			
				/* If this option set a flag, do nothing else now. */
          			if (pource_options[option_index].flag != 0)
            				break;

				/* Handle long option argument */
	
				break;
			}
			case 'i':
				/* Interface */
				flags |= POURCE_OPT_INTF;
				intf = strdup(optarg);
				break;
			case 'f':
				/* Filename */
				flags |= POURCE_OPT_FILE;
				filename = strdup(optarg);				
				break;
			case 'F':
				/* Filter */
				flags |= POURCE_OPT_FILTER;
				filter = strdup(optarg);
				break;
			case 'L':
				/* List interfaces */
				pource_print_ilist();
				pource_exit(POURCE_EXIT_SUCCESS);
				break;
			case 'h':
				/* Help */
				pource_usage(argv0);
				pource_exit(POURCE_EXIT_SUCCESS);
             		case '?':
             		default:
				break;
             }
    	}

	/* Adjust command line */ 
	argc -= optind;
	argv += optind;

	/* Check if interface and file options used at same time */
	if (POURCE_OPT(flags, INTF) && POURCE_OPT(flags, FILE)) {
		fprintf(stderr, "Can't use --interface and --file at the same time.\n\n");

		pource_usage(argv0);
		pource_exit(POURCE_EXIT_SUCCESS);
	}

	/* Initialize */
	p = pource_init(intf, filename, filter, flags);

	/* Issues with init, lets bail with message to stderr */
	if (p == NULL) {
		fprintf(stderr, "pource_init(): error\n");
		pource_exit(POURCE_EXIT_FAILURE);
	}

	
#ifdef EBUG
	pource_pack_dump(p);
#endif /* EBUG */

	/* Go for launch! */
	pource(p);

	/* Clean up */
	pource_destroy(p);

	return 0;
}
