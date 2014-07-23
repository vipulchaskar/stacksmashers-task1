//usage : sudo ./pfring_sniffer <interface name>
//e.g.  : sudo ./pfring_sniffer wlan0
#include <pcap.h>
#include <pfring.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>

#define ETHERNET_HDR_LEN 14

pfring *handle;				// pfring Session handle

void sigproc(int sig) {

	pfring_close(handle);
	printf("pfring closed.");

 	exit(0);
}

void parse_packet(const struct pfring_pkthdr *packethdr, const u_char *packetptr, const u_char *args)
{
	struct ip* iphdr;			// Header structures
	struct icmphdr* icmphdr;
	struct tcphdr* tcphdr;
	struct udphdr* udphdr;
	struct ether_header* etherhdr;
	unsigned short id, seq;			// ID and Sequence for ICMP packets
	u_char *ptr;
	int i;
 
	// Scan the data link layer
	etherhdr = (struct ether_header *) packetptr;
	
	printf("Ethernet header:\n");
	printf("\tSource MAC: %s",ether_ntoa((const struct ether_addr *)&etherhdr->ether_shost));
	printf("\tDestination MAC: %s ",ether_ntoa((const struct ether_addr *)&etherhdr->ether_dhost));

	if (ntohs (etherhdr->ether_type) == ETHERTYPE_IP) {
        	printf("\nNetwork header (IP) : \n");
	}
	else  if (ntohs (etherhdr->ether_type) == ETHERTYPE_ARP) {
        	printf("\nNetwork header (ARP) : \n");
		return;
    	}
	else if (ntohs (etherhdr->ether_type) == ETHERTYPE_REVARP) {
		printf("\nNetwork header (RARP) : \n");
		return;
	}
	else {
        	printf("\nNetwork header not IP or ARP\n");
        	return;
    	}


	// Scan the network layer
	packetptr += ETHERNET_HDR_LEN;
    
	iphdr = (struct ip*)packetptr;
	
	printf("\tSource IP : %s \t Destination IP : %s\n",inet_ntoa(iphdr->ip_src),inet_ntoa(iphdr->ip_dst));
	printf("\tID:%d TOS:0x%x TTL:%d IpHdrLen:%d TotalLen:%d Checksum:%d\n",ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,4*iphdr->ip_hl,ntohs(iphdr->ip_len),ntohs(iphdr->ip_sum));
 

	// Scan the transport layer, then parse and display
	// the fields based on the type of hearder: tcp, udp or icmp.
	packetptr += 4*iphdr->ip_hl;
	
	switch (iphdr->ip_p)
	{
		case IPPROTO_TCP:
		tcphdr = (struct tcphdr*)packetptr;
		printf("Transport header (TCP):\n\tSource port: %d\t Destination port: %d\n",ntohs(tcphdr->source),ntohs(tcphdr->dest));
        	printf("\tFlags : %c%c%c%c%c%c\tSeq: 0x%x Ack: 0x%x Window: 0x%x TcpLen: %d\n",
		(tcphdr->urg ? 'U' : '-'),
		(tcphdr->ack ? 'A' : '-'),
		(tcphdr->psh ? 'P' : '-'),
		(tcphdr->rst ? 'R' : '-'),
		(tcphdr->syn ? 'S' : '-'),
		(tcphdr->fin ? 'F' : '-'),
		ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq),ntohs(tcphdr->window), 4*tcphdr->doff);
        	break;
 
		case IPPROTO_UDP:
		udphdr = (struct udphdr*)packetptr;
		printf("Transport header (UDP):\n\tSource port: %d\tDestination port: %d\n",ntohs(udphdr->source),ntohs(udphdr->dest));
        	printf("\tLength: %d\tChecksum: %d\n",ntohs(udphdr->len),ntohs(udphdr->check));
        	break;
 
    		case IPPROTO_ICMP:
		icmphdr = (struct icmphdr*)packetptr;
		printf("Transport header (ICMP):\n");
		memcpy(&id, (u_char*)icmphdr+4, 2);
		memcpy(&seq, (u_char*)icmphdr+6, 2);
		printf("\tType:%d Code:%d Checksum:%d ID:%d Sequence:%d\n", icmphdr->type, icmphdr->code,icmphdr->checksum,ntohs(id), ntohs(seq));
      		break;

		default:
		printf("\tTransport header not identified.\n");
	}

	// Scanning packet finished
    	printf("------------------------------------------------------------\n\n");
}

int main(int argc, char *argv[])
{
	char *dev;			// The device to sniff on
	char errbuf[PCAP_ERRBUF_SIZE];	// Error string if any operation fails
	struct bpf_program fp;		// The compiled filter (not used)
	char filter_exp[] = "port 23";	// The filter expression (not used)
	bpf_u_int32 mask;		// Our subnet mask
	bpf_u_int32 net;		// Our network ID
	struct pfring_pkthdr header;	// The header that pfring gives us 
	const u_char *packet;		// The actual packet
	int flags;			// Flags to pass for opening pfring instance

	signal(SIGINT,sigproc);

	dev = argv[1];			// Set the device manually to arg[1]

	flags = PF_RING_PROMISC;
	if((handle = pfring_open(dev, MAX_CAPLEN, flags)) == NULL) {
   		printf("pfring_open error");
    		return(-1);
  	} else {
    		pfring_set_application_name(handle, "packetcapture");
	}

	pfring_enable_ring(handle);
		
	pfring_loop(handle,parse_packet,NULL,0);
		

	//pfring_close(handle);
	
	return 0;
}
