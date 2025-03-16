#include <ft_nmap.h>

struct in_addr dest_ip;


void	send_port_scan(int socket, char *ip, int port, t_scan_type type)
{
	printf("Scanning port %i for IP: %s and type: %i\n", port, ip, type);
	// (void)type;
	struct sockaddr_in	dest;

	//Datagram to represent the packet
	char datagram[4096];	
	
	//IP header
	struct iphdr *iph = (struct iphdr *) datagram;
	
	//TCP header
	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof(struct ip));
	// struct pseudo_header psh;

	memset (datagram, 0, 4096);	/* zero out the buffer */
	
	//Fill in the IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
	iph->id = htons (54321);	//Id of this packet
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;		//Set to 0 before calculating checksum
	char	source_ip[1024];
	get_local_ip(source_ip);
	iph->saddr = inet_addr ( source_ip );	//Spoof the source ip address
	iph->daddr = dest_ip.s_addr;
	
	iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
	
	//TCP Header
	tcph->source = htons(31234);
	tcph->dest = htons (80);
	tcph->seq = htonl(1105024978);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr) / 4;		//Size of tcp header
	tcph->fin=0;
	tcph->syn=1;
	tcph->rst=0;
	tcph->psh=0;
	tcph->ack=0;
	tcph->urg=0;
	tcph->window = htons ( 14600 );	// maximum allowed window size
	tcph->check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
	tcph->urg_ptr = 0;

	dest.sin_family = AF_INET;
	inet_aton(ip, &dest.sin_addr);
	dest.sin_port = htons(port);

	sendto(socket, "hola", 5, 0, (struct sockaddr *)&dest, sizeof(dest));
}
