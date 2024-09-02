#include <ft_nmap.h>

typedef struct s_scan_info
{
	char	*dest_ip;
	int		dest_port;

}	t_scan_info;

struct pseudo_header    //needed for checksum calculation
{
	struct tcphdr	tcp;
	unsigned int	source_address;
	unsigned int	dest_address;
	unsigned char	placeholder;
	unsigned char	protocol;
	unsigned short	tcp_length;
};

// void	send_syn(t_scan_info *scan_info)
// {
// 	int s = socket(AF_INET, SOCK_RAW , IPPROTO_TCP);
// 	if (s < 0)
// 	{
// 		printf("Error creating socket.\n");
// 		return ;
// 	}
// 	else
// 	{
// 		printf("Socket created.\n");
// 	}
		
// 	//Datagram to represent the packet
// 	char datagram[4096];	
	
// 	//IP header
// 	struct iphdr *iph = (struct iphdr *) datagram;
	
// 	//TCP header
// 	struct tcphdr *tcph = (struct tcphdr *) (datagram + sizeof (struct ip));
	
// 	struct sockaddr_in  dest;
// 	struct pseudo_header psh;
	
// 	int source_port = 43591;
// 	char source_ip[20];
// 	get_local_ip(source_ip);
	
// 	printf("Local source IP is %s \n" , source_ip);
	
// 	memset (datagram, 0, 4096);	/* zero out the buffer */
	
// 	//Fill in the IP Header
// 	iph->ihl = 5;
// 	iph->version = 4;
// 	iph->tos = 0;
// 	iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
// 	iph->id = htons (54321);	//Id of this packet
// 	iph->frag_off = htons(16384);
// 	iph->ttl = 64;
// 	iph->protocol = IPPROTO_TCP;
// 	iph->check = 0;		//Set to 0 before calculating checksum
// 	iph->saddr = inet_addr(source_ip);	//Spoof the source ip address
// 	iph->daddr = dest_ip.s_addr;
	
// 	iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);
	
// 	//TCP Header
// 	tcph->source = htons ( source_port );
// 	tcph->dest = htons (80);
// 	tcph->seq = htonl(1105024978);
// 	tcph->ack_seq = 0;
// 	tcph->doff = sizeof(struct tcphdr) / 4;		//Size of tcp header
// 	tcph->fin=0;
// 	tcph->syn=1;
// 	tcph->rst=0;
// 	tcph->psh=0;
// 	tcph->ack=0;
// 	tcph->urg=0;
// 	tcph->window = htons ( 14600 );	// maximum allowed window size
// 	tcph->check = 0; //if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission
// 	tcph->urg_ptr = 0;
	
// 	//IP_HDRINCL to tell the kernel that headers are included in the packet
// 	int one = 1;
// 	const int *val = &one;
	
// 	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
// 	{
// 		printf ("Error setting IP_HDRINCL.\n");
// 		return ;
// 	}

// 	printf("Starting to send syn packets\n");
	
// 	dest.sin_family = AF_INET;
// 	dest.sin_addr.s_addr = dest_ip.s_addr;
// 	tcph->dest = htons(port);
// 	tcph->check = 0;	// if you set a checksum to zero, your kernel's IP stack should fill in the correct checksum during transmission

// 	psh.source_address = inet_addr( source_ip );
// 	psh.dest_address = dest.sin_addr.s_addr;
// 	psh.placeholder = 0;
// 	psh.protocol = IPPROTO_TCP;
// 	psh.tcp_length = htons(sizeof(struct tcphdr) );
	
// 	memcpy(&psh.tcp , tcph , sizeof(struct tcphdr));
	
// 	tcph->check = csum( (unsigned short*) &psh , sizeof (struct pseudo_header));
	
// 	//Send the packet
// 	if ( sendto (s, datagram , sizeof(struct iphdr) + sizeof(struct tcphdr) , 0 , (struct sockaddr *) &dest, sizeof (dest)) < 0)
// 	{
// 		printf ("Error sending syn packet. Error number : %d . Error message : %s \n" , errno , strerror(errno));
// 		exit(0);
// 	}
// }