#include <ft_nmap.h>

void	process_packet(unsigned char *buffer, char *ip)
{
	struct iphdr *iph = (struct iphdr *)buffer;
	if (iph->protocol == 6) // Protocol == TCP
	{
		unsigned short iphdrlen = iph->ihl * 4;
		struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen);

		struct sockaddr_in source_port, dest_port;
		memset(&source_port, 0, sizeof(source_port));
		source_port.sin_addr.s_addr = iph->saddr;
	
		memset(&dest_port, 0, sizeof(dest_port));
		dest_port.sin_addr.s_addr = iph->daddr;

		if (inet_addr(ip) == source_port.sin_addr.s_addr)
		{
			printf("Sniffed TCP packet\n");
			printf("   Source: %d - Seq: %u\n", ntohs(tcph->source), tcph->seq);
		}
	}
}

void	sniffer(t_scan *scan)
{
	struct sockaddr	saddr;
	unsigned char	buffer[IP_MAXPACKET];
	clock_t			start;
	int				sock_raw, saddr_size, data_size;

	fflush(stdout);
	
	//Create a raw socket that shall sniff
	sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	if (sock_raw < 0)
	{
		printf("Socket Error\n");
		fflush(stdout);
		return ;
	}
	
	saddr_size = sizeof(saddr);
	start = clock();
	while ((((double)(clock() - start)) / CLOCKS_PER_SEC) < 0.01)
	{
		//Receive a packet
		data_size = recvfrom(sock_raw, buffer, IP_MAXPACKET, 0, &saddr, (socklen_t *)&saddr_size);

		if (data_size < 0)
		{
			printf("Recvfrom error , failed to get packets\n");
			fflush(stdout);
			return ;
		}
		
		//Now process the packet
		process_packet(buffer, scan->ip);
	}
	
	close(sock_raw);
	printf("Sniffer finished.");
	fflush(stdout);
	return ;
}