#include <ft_nmap.h>

void	manage_scan_response(t_port_scan *scanned_port, t_scan *scan, struct tcphdr *tcph)
{
	(void)scan;
	if ((scanned_port->n_scans == 1 && tcph->seq != scanned_port->scans_type[0].type) ||
			(scanned_port->n_scans == 6 && tcph->seq >= 6))
		return ;
	switch (tcph->seq)
	{
		case SYN:
			/* code */
			break;
		case NUL:
			/* code */
			break;
		case ACK:
			/* code */
			break;
		case FIN:
			/* code */
			break;
		case XMAS:
			/* code */
			break;
		case UDP:
			/* code */
			break;
		default:
			break ;
	}
}

t_port_scan	*search_scanned_port(struct tcphdr *tcph, t_scan *scan)
{
	int	port = ntohs(tcph->source);
	for (int i = 0; i < scan->n_ports; ++i)
	{
		if (scan->port_scan_array[i].port == port)
			return &(scan->port_scan_array[i]);
	}
	return NULL;
}

void	process_packet(unsigned char *buffer, t_scan *scan)
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

		if (inet_addr(scan->ip) == source_port.sin_addr.s_addr)
		{
			t_port_scan	*scanned_port = search_scanned_port(tcph, scan);
			if (!scanned_port || tcph->seq >= 6)
				return ;
			manage_scan_response(scanned_port, scan, tcph);
			printf("Sniffed TCP packet\n");
			printf("   Source: %d - Seq: %u\n", ntohs(tcph->source), tcph->seq);
		}
	}
}

void	sniffer(t_scan *scan)
{
	struct sockaddr	saddr;
	unsigned char	buffer[IP_MAXPACKET];
	int				sock_raw, saddr_size, data_size;

	fflush(stdout);
	sock_raw = socket(AF_INET , SOCK_RAW , IPPROTO_TCP);
	if (sock_raw < 0)
	{
		printf("Socket Error\n");
		fflush(stdout);
		return ;
	}

	struct timeval timeout;      
    timeout.tv_sec = 5;
    // timeout.tv_usec = 0;
    
    if (setsockopt(sock_raw, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
    {
		printf("setsockopt failed\n");
		fflush(stdout);
		return ;
	}
	
	saddr_size = sizeof(saddr);
	while (1)
	{
		//Receive a packet
		data_size = recvfrom(sock_raw, buffer, IP_MAXPACKET, 0, &saddr, (socklen_t *)&saddr_size);

		if (data_size < 0)
		{
			fflush(stdout);
			return ;
		}
		
		//Now process the packet
		process_packet(buffer, scan);
	}
	
	close(sock_raw);
	printf("Sniffer finished.");
	fflush(stdout);
	return ;
}