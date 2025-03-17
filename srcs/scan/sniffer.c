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

static void	setup_listening_sockets(int *sock_raw_tcp, int *sock_raw_udp, struct pollfd *pfds)
{
	struct timeval timeout;

	*sock_raw_tcp = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (*sock_raw_tcp < 0)
	{
		printf("TCP Socket Error\n");
		fflush(stdout);
		exit(1);
	}
	*sock_raw_udp = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (*sock_raw_udp < 0)
	{
		printf("UDP Socket Error\n");
		fflush(stdout);
		exit(1);
	}
	timeout.tv_sec = 0;
	timeout.tv_usec = 10;
	if (setsockopt(*sock_raw_tcp, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		printf("setsockopt TCP failed\n");
		fflush(stdout);
		exit(1);
	}
	if (setsockopt(*sock_raw_udp, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
	{
		printf("setsockopt UDP failed\n");
		fflush(stdout);
		exit(1);
	}
	if (fcntl(*sock_raw_tcp, F_SETFL, O_NONBLOCK) < 0 || fcntl(*sock_raw_udp, F_SETFL, O_NONBLOCK) < 0)
	{
		perror("fcntl failed");
		close(*sock_raw_tcp);
		close(*sock_raw_udp);
		exit(EXIT_FAILURE);
	}
	pfds[0].fd = *sock_raw_tcp;
	pfds[0].events = POLLIN;
	pfds[1].fd = *sock_raw_udp;
	pfds[1].events = POLLIN;
}

void	sniffer(t_scan *scan)
{
	(void)scan;
	struct pollfd	pfds[2];
	struct sockaddr	saddr;
	struct timeval	current_time, start_time;
	unsigned char	buffer[IP_MAXPACKET];
	int				tcp_sock_raw, udp_sock_raw, saddr_size, data_size;

	setup_listening_sockets(&tcp_sock_raw, &udp_sock_raw, pfds);
	fflush(stdout);

	saddr_size = sizeof(saddr);
	gettimeofday(&start_time, NULL);
	while (1)
	{
		int ret = poll(pfds, 1, -1);
		if (ret < 0)
			perror("poll failed");
		else if (ret == 0)
			break ;
		else
		{
			for (int i = 0; i < 2; i++)
			{
				if (pfds[i].revents & POLLIN)
				{
					data_size = recvfrom(pfds[i].fd, buffer, IP_MAXPACKET, 0, &saddr, (socklen_t *)&saddr_size);
					if (data_size < 0)
					{
						fflush(stdout);
						return ;
					}
					printf("Received packet: %s\n", buffer);
					// process_packet(buffer, scan);
				}
			}
		}
		gettimeofday(&current_time, NULL);
		if (current_time.tv_sec - start_time.tv_sec > 5)
			break ;
	}
	close(tcp_sock_raw);
	close(udp_sock_raw);
	fflush(stdout);
	return ;
}