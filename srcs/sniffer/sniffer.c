#include <ft_nmap.h>

void	manage_scan_response(t_port_scan *scanned_port, t_scan *scan, struct tcphdr *tcph)
{
	(void)scan;
	if ((scanned_port->n_scans == 1 && tcph->seq != scanned_port->scans_type[0].type) || (scanned_port->n_scans == 6 && tcph->seq >= 6))
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
		
/*
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

void	sniffer(t_scan *scan, int timeout)
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
					// process_packet(buffer, scan);
				}
			}
		}
		gettimeofday(&current_time, NULL);
		if ((current_time.tv_sec - start_time.tv_sec) * 1000 + (current_time.tv_usec - start_time.tv_usec) / 1000 > timeout)
		break ;
	}
	close(tcp_sock_raw);
	close(udp_sock_raw);
	fflush(stdout);
	return ;
}
*/

void	packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	(void)userData;
	(void)pkthdr;
    struct ip *ipHeader = (struct ip *)(packet + 14); // Skipping Ethernet header (14 bytes)
	struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + ipHeader->ip_hl * 4);
    char srcIp[INET_ADDRSTRLEN];
    char dstIp[INET_ADDRSTRLEN];
	int	port;
    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);
	port = ntohs(tcph->source);


    printf("Source IP: %s:%i -> Destination IP: %s\n", srcIp, port, dstIp);

    if (ipHeader->ip_p == IPPROTO_TCP) {
        printf("TCP Packet Received\n");
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        printf("UDP Packet Received\n");
    }
    printf("-------------------------\n");
}

void	*sniffer_loop(void *handle)
{
    pcap_loop((pcap_t *)handle, 0, packet_handler, NULL);
    return NULL;
}

void	sniffer(t_scan *scan, int timeout)
{
	struct bpf_program	filter;
	char				errbuf[PCAP_ERRBUF_SIZE], filter_exp[64];
	pcap_if_t			*alldevs, *device;
	pcap_t				*handle;
	pthread_t			sniffer_thread;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error finding devices: %s\n", errbuf);
		return ;
	}
	device = alldevs;
	handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Could not open device: %s\n", errbuf);
		pcap_freealldevs(alldevs);
		return ;
	}
	snprintf(filter_exp, sizeof(filter_exp), "ip src %s and (tcp or udp)", scan->ip);
	if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 ||
		pcap_setfilter(handle, &filter) == -1)
	{
		fprintf(stderr, "Failed to set filter: %s\n", pcap_geterr(handle));
		pcap_freealldevs(alldevs);
		pcap_close(handle);
		return ;
	}
	pthread_create(&sniffer_thread, NULL, sniffer_loop, handle);
	usleep(timeout * 1000);
	pcap_breakloop(handle);
	pthread_join(sniffer_thread, NULL);
	pcap_freealldevs(alldevs);
	pcap_close(handle);
}
