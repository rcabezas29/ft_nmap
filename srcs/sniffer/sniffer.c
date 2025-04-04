#include <ft_nmap.h>

t_port_scan		*g_port_scan;
pthread_mutex_t	g_received_responses_mutex = PTHREAD_MUTEX_INITIALIZER;
int				g_received_responses;

void	manage_udp_scan_response(struct udphdr *udph)
{
	t_port_scan	*port_scan = g_port_scan;
	int			i = 0;
	uint16_t	source_port = ntohs(udph->source);
	uint16_t	dest_port = ntohs(udph->dest);

	while (port_scan[i].port != -1)
	{
		if (port_scan[i].port == source_port)
		{
			for (int j = 0; j < port_scan[i].n_scans; ++j)
			{
				pthread_mutex_lock(&port_scan[i].scans_type[j].scan_mutex);
				if (port_scan[i].scans_type[j].source_port == dest_port)
				{
					port_scan[i].scans_type[j].state = OPEN;
					pthread_mutex_lock(&g_received_responses_mutex);
					g_received_responses += 1;
					pthread_mutex_unlock(&g_received_responses_mutex);
					pthread_mutex_unlock(&port_scan[i].scans_type[j].scan_mutex);
					return ;
				}
				pthread_mutex_unlock(&port_scan[i].scans_type[j].scan_mutex);
			}
		}
		i++;
	}
}

void	manage_tcp_scan_response(struct tcphdr *tcph)
{
	t_port_scan	*port_scan = g_port_scan;
	int			i = 0;
	uint16_t	source_port = ntohs(tcph->source);
    uint16_t	dest_port = ntohs(tcph->dest);

	while (port_scan[i].port != -1)
	{
		if (port_scan[i].port == source_port)
		{
			for (int j = 0; j < port_scan[i].n_scans; ++j)
			{
				pthread_mutex_lock(&port_scan[i].scans_type[j].scan_mutex);
				if (port_scan[i].scans_type[j].source_port == dest_port)
				{
					if (port_scan[i].scans_type[j].type == SYN)
					{
						if (tcph->syn && tcph->ack)
							port_scan[i].scans_type[j].state = OPEN;
						else if (tcph->rst)
							port_scan[i].scans_type[j].state = CLOSED;
					}
					else if (port_scan[i].scans_type[j].type == NUL || port_scan[i].scans_type[j].type == FIN || port_scan[i].scans_type[j].type == XMAS)
					{
						if (tcph->rst)
							port_scan[i].scans_type[j].state = CLOSED;
					}
					else if (port_scan[i].scans_type[j].type == ACK)
					{
						if (tcph->rst)
							port_scan[i].scans_type[j].state = UNFILTERED;
					}
					pthread_mutex_lock(&g_received_responses_mutex);
					g_received_responses += 1;
					pthread_mutex_unlock(&g_received_responses_mutex);
					pthread_mutex_unlock(&port_scan[i].scans_type[j].scan_mutex);
					return ;
				}
				pthread_mutex_unlock(&port_scan[i].scans_type[j].scan_mutex);
			}
		}
		++i;
	}
}

void	manage_icmp_scan_response(const u_char *packet, struct ip *iph)
{
	struct icmphdr	*icmph = (struct icmphdr *)(packet + ETHERNET_HEADER_SIZE + iph->ip_hl * 4);
	struct ip		*orig_ip = (struct ip *)((packet + ETHERNET_HEADER_SIZE) + (iph->ip_hl * 4) + sizeof(icmph));
	t_port_scan		*port_scan = g_port_scan;
	int				i = 0;

	if (orig_ip->ip_p == IPPROTO_TCP)
	{
		struct tcphdr	*orig_tcp = (struct tcphdr *)((unsigned char *)orig_ip + (orig_ip->ip_hl * 4));
		uint16_t	source_port = ntohs(orig_tcp->source);
		uint16_t	dest_port = ntohs(orig_tcp->dest);

		while (port_scan[i].port != -1)
		{
			if (port_scan[i].port == dest_port)
			{
				for (int j = 0; j < port_scan[i].n_scans; ++j)
				{
					pthread_mutex_lock(&port_scan[i].scans_type[j].scan_mutex);
					if (port_scan[i].scans_type[j].source_port == source_port)
					{
						if (icmph->type == ICMP_DEST_UNREACH)
							port_scan[i].scans_type[j].state = FILTERED;
						pthread_mutex_lock(&g_received_responses_mutex);
						g_received_responses += 1;
						pthread_mutex_unlock(&g_received_responses_mutex);
						pthread_mutex_unlock(&port_scan[i].scans_type[j].scan_mutex);
						return ;
					}
					pthread_mutex_unlock(&port_scan[i].scans_type[j].scan_mutex);
				}
			}
			i++;
		}
		
	}
	else if (orig_ip->ip_p == IPPROTO_UDP)
	{
		struct udphdr	*orig_udp = (struct udphdr *)((unsigned char *)orig_ip + (orig_ip->ip_hl * 4));
		uint16_t	source_port = ntohs(orig_udp->source);
		uint16_t	dest_port = ntohs(orig_udp->dest);

		while (port_scan[i].port != -1)
		{
			if (port_scan[i].port == dest_port)
			{
				for (int j = 0; j < port_scan[i].n_scans; ++j)
				{
					pthread_mutex_lock(&port_scan[i].scans_type[j].scan_mutex);
					if (port_scan[i].scans_type[j].source_port == source_port)
					{
						if (icmph->type == ICMP_DEST_UNREACH)
						{
							if (icmph->code == ICMP_PORT_UNREACH)
								port_scan[i].scans_type[j].state = CLOSED;
							else
								port_scan[i].scans_type[j].state = FILTERED;
						}
						pthread_mutex_lock(&g_received_responses_mutex);
						g_received_responses += 1;
						pthread_mutex_unlock(&g_received_responses_mutex);
						pthread_mutex_unlock(&port_scan[i].scans_type[j].scan_mutex);
						return ;
					}
					pthread_mutex_unlock(&port_scan[i].scans_type[j].scan_mutex);
				}
			}
			i++;
		}
	}
}

void	packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	(void)userData;
	(void)pkthdr;
	struct ip *iph = (struct ip *)(packet + ETHERNET_HEADER_SIZE);

	if (iph->ip_p == IPPROTO_TCP)
	{
		struct tcphdr *tcph = (struct tcphdr *)(packet + ETHERNET_HEADER_SIZE + iph->ip_hl * 4);
		manage_tcp_scan_response(tcph);
	}
	else if (iph->ip_p == IPPROTO_UDP)
	{
		struct udphdr *udph = (struct udphdr *)(packet + ETHERNET_HEADER_SIZE + iph->ip_hl * 4);
		manage_udp_scan_response(udph);
	}
	else if (iph->ip_p == IPPROTO_ICMP)
		manage_icmp_scan_response(packet, iph);
}

void	*sniffer_loop(void *handle)
{
	pthread_mutex_lock(&g_received_responses_mutex);
	g_received_responses = 0;
	pthread_mutex_unlock(&g_received_responses_mutex);
	pcap_loop((pcap_t *)handle, 0, packet_handler, NULL);
	return NULL;
}

void	wait_for_responses(t_scan *scan, int timeout)
{
	struct timeval	start, current_time;

	gettimeofday(&start, NULL);
	while (true)
	{
		pthread_mutex_lock(&g_received_responses_mutex);
		if (g_received_responses >= scan->n_ports * scan->port_scan_array[0].n_scans)
		{
			pthread_mutex_unlock(&g_received_responses_mutex);
			break ;
		}
		gettimeofday(&current_time, NULL);
		if (timeout != 0 && (current_time.tv_sec - start.tv_sec) * 1000 + (current_time.tv_usec - start.tv_usec) / 1000 >= timeout)
		{
			pthread_mutex_unlock(&g_received_responses_mutex);
			break ;
		}
		pthread_mutex_unlock(&g_received_responses_mutex);
	}
}

void	sniffer(t_scan *scan, int timeout, char *ip)
{
	struct bpf_program	filter;
	char				errbuf[PCAP_ERRBUF_SIZE], filter_exp[64];
	pcap_if_t			*alldevs, *device;
	pcap_t				*handle;
	pthread_t			sniffer_thread;
	bpf_u_int32			netp, maskp;

	if (pcap_findalldevs(&alldevs, errbuf) == -1 || alldevs == NULL)
	{
		fprintf(stderr, "Error finding devices: %s\n", errbuf);
		return ;
	}
	if (strcmp(ip, "127.0.0.1") == 0)
	{
		device = alldevs;
		while (device)
		{
			if (device->flags & PCAP_IF_LOOPBACK)
				break ;
			device = device->next;
		}
		if (device == NULL)
		{
			fprintf(stderr, "No loopback device found\n");
			pcap_freealldevs(alldevs);
			return ;
		}
	}
	else
		device = alldevs;
	if (pcap_lookupnet(device->name, &netp, &maskp, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device->name, errbuf);
		return ;
	}
	handle = pcap_open_live(device->name, BUFSIZ, 1, 10, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Could not open device: %s\n", errbuf);
		pcap_freealldevs(alldevs);
		return ;
	}
	snprintf(filter_exp, sizeof(filter_exp), "src host %s", scan->ip);
	if (pcap_compile(handle, &filter, filter_exp, 0, netp) == -1 ||
		pcap_setfilter(handle, &filter) == -1)
	{
		fprintf(stderr, "Failed to set filter: %s\n", pcap_geterr(handle));
		pcap_freealldevs(alldevs);
		pcap_close(handle);
		return ;
	}
	g_port_scan = scan->port_scan_array;
	pthread_mutex_lock(&scan->ready_to_send_mutex);
	scan->ready_to_send = true;
	pthread_mutex_unlock(&scan->ready_to_send_mutex);
	pthread_create(&sniffer_thread, NULL, sniffer_loop, handle);
	wait_for_responses(scan, timeout);
	pcap_breakloop(handle);
	pthread_join(sniffer_thread, NULL);
	pcap_freealldevs(alldevs);
	pcap_freecode(&filter);
	pcap_close(handle);
}
