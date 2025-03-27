#include <ft_nmap.h>

t_port_scan	*g_port_scan;
int			g_received_responses;

void	manage_udp_scan_response(struct udphdr *udph)
{
	t_port_scan	*port_scan = g_port_scan;
	int			i = 0;

	while (port_scan[i].port != -1)
	{
		if (port_scan[i].port == ntohs(udph->source) && port_scan[i].scans_type->source_port == ntohs(udph->dest))
			port_scan[i].scans_type->state = OPEN;
		i++;
	}
}

void	manage_tcp_scan_response(struct tcphdr *tcph)
{
	t_port_scan	*port_scan = g_port_scan;
	int			i = 0;

	while (port_scan[i].port != -1)
	{
		if (port_scan[i].port == ntohs(tcph->source) && port_scan[i].scans_type->source_port == ntohs(tcph->dest))
		{
			if (port_scan[i].scans_type->type == SYN)
			{
				if (tcph->syn && tcph->ack)
					port_scan[i].scans_type->state = OPEN;
				else if (tcph->rst)
					port_scan[i].scans_type->state = CLOSED;
				else
					port_scan[i].scans_type->state = FILTERED;
			}
			else if (port_scan[i].scans_type->type == NUL || port_scan[i].scans_type->type == FIN || port_scan[i].scans_type->type == XMAS)
			{
				if (tcph->rst)
					port_scan[i].scans_type->state = CLOSED;
			}
			else if (port_scan[i].scans_type->type == ACK)
			{
				if (tcph->rst)
					port_scan[i].scans_type->state = UNFILTERED;
			}
		}
		i++;
	}
}

void	manage_icmp_scan_response(const u_char *packet, struct ip *ipHeader)
{
	struct icmphdr	*icmph = (struct icmphdr *)(packet + 14 + ipHeader->ip_hl * 4);
	struct ip		*orig_ip = (struct ip *)((packet + 14) + (ipHeader->ip_hl * 4) + sizeof(icmph));
	t_port_scan		*port_scan = g_port_scan;
	int				i = 0;

	while (port_scan[i].port != -1)
	{
		if (orig_ip->ip_p == IPPROTO_TCP)
		{
			struct tcphdr	*orig_tcp = (struct tcphdr *)((unsigned char *)orig_ip + (orig_ip->ip_hl * 4));
			if (port_scan[i].port == ntohs(orig_tcp->dest) && port_scan[i].scans_type->source_port == ntohs(orig_tcp->source))
				if (icmph->type == ICMP_DEST_UNREACH)
					port_scan[i].scans_type->state = FILTERED;
		}
		else if (orig_ip->ip_p == IPPROTO_UDP)
		{
			struct udphdr	*orig_udp = (struct udphdr *)((unsigned char *)orig_ip + (orig_ip->ip_hl * 4));
			if (port_scan[i].port == ntohs(orig_udp->dest) && port_scan[i].scans_type->source_port == ntohs(orig_udp->source))
			{
				if (icmph->type == ICMP_DEST_UNREACH)
				{
					if (icmph->code == ICMP_PORT_UNREACH)
						port_scan[i].scans_type->state = CLOSED;
					else
						port_scan[i].scans_type->state = FILTERED;
				}
			}
		}
		i++;
	}
}

void	packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	(void)userData;
	(void)pkthdr;
	struct ip *ipHeader = (struct ip *)(packet + 14); // Skipping Ethernet header (14 bytes)
	char srcIp[INET_ADDRSTRLEN];
	char dstIp[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);

	if (ipHeader->ip_p == IPPROTO_TCP)
	{
		struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + ipHeader->ip_hl * 4);
		manage_tcp_scan_response(tcph);
	}
	else if (ipHeader->ip_p == IPPROTO_UDP)
	{
		struct udphdr *udph = (struct udphdr *)(packet + 14 + ipHeader->ip_hl * 4);
		manage_udp_scan_response(udph);
	}
	else if (ipHeader->ip_p == IPPROTO_ICMP)
		manage_icmp_scan_response(packet, ipHeader);
	++g_received_responses;
}

void	*sniffer_loop(void *handle)
{
	g_received_responses = 0;
    pcap_loop((pcap_t *)handle, 0, packet_handler, NULL);
    return NULL;
}

void	wait_for_responses(t_scan *scan, int timeout)
{
	struct timeval	start, current_time;

	gettimeofday(&start, NULL);
	while (true)
	{
		if (g_received_responses >= scan->n_ports * scan->port_scan_array[0].n_scans)
			break ;
		gettimeofday(&current_time, NULL);
		if (timeout != 0 && (current_time.tv_sec - start.tv_sec) * 1000 + (current_time.tv_usec - start.tv_usec) / 1000 >= timeout)
			break ;
	}
}

void	sniffer(t_scan *scan, int timeout)
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
	device = alldevs;
	if (pcap_lookupnet(device->name, &netp, &maskp, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", device->name, errbuf);
		return ;
	}
	handle = pcap_open_live(device->name, BUFSIZ, 1, 100, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Could not open device: %s\n", errbuf);
		pcap_freealldevs(alldevs);
		return ;
	}
	snprintf(filter_exp, sizeof(filter_exp), "src %s and (tcp or udp or icmp)", scan->ip);
	if (pcap_compile(handle, &filter, filter_exp, 0, netp) == -1 ||
		pcap_setfilter(handle, &filter) == -1)
	{
		fprintf(stderr, "Failed to set filter: %s\n", pcap_geterr(handle));
		pcap_freealldevs(alldevs);
		pcap_close(handle);
		return ;
	}
	g_port_scan = scan->port_scan_array;
	scan->ready_to_send = true;
	pthread_create(&sniffer_thread, NULL, sniffer_loop, handle);
	wait_for_responses(scan, timeout);
	pcap_breakloop(handle);
	pthread_join(sniffer_thread, NULL);
	pcap_freealldevs(alldevs);
	pcap_freecode(&filter);
	pcap_close(handle);
}
