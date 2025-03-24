#include <ft_nmap.h>

t_port_scan	*g_port_scan;

void	manage_tcp_scan_response(struct tcphdr *tcph)
{
	t_port_scan	*port_scan = g_port_scan;
	int			i = 0;

	while (port_scan[i].port != -1)
	{
		if (port_scan[i].port == ntohs(tcph->source) && port_scan[i].scans_type->source_port == ntohs(tcph->dest))
		{
			switch (port_scan[i].scans_type->type)
			{
				case SYN:
					if (tcph->syn && tcph->ack)
						port_scan[i].scans_type->state = OPEN;
					else if (tcph->rst)
						port_scan[i].scans_type->state = CLOSED;
					else
						port_scan[i].scans_type->state = FILTERED;
					break ;
				case NUL:
					if (tcph->rst)
						port_scan[i].scans_type->state = CLOSED;
					else
						port_scan[i].scans_type->state = OPEN;
					break ;
				case FIN:
					if (tcph->rst)
						port_scan[i].scans_type->state = CLOSED;
					else
						port_scan[i].scans_type->state = OPEN;
					break ;
				case XMAS:
					if (tcph->rst)
						port_scan[i].scans_type->state = CLOSED;
					else
						port_scan[i].scans_type->state = OPEN;
					break ;
				case ACK:
					if (tcph->rst)
						port_scan[i].scans_type->state = OPEN;
					else
						port_scan[i].scans_type->state = FILTERED;
					break ;
				default:
					break ;
			}
			// if (tcph->syn && tcph->ack)
			// 	port_scan[i].scans_type->state = OPEN;
			// else if (tcph->rst)
			// 	port_scan[i].scans_type->state = CLOSED;
			// else
			// 	port_scan[i].scans_type->state = FILTERED;
			// break ;
		}
		i++;
	}
}

void	packet_handler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	(void)userData;
	(void)pkthdr;
	struct ip *ipHeader = (struct ip *)(packet + 14); // Skipping Ethernet header (14 bytes)
	struct tcphdr *tcph = (struct tcphdr *)(packet + 14 + ipHeader->ip_hl * 4);
	char srcIp[INET_ADDRSTRLEN];
	char dstIp[INET_ADDRSTRLEN];
	int	port, dest_port;
	inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);
	port = ntohs(tcph->source);
	dest_port = ntohs(tcph->dest);


	printf("Source IP: %s:%i -> Destination IP: %s:%d\n", srcIp, port, dstIp, dest_port);

	if (ipHeader->ip_p == IPPROTO_TCP) {
		printf("TCP Packet Received\n");
		manage_tcp_scan_response(tcph);
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
	g_port_scan = scan->port_scan_array;
	pthread_create(&sniffer_thread, NULL, sniffer_loop, handle);
	usleep(timeout * 1000);
	pcap_breakloop(handle);
	pthread_join(sniffer_thread, NULL);
	pcap_freealldevs(alldevs);
	pcap_freecode(&filter);
	pcap_close(handle);
}
