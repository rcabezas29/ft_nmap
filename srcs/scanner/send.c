#include <ft_nmap.h>

struct pseudo_header
{
	u_int32_t	source_address;
	u_int32_t	dest_address;
	u_int16_t	tcp_length;
	u_int8_t	placeholder;
	u_int8_t	protocol;
};

void	fill_tcp_with_scan_type(struct tcphdr *tcph, t_scan_type_info *sti)
{
	if (sti->type == SYN)
		tcph->syn = 1;
	else if (sti->type == XMAS)
	{
		tcph->psh = 1;
		tcph->urg = 1;
	}
	else if (sti->type == FIN || sti->type == XMAS)
		tcph->fin = 1;
	else if (sti->type == ACK)
		tcph->ack = 1;
}

void	send_udp_scan(char *packet, int port, t_scan_type_info *sti, char *ip, char *source_ip)
{
	struct udphdr	*udph = (struct udphdr *)(packet + sizeof(struct iphdr));
	struct pseudo_header	psh;

	udph->source = htons(rand() % 65535);
	udph->dest = htons(port);
	udph->len = htons(sizeof(struct udphdr));

	sti->source_port = ntohs(udph->source);

	psh.source_address = inet_addr(source_ip);
	psh.dest_address = inet_addr(ip);
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.tcp_length = htons(sizeof(struct udphdr));

	char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct udphdr)];
	memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
	memcpy(pseudo_packet + sizeof(struct pseudo_header), udph, sizeof(struct udphdr));

	udph->check = csum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));
}

void	send_tcp_scan(char *packet, int port, t_scan_type_info *sti, char *ip, char *source_ip)
{
	struct tcphdr			*tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
	struct pseudo_header	psh;

	tcph->source = htons(rand() % 65535);
	tcph->dest = htons(port);
	tcph->seq = htonl(rand());
	tcph->ack_seq = 0;
	tcph->doff = 5;
	fill_tcp_with_scan_type(tcph, sti);
	tcph->window = htons(65535);
	tcph->urg_ptr = 0;

	sti->source_port = ntohs(tcph->source);

	psh.source_address = inet_addr(source_ip);
	psh.dest_address = inet_addr(ip);
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

	char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
	memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
	memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

	tcph->check = csum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));
}

void	send_port_scan(int socket, char *ip, int port, t_scan_type_info *sti, char *source_ip)
{
	char					packet[4096];
	struct sockaddr_in		dest;
	struct iphdr			*iph = (struct iphdr *)packet;

	dest.sin_family = AF_INET;
	dest.sin_port = htons(port);
	dest.sin_addr.s_addr = inet_addr(ip);

	memset(packet, 0, sizeof(packet));

	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + (sti->type == UDP ? sizeof(struct udphdr) : sizeof(struct tcphdr));
	iph->id = htonl(rand() % 65535);
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = sti->type == UDP ? IPPROTO_UDP : IPPROTO_TCP;
	iph->saddr = inet_addr(source_ip);
	iph->daddr = dest.sin_addr.s_addr;
	iph->check = csum((unsigned short *)packet, sizeof(struct iphdr));

	if (sti->type == UDP)
		send_udp_scan(packet, port, sti, ip, source_ip);
	else
		send_tcp_scan(packet, port, sti, ip, source_ip);
	sendto(socket, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest));
}
