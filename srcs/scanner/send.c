#include <ft_nmap.h>

struct pseudo_header
{
	u_int32_t	source_address;
	u_int32_t	dest_address;
	u_int16_t	tcp_length;
	u_int8_t	placeholder;
	u_int8_t	protocol;
};

void	send_port_scan(int socket, char *ip, int port, t_scan_type type, char *source_ip)
{
	(void)type;
	char					packet[4096];
	struct sockaddr_in		dest;
	struct iphdr			*iph = (struct iphdr *)packet;
	struct tcphdr			*tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
	struct pseudo_header	psh;

	dest.sin_family = AF_INET;
	dest.sin_port = htons(port);
	dest.sin_addr.s_addr = inet_addr(ip);

	memset(packet, 0, sizeof(packet));

	// Fill IP Header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
	iph->id = htonl(rand() % 65535);
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr(source_ip);
	iph->daddr = dest.sin_addr.s_addr;
	iph->check = csum((unsigned short *)packet, sizeof(struct iphdr));

	// Fill TCP Header
	tcph->source = htons(rand() % 65535);
	tcph->dest = htons(port);
	tcph->seq = htonl(rand());
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->syn = 1;
	tcph->ack = 0;
	tcph->fin = 0;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->urg = 0;
	tcph->window = htons(65535);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	// Pseudo Header for Checksum
	psh.source_address = inet_addr(source_ip);
	psh.dest_address = inet_addr(ip);
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

	char pseudo_packet[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];
	memcpy(pseudo_packet, &psh, sizeof(struct pseudo_header));
	memcpy(pseudo_packet + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

	tcph->check = csum((unsigned short *)pseudo_packet, sizeof(pseudo_packet));

	// Send Packet
	sendto(socket, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest));
}
