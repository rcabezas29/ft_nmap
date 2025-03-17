#include <ft_nmap.h>

struct in_addr dest_ip;


void	send_port_scan(int socket, char *ip, int port, t_scan_type type)
{
	struct sockaddr_in	dest;
	(void)type;

	dest.sin_family = AF_INET;
	inet_aton(ip, &dest.sin_addr);
	dest.sin_port = htons(port);

	// printf("Sending scan to %s:%d type: %d\n", ip, port, type);
	sendto(socket, "hola", 4, 0, (struct sockaddr *)&dest, sizeof(dest));
}
