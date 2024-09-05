#include <ft_nmap.h>

void	send_port_scan(char *ip, int port, t_scan_type type)
{
	printf("Scanning port %i for IP: %s and type: %i\n", port, ip, type);
}
