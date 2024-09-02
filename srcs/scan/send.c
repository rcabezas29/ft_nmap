#include <ft_nmap.h>

void	send_port_scan(t_port_scan port_scan, char *ip)
{
	(void)port_scan;
	(void)ip;
	for (int i = 0; i < port_scan.n_scans; ++i)
	{
		switch (port_scan.scans_type[i].type)
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
}
