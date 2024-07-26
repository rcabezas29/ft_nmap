#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <options.h>
#include <time.h>
#include <lib_tpool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

typedef enum	e_scan_state
{
	FILTERED,
	OPEN,
	CLOSED
}	t_scan_state;

typedef	union	u_scan_type_pair
{
	t_scan_type		type;
	t_scan_state	state;
}	t_scan_type_pair;

typedef struct	s_port_scan
{
	t_scan_type_pair	*scans_type;
	int					port;
}	t_port_scan;

typedef struct s_scan
{
	t_port_scan	*port_scan_array;
	char		*ip;
}		t_scan;

void	sniffer(t_scan *scan);
void	process_packet(unsigned char *buffer, char *ip);

t_scan	*create_scan_result_struct(t_nmap_config *conf, char *ip);
void	free_scan_struct(t_scan *scan, t_nmap_config *conf);

#endif
