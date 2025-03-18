#ifndef SCAN_H
#define SCAN_H

#include <libft.h>

typedef enum	e_scan_type
{
	SYN,
	NUL,
	ACK,
	FIN,
	XMAS,
	UDP,
	ALL
}	t_scan_type;

typedef enum	e_scan_state
{
	FILTERED,
	OPEN,
	CLOSED
}	t_scan_state;

typedef	struct	u_scan_type_pair
{
	t_scan_type		type;
	t_scan_state	state;
}	t_scan_type_pair;

typedef struct	s_port_scan
{
	t_scan_type_pair	*scans_type;
	int					port;
	int					n_scans;
}	t_port_scan;

typedef struct s_scan
{
	t_port_scan	*port_scan_array;
	char		*ip;
	int			n_ports;
}		t_scan;

typedef struct s_nmap_config
{
	t_scan_type	scan_type;
	char		**ips;
	t_list		*ports;
	int			n_speedup_threads;
	int			timeout;
}	t_nmap_config;

#endif
