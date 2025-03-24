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
	UDP
}	t_scan_type;

typedef enum	e_scan_state
{
	FILTERED,
	OPEN,
	CLOSED,
	OPEN_FILTERED,
	UNFILTERED
}	t_scan_state;

typedef	struct	u_scan_type_info
{
	t_scan_type		type;
	t_scan_state	state;
	int				source_port;
}	t_scan_type_info;

typedef struct	s_port_scan
{
	t_scan_type_info	*scans_type;
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
	t_list		*scan_type;
	char		**ips;
	t_list		*ports;
	int			n_speedup_threads;
	int			timeout;
}	t_nmap_config;

#endif
