#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <options.h>
#include <time.h>
#include <lib_tpool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <poll.h>

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

typedef struct s_thread_data
{
	t_scan	*scan;
	int		start_port_index;
	int		end_port_index;
	int		n_ports;
}		t_thread_data;

void	sniffer(t_scan *scan);
void	process_packet(unsigned char *buffer, t_scan *scan);

t_scan	*create_scan_result_struct(t_nmap_config *conf, char *ip);
void	free_scan_struct(t_scan *scan, t_nmap_config *conf);


void	get_local_ip(char *buffer);
unsigned short csum(unsigned short *ptr,int nbytes);

void	*scanning(t_thread_data *data);

void	send_port_scan(int socket, char *ip, int port, t_scan_type type);

// unsigned short	csum(unsigned short *ptr,int nbytes);
// void	get_local_ip(char *buffer);
#endif
