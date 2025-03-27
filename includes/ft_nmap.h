#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <options.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <poll.h>
#include <pthread.h>
#include <pcap.h>
#include <signal.h>
#include <errno.h>

#define ETHERNET_HEADER_SIZE 14

typedef struct s_thread_data
{
	t_scan	*scan;
	int		start_port_index;
	int		end_port_index;
	int		n_ports;
	char	*source_ip;
}		t_thread_data;

void	process_packet(t_scan *scan, unsigned char *buffer);
void	sniffer(t_scan *scan, int timeout);

t_scan	*create_scan_result_struct(t_nmap_config *conf, char *ip);
void	free_scan_struct(t_scan *scan, t_nmap_config *conf);


void	get_local_ip(char *buffer);
unsigned short csum(unsigned short *ptr,int nbytes);

void	*scanning(t_thread_data *data);
t_scan	*create_scan_result_struct(t_nmap_config *conf, char *ip);

void	send_port_scan(int socket, char *ip, int port, t_scan_type_info *sti, char *source_ip);


void	print_scan_result(t_scan *scan);

#endif
