#ifndef OPTIONS_H
#define OPTIONS_H

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <utils.h>
#include <libft.h>

void		parse_options(int argc, char **argv, t_nmap_config *conf);
void		parse_long_option(const char *option, const char *optarg, t_nmap_config *conf);

void		print_help(void);

char		**parse_ips_file(const char *argument);
char		**parse_ip(const char *argument);

t_list		*parse_ports(const char *argument);

void		parse_scan_type(t_list **scan_type, const char *optarg);
t_list		*add_all_scans(void);

int			parse_thread_number(const char *optarg);

int			parse_timeout(const char *timeout);

#endif
