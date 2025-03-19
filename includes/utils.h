#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>
#include <scan.h>
#include <string.h>

void	double_free(char **arr);
char	*scantype_tostring(t_scan_type scan);
t_scan_type	string_to_scan_type(const char *str);
void	free_scan_struct(t_scan *scan, t_nmap_config *conf);
void	print_configurations(t_nmap_config *conf, int i);

#endif
