#include <utils.h>

void	double_free(char **arr)
{
	for (int i = 0; arr[i]; ++i)
		free(arr[i]);
	free(arr);
}

void	free_scan_struct(t_scan *scan, t_nmap_config *conf)
{
	int		n_ports = ft_lstsize(conf->ports);

	for (int i = 0; i < n_ports; ++i)
		free(scan->port_scan_array[i].scans_type);
	free(scan->port_scan_array);
	free(scan);
}

void	free_conf(t_nmap_config *conf)
{
	ft_lstclear(&conf->scan_type, free);
	ft_lstclear(&conf->ports, free);
	double_free(conf->ips);
	free(conf->scan_type);
	free(conf);
}
