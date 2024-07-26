#include <ft_nmap.h>

void	print_configurations(t_nmap_config *conf)
{
	ft_putstr_fd("\nScan Configurations\n", 1);
	printf("Target Ip-Address : %s\n", conf->ips[0]);
	printf("No of Ports to scan : %i\n", ft_lstsize(conf->ports));
	printf("Scans to be performed : %s \n", scantype_tostring(conf->scan_type));
	printf("No of threads : %i\n", conf->n_speedup_threads);
	ft_putstr_fd("Scanning...\n", 1);
}

void	iterate_over_every_port(t_nmap_config *conf)
{
	t_list	*current_port = conf->ports;
	while (current_port)
	{
		printf("Scanning Port: %i\n", *(int *)(current_port->content));
		current_port = current_port->next;
	}
}

t_scan	*create_scan_result_struct(t_nmap_config *conf, char *ip)
{
	t_scan	*scan = malloc(sizeof(t_scan));
	int		n_ports = ft_lstsize(conf->ports);
	int		n_scans = conf->scan_type == ALL ? 6 : 1;

	scan->ip = ip;
	scan->port_scan_array = malloc(sizeof(t_port_scan) * n_ports);

	t_list	*current_port = conf->ports;
	for (int i = 0; i < n_ports; ++i)
	{
		scan->port_scan_array[i].port = *(int *)(current_port->content);
		scan->port_scan_array[i].scans_type = malloc(sizeof(t_scan_type_pair) * n_scans);
		for (int j = 0; j < n_scans; ++j)
		{
			if (conf->scan_type == ALL)
				scan->port_scan_array[i].scans_type[j].type = j;
			else
				scan->port_scan_array[i].scans_type[j].type = conf->scan_type;
			scan->port_scan_array[i].scans_type[j].state = FILTERED;
		}
		current_port = current_port->next;
	}

	return scan;
}

void	free_scan_struct(t_scan *scan, t_nmap_config *conf)
{
	int		n_ports = ft_lstsize(conf->ports);

	for (int i = 0; i < n_ports; ++i)
		free(scan->port_scan_array[i].scans_type);
	free(scan->port_scan_array);
	free(scan);
}

void	scan(t_nmap_config *conf)
{
	tpool_t	*tm;

	for (int i = 0; conf->ips[i]; ++i)
	{
		t_scan	*scan = create_scan_result_struct(conf, conf->ips[i]);
		tm = tpool_create(conf->n_speedup_threads + 1);
		tpool_add_work(tm, (void (*)(void *))sniffer, scan);
		clock_t	start;
		double	cpu_time_used;
		
		start = clock();
		iterate_over_every_port(conf);
		cpu_time_used = ((double)(clock() - start)) / CLOCKS_PER_SEC;

		tpool_wait(tm);
		printf("Scan took %f secs\n", cpu_time_used);
		printf("IP address: %s\n", conf->ips[i]);
		tpool_destroy(tm);
		free_scan_struct(scan, conf);
	}
}

int	main(int argc, char **argv)
{
	t_nmap_config	*conf;

	conf = malloc(sizeof(t_nmap_config));
	parse_options(argc, argv, conf);

	print_configurations(conf);

	printf("................\n");

	scan(conf);

	ft_lstclear(&conf->ports, free);
	double_free(conf->ips);
	free(conf);

	return 0;
}
