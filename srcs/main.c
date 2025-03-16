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

void	iterate_over_every_port(t_scan *scan)
{
	pthread_t		threads[4];
	t_thread_data	*thread_data = malloc(sizeof(t_thread_data) * 4);
	int				ports_per_thread = scan->n_ports / 4;
	int				extra_ports = scan->n_ports % 4;

	for (int i = 0; i < 4; i++)
	{
		thread_data[i].scan = scan;
		thread_data[i].n_ports = ports_per_thread + (i < extra_ports ? 1 : 0);
		thread_data[i].start_port_index = i * ports_per_thread + (i < extra_ports ? i : extra_ports);
			thread_data[i].end_port_index = thread_data[i].start_port_index + thread_data[i].n_ports - 1;

		if (pthread_create(&threads[i], NULL, (void *(*)(void *))scanning, &thread_data[i]) != 0)
		{
			perror("pthread_create failed");
			free(thread_data);
			exit(EXIT_FAILURE);
		}
			}
	for (int i = 0; i < 4; i++)
	{
		if (pthread_join(threads[i], NULL) != 0)
		{
			perror("pthread_join failed");
			exit(EXIT_FAILURE);
		}
	}
    free(thread_data);
}

t_scan	*create_scan_result_struct(t_nmap_config *conf, char *ip)
{
	t_scan	*scan = malloc(sizeof(t_scan));
	int		n_ports = ft_lstsize(conf->ports);
	int		n_scans = conf->scan_type == ALL ? 6 : 1;

	scan->ip = ip;
	scan->n_ports = n_ports;
	scan->port_scan_array = malloc(sizeof(t_port_scan) * n_ports);

	t_list	*current_port = conf->ports;
	for (int i = 0; i < n_ports; ++i)
	{
		scan->port_scan_array[i].port = *(int *)(current_port->content);
		scan->port_scan_array[i].scans_type = malloc(sizeof(t_scan_type_pair) * n_scans);
		scan->port_scan_array[i].n_scans = n_scans;
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
	for (int i = 0; conf->ips[i]; ++i)
	{
		t_scan	*scan = create_scan_result_struct(conf, conf->ips[i]);

		struct timeval end, start;

  		gettimeofday(&start, NULL);
		iterate_over_every_port(scan);

		gettimeofday(&end, NULL);
		printf("Scan took %f secs\n", (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0);
		printf("IP address: %s\n", conf->ips[i]);
		free_scan_struct(scan, conf);
	}
}

int	main(int argc, char **argv)
{
	t_nmap_config	*conf;

	if (getuid())
	{
		write(2, "ft_nmap must be run with root rights\n", 38);
		return 1;
	}
	conf = ft_calloc(1, sizeof(t_nmap_config));
	parse_options(argc, argv, conf);

	print_configurations(conf);

	printf("................\n");

	// scan(conf);

	ft_lstclear(&conf->ports, free);
	double_free(conf->ips);
	free(conf);

	return 0;
}
