#include <ft_nmap.h>

float	iterate_over_every_port(t_scan *scan, int n_threads, int timeout)
{
	pthread_t		threads[n_threads];
	t_thread_data	*thread_data = malloc(sizeof(t_thread_data) * n_threads);
	int				ports_per_thread = scan->n_ports / n_threads;
	int				extra_ports = scan->n_ports % n_threads;
	char			*source_ip = malloc(INET_ADDRSTRLEN);
	struct timeval	start, end;
	
	get_local_ip(scan->ip, source_ip);
	for (int i = 0; i < n_threads; i++)
	{
		thread_data[i].scan = scan;
		thread_data[i].n_ports = ports_per_thread + (i < extra_ports ? 1 : 0);
		thread_data[i].start_port_index = i * ports_per_thread + (i < extra_ports ? i : extra_ports);
		thread_data[i].end_port_index = thread_data[i].start_port_index + thread_data[i].n_ports - 1;
		thread_data[i].source_ip = source_ip;
		if (pthread_create(&threads[i], NULL, (void *(*)(void *))scanning, &thread_data[i]) != 0)
		{
			perror("pthread_create failed");
			free(thread_data);
			exit(EXIT_FAILURE);
		}
	}
	gettimeofday(&start, NULL);
	sniffer(scan, timeout, scan->ip);
	gettimeofday(&end, NULL);
	for (int i = 0; i < n_threads; i++)
	{
		if (pthread_join(threads[i], NULL) != 0)
		{
			perror("pthread_join failed");
			exit(EXIT_FAILURE);
		}
	}
	free(source_ip);
	free(thread_data);
	return (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1000000.0;
}

void	scan(t_nmap_config *conf, int i)
{
	t_scan		*scan = create_scan_result_struct(conf, conf->ips[i]);
	float		scan_time;

	scan_time = iterate_over_every_port(scan, conf->n_speedup_threads, conf->timeout);

	printf("Scan took %f secs\n", scan_time);
	printf("IP address: %s\n", conf->ips[i]);
	print_scan_result(scan);

	free_scan_struct(scan, conf);
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

	for (int i = 0; conf->ips[i]; ++i)
	{
		print_configurations(conf, i);
		scan(conf, i);
	}
	free_conf(conf);
	return 0;
}
