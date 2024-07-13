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

void	scan(t_nmap_config *conf)
{
	for (int i = 0; conf->ips[i]; ++i)
	{
		clock_t start;
		double cpu_time_used;
		
		start = clock();
		iterate_over_every_port(conf);
		cpu_time_used = ((double)(clock() - start)) / CLOCKS_PER_SEC;

		printf("Scan took %f secs\n", cpu_time_used);
		printf("IP address: %s\n", conf->ips[i]);
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
