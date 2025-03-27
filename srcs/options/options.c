#include <options.h>

void parse_long_option(const char *option, const char *argument, t_nmap_config *conf)
{
	if (strcmp(option, "help") == 0)
	{
		free(conf);
		print_help();
	}
	else if (strcmp(option, "ports") == 0)
		conf->ports = parse_ports(argument);
	else if (strcmp(option, "ip") == 0)
		conf->ips = parse_ip(argument);
	else if (strcmp(option, "speedup") == 0)
		conf->n_speedup_threads = parse_thread_number(argument);
	else if (strcmp(option, "scan") == 0)
		parse_scan_type(&conf->scan_type , argument);
	else if (strcmp(option, "file") == 0)
		conf->ips = parse_ips_file(argument);
	else if (strcmp(option, "timeout") == 0)
		conf->timeout = parse_timeout(argument);
}

void parse_options(int argc, char **argv, t_nmap_config *conf)
{
	static struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"ports", required_argument, 0, 'p'},
		{"ip", required_argument, 0, 0},
		{"speedup", required_argument, 0, 's'},
		{"scan", required_argument, 0, 0},
		{"file", required_argument, 0, 'f'},
		{"timeout", required_argument, 0, 't'},
		{0, 0, 0, 0}};
	int option_index = 0;
	int mandatory_flag = 0;
	int c;

	while ((c = getopt_long(argc, argv, "hp:s:f:t:", long_options, &option_index)) != -1)
	{
		if (c == 0)
		{
			parse_long_option(long_options[option_index].name, optarg, conf);
			if (strcmp(long_options[option_index].name, "ip") == 0)
				mandatory_flag += 1;
		}
		else if (c == 'h')
		{
			free(conf);
			print_help();
		}
		else if (c == 'p')
			conf->ports = parse_ports(optarg);
		else if (c == 's')
			conf->n_speedup_threads = parse_thread_number(optarg);
		else if (c == 'f')
		{
			conf->ips = parse_ips_file(optarg);
			mandatory_flag += 1;
		}
		else if (c == 't')
			conf->timeout = parse_timeout(optarg);
	}
	if (optind < argc)
	{
		fprintf(stderr, "Error: unexpected (%s)\n", argv[optind]);
		exit(EXIT_FAILURE);
	}
	if (mandatory_flag != 1)
	{
		printf("There are some mandatory flags that must be set: --ip/--file\n");
		exit(EXIT_FAILURE);
	}
	if (conf->n_speedup_threads == 0)
		conf->n_speedup_threads = 1;
	if (ft_lstsize(conf->scan_type) == 0)
		conf->scan_type = add_all_scans();
	if (conf->ports == NULL)
		conf->ports = parse_ports("1-1024");
	if (conf->timeout == 0)
		conf->timeout = 500;
	if (ft_lstsize(conf->ports) > 1024)
	{
		printf("Ports cannot be more than 1024\n");
		exit(EXIT_FAILURE);
	}
}
