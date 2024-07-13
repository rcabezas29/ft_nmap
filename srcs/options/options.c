#include <options.h>

void	parse_long_option(const char *option, const char *argument, t_nmap_config *conf)
{
	if (strcmp(option, "help") == 0) {
		free(conf);
		print_help();
	} else if (strcmp(option, "ports") == 0) {
		conf->ports = parse_ports(argument);
	} else if (strcmp(option, "ip") == 0) {
		conf->ips = parse_ip(argument);
	} else if (strcmp(option, "speedup") == 0) {
		conf->n_speedup_threads = parse_thread_number(argument);
	} else if (strcmp(option, "scan") == 0) {
		conf->scan_type = parse_scan_type(argument);
	} else if (strcmp(option, "file") == 0) {
		conf->ips = parse_ips_file(argument);
	}
}

void	parse_options(int argc, char **argv, t_nmap_config *conf)
{
	static struct option long_options[] = {
		{"help", no_argument, 0, 'h'},
		{"ports", required_argument, 0, 'p'},
		{"ip", required_argument, 0, 0},
		{"speedup", required_argument, 0, 's'},
		{"scan",  required_argument, 0, 0},
		{"file",  required_argument, 0, 'f'},
		{0, 0, 0, 0}
	};
	int	option_index = 0;
	int	default_threads = 0;
	int	default_scans = 0;
	int	mandatory_flag = 0;
	int	c;

	while ((c = getopt_long(argc, argv, "hp:s:f:", long_options, &option_index)) != -1) {
		if (c == 0) {
			parse_long_option(long_options[option_index].name, optarg, conf);
			if (strcmp(long_options[option_index].name, "ip") == 0)
				mandatory_flag += 1;
		} else if (c == 'h') {
			free(conf);
			print_help();
		} else if (c == 'p') {
			conf->ports = parse_ports(optarg);
		} else if (c == 's') {
			conf->n_speedup_threads = parse_thread_number(optarg);
			default_threads = 0;
		} else if (c == 'f') {
			conf->ips = parse_ips_file(optarg);
			mandatory_flag += 1;
		}
	}
	if (optind < argc) {
		fprintf(stderr, "Error: unexpected (%s)\n", argv[optind]);
		exit(EXIT_FAILURE);
	}
	if (mandatory_flag != 1) {
		printf("There are some mandatory flags that must be set: --ip/--file\n");
		exit(EXIT_FAILURE);
	}
	if (default_threads == 0) {
		conf->n_speedup_threads = 1;
	}
	if (default_scans == 0) {
		conf->scan_type = ALL;
	}
	if (ft_lstsize(conf->ports) > 1024) {
		printf("Ports cannot be more than 1024\n");
		exit(EXIT_FAILURE);
	}
}
