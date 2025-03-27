#include <ft_nmap.h>

char	*print_scan_types(t_list *scan_types)
{
	char	*str = ft_calloc(1, 1);
	char	*tmp;

	while (scan_types)
	{
		tmp = str;
		str = ft_strjoin(str, scan_types->content);
		free(tmp);
		if (scan_types->next)
		{
			tmp = str;
			str = ft_strjoin(str, " ");
			free(tmp);
		}
		scan_types = scan_types->next;
	}
	return (str);
}

void	print_configurations(t_nmap_config *conf, int i)
{
	char	*scan_types = print_scan_types(conf->scan_type);

	printf("\nScan Configurations\n");
	printf("Target Ip-Address : %s\n", conf->ips[i]);
	printf("No of Ports to scan : %i\n", ft_lstsize(conf->ports));
	printf("Scans to be performed : %s \n", scan_types);
	printf("No of threads : %i\n", conf->n_speedup_threads);
	printf("Scanning...\n");
	printf("................\n");
	free(scan_types);
}

static const char *get_scan_type_name(t_scan_type type)
{
	switch (type)
	{
		case SYN:
			return "SYN";
		case NUL:
			return "NULL";
		case FIN:
			return "FIN";
		case XMAS:
			return "XMAS";
		case ACK:
			return "ACK";
		case UDP:
			return "UDP";
		default:
			return "UNKNOWN";
	}
}

static const char *get_scan_state_name(t_scan_state state)
{
	switch (state)
	{
		case FILTERED:
			return "Filtered";
		case OPEN:
			return "Open";
		case CLOSED:
			return "Closed";
		case OPEN_FILTERED:
			return "Open|Filtered";
		case UNFILTERED:
			return "Unfiltered";
		default:
			return "Unknown";
	}
}

char	*get_service_name(int port)
{
	struct servent *service = getservbyport(htons(port), "tcp");
	if (service)
		return service->s_name;
	service = getservbyport(htons(port), "udp");
	if (service)
		return service->s_name;
	return "Unassigned";
}

void print_scan_result(t_scan *scan)
{
	printf("Open ports:\n");
	printf("Port    Service Name (if applicable)    Results                      Conclusion\n");
	printf("-------------------------------------------------------------------------------\n");

	for (int i = 0; i < scan->n_ports; i++)
	{
		t_port_scan *port_scan = &scan->port_scan_array[i];
		int open = 0;
		for (int j = 0; j < port_scan->n_scans; j++)
		{
			if (port_scan->scans_type[j].state == OPEN)
			{
				open = 1;
				break;
			}
		}
		if (open)
		{
			printf("%-7d %-32s ", port_scan->port, get_service_name(port_scan->port));
			for (int j = 0; j < port_scan->n_scans; j++)
			{
				printf("%s(%s) ", get_scan_type_name(port_scan->scans_type[j].type), get_scan_state_name(port_scan->scans_type[j].state));
			}
			printf("%10s\n", "Open");
		}
	}

	printf("\nClosed/Filtered/Unfiltered ports:\n");
	printf("Port    Service Name (if applicable)    Results                      Conclusion\n");
	printf("-------------------------------------------------------------------------------\n");

	for (int i = 0; i < scan->n_ports; i++)
	{
		t_port_scan *port_scan = &scan->port_scan_array[i];
		int open = 0;
		for (int j = 0; j < port_scan->n_scans; j++)
		{
			if (port_scan->scans_type[j].state == OPEN)
			{
				open = 1;
				break;
			}
		}
		if (!open)
		{
			printf("%-7d %-32s ", port_scan->port, get_service_name(port_scan->port));
			for (int j = 0; j < port_scan->n_scans; j++)
			{
				printf("%s(%s) ", get_scan_type_name(port_scan->scans_type[j].type), get_scan_state_name(port_scan->scans_type[j].state));
			}
			printf("%10s\n", "Closed");
		}
	}
}
