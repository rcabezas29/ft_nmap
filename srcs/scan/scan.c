#include <ft_nmap.h>

void	*scanning(t_thread_data *data)
{
	int					n_scans = data->scan->port_scan_array[0].n_scans;
	int					len = data->n_ports * n_scans;
	int					*sockets = malloc(sizeof(int) * len);

	for (int i = 0; i < len; i++)
	{
		int port_index = (i + data->start_port_index) / n_scans;
		int port = data->scan->port_scan_array[port_index].port;
		t_scan_type st = data->scan->port_scan_array[port_index].scans_type[i % n_scans].type;

		sockets[i] = socket(AF_INET, SOCK_RAW, st == UDP || (data->scan->port_scan_array[0].scans_type[0].type == UDP) ? IPPROTO_UDP : IPPROTO_TCP);
		if (sockets[i] < 0)
		{
			perror("Socket creation failed");
			continue ;
		}
		send_port_scan(sockets[i], data->scan->ip, port, st);
		close(sockets[i]);
	}
	return NULL;
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
