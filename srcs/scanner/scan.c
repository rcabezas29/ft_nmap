#include <ft_nmap.h>

void *scanning(t_thread_data *data)
{
	int n_scans = data->scan->port_scan_array[0].n_scans;
	int len = data->n_ports * n_scans;
	int *sockets = malloc(sizeof(int) * len);
	int one = 1;
	const int *val = &one;

	while (data->scan->ready_to_send == false)
		usleep(500);
	for (int i = 0; i < len; i++)
	{
		int port_index = data->start_port_index + i / n_scans;
		int port = data->scan->port_scan_array[port_index].port;
		t_scan_type_info *sti = &(data->scan->port_scan_array[port_index].scans_type[i % n_scans]);

		sockets[i] = socket(AF_INET, SOCK_RAW, sti->type == UDP ? IPPROTO_UDP : IPPROTO_TCP);
		if (sockets[i] < 0)
		{
			perror("Socket creation failed");
			continue;
		}
		if (setsockopt(sockets[i], IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
		{
			printf("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n", errno, strerror(errno));
			exit(1);
		}
		send_port_scan(sockets[i], data->scan->ip, port, sti, data->source_ip);
		close(sockets[i]);
	}
	free(sockets);
	return NULL;
}

t_scan	*create_scan_result_struct(t_nmap_config *conf, char *ip)
{
	t_scan *scan = malloc(sizeof(t_scan));
	int n_ports = ft_lstsize(conf->ports);
	int n_scans = ft_lstsize(conf->scan_type);

	scan->ip = ip;
	scan->n_ports = n_ports;
	scan->port_scan_array = malloc(sizeof(t_port_scan) * (n_ports + 1));
	scan->port_scan_array[n_ports].port = -1;

	t_list *current_port = conf->ports;
	for (int i = 0; i < n_ports; ++i)
	{
		scan->port_scan_array[i].port = *(int *)(current_port->content);
		scan->port_scan_array[i].scans_type = malloc(sizeof(t_scan_type_info) * n_scans);
		scan->port_scan_array[i].n_scans = n_scans;
		t_list *current_scan = conf->scan_type;
		for (int j = 0; j < n_scans; ++j)
		{
			scan->port_scan_array[i].scans_type[j].type = string_to_scan_type(current_scan->content);
			scan->port_scan_array[i].scans_type[j].state = (scan->port_scan_array[i].scans_type[j].type == SYN || scan->port_scan_array[i].scans_type[j].type == ACK) ? FILTERED : OPEN_FILTERED;
			current_scan = current_scan->next;
		}
		current_port = current_port->next;
	}
	scan->ready_to_send = false;
	return scan;
}
