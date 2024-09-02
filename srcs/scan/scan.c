#include <ft_nmap.h>

struct pollfd	*initialize_poll_struct(t_thread_data *data)
{
	struct pollfd		*pfds;
	struct sockaddr_in	target;
	int					n_scans = data->scan->port_scan_array[0].n_scans;

	pfds = malloc(sizeof(struct pollfd) * data->n_ports * n_scans);
	for (int port = 0; port <= data->n_ports; port++)
	{
		for (t_scan_type sn = SYN; (int)sn < n_scans; ++sn)
		{
			pfds[port + sn].fd = socket(AF_INET, SOCK_RAW, sn == UDP || (data->scan->port_scan_array[0].scans_type[0].type == UDP) ? IPPROTO_UDP : IPPROTO_TCP);
			if (pfds[port + sn].fd < 0)
			{
				perror("Socket creation failed");
				continue ;
			}

			target.sin_family = AF_INET;
			target.sin_port = htons(port);
			inet_pton(AF_INET, data->scan->ip, &target.sin_addr);

			pfds[port + sn].events = POLLOUT;
		}
    }
	return pfds;
}

void	*scanning(t_thread_data *data)
{
	int					len = data->n_ports * data->scan->port_scan_array[0].n_scans;
	struct pollfd		*pfds = initialize_poll_struct(data);

	printf("Scanning Ports: %i - %i\nNumber of ports = %i\n", data->scan->port_scan_array[data->start_port_index].port, data->scan->port_scan_array[data->end_port_index].port, data->n_ports);
	while (true)
	{
		int ret = poll(pfds, len, 50000);
		if (ret < 0)
			perror("poll failed");
		else if (ret == 0)
			printf("Timeout occurred! No data.\n");
		else
		{
			for (int i = 0; i < len; i++)
			{
				if (pfds[i].revents & POLLIN) {
					printf("Port %d is open on %s\n", ntohs(pfds[i].fd), data->scan->ip);
				} else if (pfds[i].revents & POLLOUT) {
					send(pfds[i].fd, "hola", 4, 0);
				} else {
					printf("Port %d is closed or filtered on %s\n", ntohs(pfds[i].fd), data->scan->ip);
				}
				close(pfds[i].fd);
			}
		}
	}
	free(pfds);
	return NULL;
}
