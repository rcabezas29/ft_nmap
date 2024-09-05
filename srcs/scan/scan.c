#include <ft_nmap.h>

struct pollfd	*initialize_poll_struct(t_thread_data *data)
{
	struct pollfd		*pfds;
	int					n_scans = data->scan->port_scan_array[0].n_scans;

	pfds = malloc(sizeof(struct pollfd) * data->n_ports * n_scans + 1);
	for (int port = 0; port < data->n_ports; port++)
	{
		for (t_scan_type sn = SYN; (int)sn < n_scans; sn++)
		{
			pfds[port * data->n_ports + sn].fd = socket(AF_INET, SOCK_RAW, sn == UDP || (data->scan->port_scan_array[0].scans_type[0].type == UDP) ? IPPROTO_UDP : IPPROTO_TCP);
			if (pfds[port * data->n_ports + sn].fd < 0)
			{
				perror("Socket creation failed");
				continue ;
			}
			pfds[port * data->n_ports + sn].events = POLLOUT;
		}
    }
	return pfds;
}

void	*scanning(t_thread_data *data)
{
	int					n_scans = data->scan->port_scan_array[0].n_scans;
	int					len = data->n_ports * n_scans;
	struct pollfd		*pfds = initialize_poll_struct(data);

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
				int port_index = (i + data->start_port_index) / n_scans;
				int port = data->scan->port_scan_array[port_index].port;
				t_scan_type st = data->scan->port_scan_array[port_index].scans_type[i % n_scans].type;
				
				if (pfds[i].revents & POLLIN) {
					printf("Port %d is open on %s\n", ntohs(pfds[i].fd), data->scan->ip);
				} else if (pfds[i].revents & POLLOUT) {
					// send_port_scan(data->scan->ip, );
				}
				close(pfds[i].fd);
			}
		}
	}
	free(pfds);
	return NULL;
}
