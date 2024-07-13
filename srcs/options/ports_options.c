#include <options.h>


static void	parse_port_ranges(char *commas, t_list **ports)
{
	char	**range;
	int		beggining, end;

	range = ft_split(commas, '-');
	beggining = ft_atoi(range[0]);
	end = ft_atoi(range[1]);
	double_free(range);
	if (beggining == 0 || end == 0) {
		fprintf(stderr, "Error: Unable to recognize ports\n");
		exit(EXIT_FAILURE);
	}

	if (((end - beggining) + 1) < 2) {
		fprintf(stderr, "Error: Invalid range of ports\n");
		exit(EXIT_FAILURE);
	}

	for (int i = beggining; i <= end; i++) {
		int	*n = malloc(sizeof(int));
		*n = i;
		ft_lstadd_back(ports, ft_lstnew(n));
	}
}

t_list	*parse_ports(const char *argument)
{
	char	**commas = ft_split(argument, ',');
	t_list	*ports = NULL;

	for (int i = 0; commas[i]; ++i)
	{
		if (ft_strchr(commas[i], '-')) {
			parse_port_ranges(commas[i], &ports);
		} else {
			int	*n = malloc(sizeof(int));
			*n = ft_atoi(commas[i]);
			if (n == 0) {
				fprintf(stderr, "Error: Unable to recognize ports\n");
				exit(EXIT_FAILURE);
			}
			ft_lstadd_back(&ports, ft_lstnew(n));
		}
	}
	double_free(commas);

	return ports;
}
