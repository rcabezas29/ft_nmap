#include <options.h>

static bool	is_valid_port_options(const char *argument)
{
	int	i;

	i = 0;
	while (argument[i])
	{
		if (argument[i] != ',' && argument[i] != '-' && !ft_isdigit(argument[i]))
			return false;
		i++;
	}
	return true;
}

static void	parse_port_ranges(char *commas, t_list **ports)
{
	char	**range;
	int		beggining, end;

	range = ft_split(commas, '-');
	beggining = ft_atoi(range[0]);
	end = ft_atoi(range[1]);
	double_free(range);
	if (beggining == 0 || end == 0)
	{
		write(STDERR_FILENO, "Error: Unable to recognize ports\n", 34);
		exit(EXIT_FAILURE);
	}
	if (((end - beggining) + 1) < 2)
	{
		write(STDERR_FILENO, "Error: Invalid range of ports\n", 31);
		exit(EXIT_FAILURE);
	}
	for (int i = beggining; i <= end; i++)
	{
		int	*n = malloc(sizeof(int));
		*n = i;
		ft_lstadd_back(ports, ft_lstnew(n));
	}
}

t_list	*parse_ports(const char *argument)
{
	char	**commas;
	t_list	*ports = NULL;

	if (!is_valid_port_options(argument))
	{
		write(STDERR_FILENO, "Error: Invalid port option\n", 28);
		exit(EXIT_FAILURE);
	}
	commas = ft_split(argument, ',');
	for (int i = 0; commas[i]; ++i)
	{
		if (ft_strchr(commas[i], '-'))
			parse_port_ranges(commas[i], &ports);
		else
		{
			int	*n = malloc(sizeof(int));
			*n = ft_atoi(commas[i]);
			if (n == 0)
			{
				write(STDERR_FILENO, "Error: Unable to recognize ports\n", 34);
				exit(EXIT_FAILURE);
			}
			ft_lstadd_back(&ports, ft_lstnew(n));
		}
	}
	if (ft_lstsize(ports) > 1024)
	{
		write(STDERR_FILENO, "Error: Too many ports\n", 23);
		exit(EXIT_FAILURE);
	}
	double_free(commas);
	return ports;
}
