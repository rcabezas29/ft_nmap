#include <options.h>

int	parse_timeout(const char *timeout)
{
	int	timeout_int = ft_atoi(timeout);
	if (timeout_int < 0)
	{
		ft_putstr_fd("Invalid timeout value\n", 2);
		exit(EXIT_FAILURE);
	}
	return timeout_int;
}