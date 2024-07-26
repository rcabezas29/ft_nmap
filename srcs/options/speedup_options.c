#include <options.h>

int	parse_thread_number(const char *argument)
{
	int	n = ft_atoi(argument);
	if (n < 1 || n > 250)
	{
		printf("Error while reading the number of threads\n"
		"Only numbers between 1 and 250 are supported\n");
		exit(EXIT_FAILURE);
	}
	else
		return (n);
}
