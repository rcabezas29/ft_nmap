#include <options.h>

bool is_valid_ip(const char *ip)
{
    struct sockaddr_in	sa;

    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}

static int	count_ip_file_length(const char *argument)
{
	FILE	*fp;
	char	*line;
	size_t	len;
	int		i;

	fp = fopen(argument, "r");
	i = 0;
	while ((getline(&line, &len, fp)) != -1)
		++i;
	fclose(fp);
	return i;
}

static char	*get_ip_from_domain(const char *domain)
{
	struct hostent *ghbn = gethostbyname(domain);

	if (ghbn)
		return ft_strdup(inet_ntoa(*(struct in_addr *)ghbn->h_addr));
	else
	{
		printf("Invalid IP Address");
		exit(EXIT_FAILURE);
	}
}

char	**parse_ips_file(const char *argument)
{
	FILE	*fp;
	char	**ips;
	char	*line;
	size_t	len;
	int		i;

	fp = fopen(argument, "r");
	if (fp == NULL)
	{
		printf("unable to find file (%s)\n", argument);
		exit(EXIT_FAILURE);
	}

	ips = malloc(count_ip_file_length(argument) * sizeof(char *));
	i = 0;
	while ((getline(&line, &len, fp)) != -1)
	{
		if (is_valid_ip(line))
			ips[i] = ft_strdup(line);
		else
			ips[i] = get_ip_from_domain(line);
		i++;
	}
	ips[i] = NULL;
	fclose(fp);
	return ips;
}


char	**parse_ip(const char *argument)
{
	char	**ip = malloc(2 * sizeof(char *));
	if (is_valid_ip(argument))
		ip[0] = ft_strdup(argument);
	else
		ip[0] = get_ip_from_domain(argument);
	ip[1] = NULL;
	return ip;
}
