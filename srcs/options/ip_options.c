#include <options.h>

bool		is_valid_ip(const char *ip)
{
	struct sockaddr_in	sa;

	int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
	return result != 0;
}

static int	count_ip_file_length(FILE *fp)
{
	size_t	len = 0;
	int		count = 0;
	char	*line = NULL;

	fseek(fp, 0, SEEK_SET);
	while (getline(&line, &len, fp) != -1)
		count++;
	free(line);
	return count;
}

static char	*get_ip_from_domain(const char *domain)
{
	struct hostent *ghbn = gethostbyname(domain);

	if (ghbn)
		return ft_strdup(inet_ntoa(*(struct in_addr *)ghbn->h_addr));
	else
	{
		ft_putstr_fd("Invalid IP Address\n", STDERR_FILENO);
		exit(EXIT_FAILURE);
	}
}

char	**parse_ips_file(const char *argument)
{
	FILE	*fp;
	char	**ips;
	char	*line = NULL;
	size_t	len;
	int		i;

	fp = fopen(argument, "r");
	if (fp == NULL)
	{
		printf("unable to find file (%s)\n", argument);
		exit(EXIT_FAILURE);
	}
	ips = malloc((count_ip_file_length(fp) + 1) * sizeof(char *));
	i = 0;
	fseek(fp, 0, SEEK_SET);
	while ((getline(&line, &len, fp)) != -1)
	{
		line[strcspn(line, "\n")] = '\0';
		if (is_valid_ip(line))
			ips[i] = ft_strdup(line);
		else
			ips[i] = get_ip_from_domain(line);
		i++;
	}
	free(line);
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
