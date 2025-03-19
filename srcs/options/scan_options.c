#include <options.h>

t_list	*add_all_scans(void)
{
	t_list	*scan_type;

	ft_lstadd_back(&scan_type, ft_lstnew(ft_strdup("SYN")));
	ft_lstadd_back(&scan_type, ft_lstnew(ft_strdup("NULL")));
	ft_lstadd_back(&scan_type, ft_lstnew(ft_strdup("ACK")));
	ft_lstadd_back(&scan_type, ft_lstnew(ft_strdup("FIN")));
	ft_lstadd_back(&scan_type, ft_lstnew(ft_strdup("XMAS")));
	ft_lstadd_back(&scan_type, ft_lstnew(ft_strdup("UDP")));
	return (scan_type);
}

void	parse_scan_type(t_list **scan_type, const char *argument)
{
	if (strcmp(argument, "SYN") != 0 &&
		strcmp(argument, "NULL") != 0 &&
		strcmp(argument, "ACK") != 0 &&
		strcmp(argument, "FIN") != 0 &&
		strcmp(argument, "XMAS") != 0 &&
		strcmp(argument, "UDP") != 0)
	{
		fprintf(stderr, "Error: invalid scan type: %s\n", argument);
		exit(EXIT_FAILURE);
	}
	else
		ft_lstadd_back(scan_type, ft_lstnew(ft_strdup(argument)));
}
