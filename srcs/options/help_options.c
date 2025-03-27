#include <options.h>

void	print_help(void)
{
	printf(
		"Help Screen\n" \
		"ft_nmap [OPTIONS]\n" \
		" --help/-h     Print this help screen\n" \
		" --ports/-p    ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n" \
		" --ip          ip addresses to scan in dot format\n" \
		" --file/-f     File name containing IP addresses to scan,\n" \
		" --speedup     [250 max] number of parallel threads to use\n" \
		" --scan/-s     SYN/NULL/FIN/XMAS/ACK/UDP\n"
		" --timeout/-t  timeout in ms\n"
	);
	exit(EXIT_SUCCESS);
}
