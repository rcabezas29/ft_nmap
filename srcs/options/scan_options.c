#include <options.h>

t_scan_type	parse_scan_type(const char *argument)
{
	if (strcmp(argument, "SYN") == 0)
		return SYN;
	else if (strcmp(argument, "NULL") == 0)
		return NUL;
	else if (strcmp(argument, "ACK") == 0)
		return ACK;
	else if (strcmp(argument, "FIN") == 0)
		return FIN;
	else if (strcmp(argument, "XMAS") == 0)
		return XMAS;
	else if (strcmp(argument, "UDP") == 0)
		return UDP;
	else
	{
		printf("Error while reading invalid SCAN TYPE option (%s)\n", argument);
		exit(EXIT_FAILURE);
	}
}
