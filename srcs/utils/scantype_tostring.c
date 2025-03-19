#include <utils.h>

char	*scantype_tostring(t_scan_type scan)
{
	if (scan == SYN)
		return "SYN";
	else if (scan == NUL)
		return "NUL";
	else if (scan == ACK)
		return "ACK";
	else if (scan == FIN)
		return "FIN";
	else if (scan == XMAS)
		return "XMAS";
	else if (scan == UDP)
		return "UDP";
	return "";
}

t_scan_type	string_to_scan_type(const char *str)
{
	if (strcmp(str, "SYN") == 0)
		return SYN;
	else if (strcmp(str, "NUL") == 0)
		return NUL;
	else if (strcmp(str, "ACK") == 0)
		return ACK;
	else if (strcmp(str, "FIN") == 0)
		return FIN;
	else if (strcmp(str, "XMAS") == 0)
		return XMAS;
	else if (strcmp(str, "UDP") == 0)
		return UDP;
	return -1;
}
