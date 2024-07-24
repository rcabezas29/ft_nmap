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
	else if (scan == ALL)
		return "SYN NUL ACK FIN XMAS UDP";
	return "";
}
