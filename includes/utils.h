#ifndef UTILS_H
#define UTILS_H

#include <stdlib.h>

typedef enum	e_scan_type {
	SYN,
	NUL,
	ACK,
	FIN,
	XMAS,
	UDP,
	ALL
}	t_scan_type;

void	double_free(char **arr);
char	*scantype_tostring(t_scan_type scan);

#endif
