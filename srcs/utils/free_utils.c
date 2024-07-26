#include <utils.h>

void	double_free(char **arr)
{
	for (int i = 0; arr[i]; ++i)
		free(arr[i]);
	free(arr);
}
