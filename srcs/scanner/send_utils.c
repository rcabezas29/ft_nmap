#include <ft_nmap.h>

void	get_local_ip(const char *dest_ip, char *ip_buffer)
{
	struct sockaddr_in name, serv;
	socklen_t namelen;
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0)
	{
		perror("socket");
		exit(EXIT_FAILURE);
	}
	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(dest_ip);
	serv.sin_port = htons(80);

	if (connect(sock, (const struct sockaddr*) &serv, sizeof(serv)) < 0)
	{
		perror("connect");
		close(sock);
		exit(EXIT_FAILURE);
	}
	namelen = sizeof(name);
	if (getsockname(sock, (struct sockaddr*) &name, &namelen) < 0)
	{
		perror("getsockname");
		close(sock);
		exit(EXIT_FAILURE);
	}
	inet_ntop(AF_INET, &name.sin_addr, ip_buffer, INET_ADDRSTRLEN);
	close(sock);
}

unsigned short	csum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1)
	{
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1)
	{
		oddbyte = 0;
		*((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;
	return (answer);
}
