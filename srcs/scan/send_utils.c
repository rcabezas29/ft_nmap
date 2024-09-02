#include <ft_nmap.h>

void	get_local_ip(char *buffer)
{
	struct sockaddr_in	serv, name;
	const char*			kGoogleDnsIp = "8.8.8.8";
	int					dns_port = 53;
	int					sock = socket(AF_INET, SOCK_DGRAM, 0);

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(kGoogleDnsIp);
	serv.sin_port = htons(dns_port);
	connect(sock, (const struct sockaddr*)&serv, sizeof(serv));
	socklen_t namelen = sizeof(name);
	getsockname(sock, (struct sockaddr*) &name, &namelen);
	inet_ntop(AF_INET, &name.sin_addr, buffer, 100);
	close(sock);
}

unsigned short csum(unsigned short *ptr,int nbytes) 
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
