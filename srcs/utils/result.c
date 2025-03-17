#include <ft_nmap.h>

void	print_configurations(t_nmap_config *conf, int i)
{
	printf("\nScan Configurations\n");
	printf("Target Ip-Address : %s\n", conf->ips[i]);
	printf("No of Ports to scan : %i\n", ft_lstsize(conf->ports));
	printf("Scans to be performed : %s \n", scantype_tostring(conf->scan_type));
	printf("No of threads : %i\n", conf->n_speedup_threads);
	printf("Scanning...\n");
	printf("................\n");
}

static const char *get_scan_type_name(t_scan_type type)
{
    switch (type)
    {
    case SYN:
        return "SYN";
    case NUL:
        return "NULL";
    case FIN:
        return "FIN";
    case XMAS:
        return "XMAS";
    case ACK:
        return "ACK";
    case UDP:
        return "UDP";
    default:
        return "UNKNOWN";
    }
}

static const char *get_scan_state_name(t_scan_state state)
{
    switch (state)
    {
    case FILTERED:
        return "Filtered";
    case OPEN:
        return "Open";
    case CLOSED:
        return "Closed";
    default:
        return "Unknown";
    }
}

void print_scan_result(t_scan *scan)
{
    printf("Open ports:\n");
    printf("Port    Service Name (if applicable)    Results                      Conclusion\n");
    printf("-------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < scan->n_ports; i++)
    {
        t_port_scan *port_scan = &scan->port_scan_array[i];
        int open = 0;
        for (int j = 0; j < port_scan->n_scans; j++)
        {
            if (port_scan->scans_type[j].state == OPEN)
            {
                open = 1;
                break;
            }
        }
        if (open)
        {
            printf("%-7d %-32s ", port_scan->port, "http"); // Assuming http as a placeholder
            for (int j = 0; j < port_scan->n_scans; j++)
            {
                printf("%s(%s) ", get_scan_type_name(port_scan->scans_type[j].type), get_scan_state_name(port_scan->scans_type[j].state));
            }
            printf("Open\n");
        }
    }
    
    printf("\nClosed/Filtered/Unfiltered ports:\n");
    printf("Port    Service Name (if applicable)    Results                      Conclusion\n");
    printf("-------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < scan->n_ports; i++)
    {
        t_port_scan *port_scan = &scan->port_scan_array[i];
        int open = 0;
        for (int j = 0; j < port_scan->n_scans; j++)
        {
            if (port_scan->scans_type[j].state == OPEN)
            {
                open = 1;
                break;
            }
        }
        if (!open)
        {
            printf("%-7d %-32s ", port_scan->port, port_scan->service_name ? port_scan->service_name : "Unassigned");
            for (int j = 0; j < port_scan->n_scans; j++)
            {
                printf("%s(%s) ", get_scan_type_name(port_scan->scans_type[j].type), get_scan_state_name(port_scan->scans_type[j].state));
            }
            printf("Closed\n");
        }
    }
}
