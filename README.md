# ft_nmap

## Overview
`ft_nmap` is a custom implementation of a network port scanner, inspired by the popular [Nmap tool](https://nmap.org/). It allows users to scan for open ports, detect hosted services, and gather information about remote systems. The project is built in C and utilizes the `pcap` and `pthread` libraries to achieve high-performance scanning through multithreading.

## Features
- Supports scanning of IPv4 addresses and hostnames.
- Allows scanning using multiple techniques:
  - **SYN scan**: Sends a SYN packet and waits for a SYN-ACK response to detect open ports. A lack of response or a RST packet indicates a closed or filtered port.
  - **NULL scan**: Sends packets with no flags set. Closed ports respond with an RST, while open ports remain silent.
  - **ACK scan**: Used to determine firewall rules rather than open ports. An RST response suggests the port is unfiltered.
  - **FIN scan**: Sends a FIN flag to the target. Open ports ignore the packet, while closed ports return an RST.
  - **XMAS scan**: Sends packets with FIN, URG, and PUSH flags set. Open ports remain silent, while closed ports send an RST.
  - **UDP scan**: Sends UDP packets to target ports. If ICMP unreachable errors are received, the port is considered closed. No response suggests an open or filtered port.
- Supports both individual port scanning and ranged scanning (1-1024 by default).
- Allows parallel scanning with user-defined thread count (max: 250).
- Allows setting a custom timeout for scan responses.
- Accepts input from both command-line arguments and files.
- Outputs results in a clean and readable format.

## Usage
```
ft_nmap [OPTIONS]
```

### Command-line Options
| Option          | Description |
|----------------|-------------|
| `--help/-h`    | Displays the help menu. |
| `--ports/-p`   | Specifies ports to scan (e.g., `1-10`, `22,80,443`, or `1000-2000`). |
| `--ip`         | Specifies a single IP address or hostname to scan. |
| `--file/-f`    | Reads a list of IP addresses/hostnames from a file. |
| `--speedup`    | Sets the number of parallel threads for scanning (default: 0, max: 250). |
| `--scan/-s`    | Specifies the scan type (SYN, NULL, FIN, XMAS, ACK, UDP). If not provided, all types are used. |
| `--timeout/-t` | Sets the timeout value for scan responses in milliseconds. |

### Example Usage
#### Single IP with a specified port range:
```sh
./ft_nmap --ip 192.168.1.1 --ports 22,80,443 --scan SYN -t 500
```

#### Scanning multiple IPs from a file:
```sh
./ft_nmap --file targets.txt --ports 1-1024 --speedup 100 -t 1000
```

#### Running all scan types with maximum threads and a 300ms timeout:
```sh
./ft_nmap --ip 10.0.0.1 --speedup 250 -t 300
```

## Example Output
```
Scan Configurations
Target IP Address: 192.168.1.1
Number of Ports to Scan: 3
Scans to be Performed: SYN
Number of Threads: 200
Scanning...
Scan took 8.32 secs

IP address: 192.168.1.1
Open ports:
Port   Service Name   Results   Conclusion
-------------------------------------------
80     http          SYN(Open)  Open
22     ssh           SYN(Open)  Open
443    https        SYN(Open)  Open
```
