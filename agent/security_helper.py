import iptc
import psutil
import socket
from xml.etree import ElementTree as ET
from sh import nmap


def nmap_scan(target):
    """
    Performs an nmap portscan against the
    target on all TCP/UDP ports.
    """
    scan = nmap([target, '-sS', '-sU', '-oX', '-'])
    dom = ET.fromstring(scan.stdout)
    result = []

    for dhost in dom.findall('host'):
        host = dhost.find('address').get('addr')
        for dport in dhost.findall('ports/port'):
            proto = dport.get('protocol')
            port = int(dport.get('portid'))
            state = dport.find('state').get('state')

            result.append({
                'host': host,
                'proto': proto,
                'port': port,
                'state': state
            })
    return result


def is_firewall_enabled():
    """Check if FILTER INPUT chain contains any rule"""
    filter_table = iptc.Table(iptc.Table.FILTER)
    input_chain = next(filter(lambda c: c.name == 'INPUT', filter_table))
    return not len(input_chain.rules) == 0


def netstat_scan():
    """
    Returns all open inet connections with their addresses and PIDs.
    """
    connections = psutil.net_connections(kind='inet')
    return [{
        'ip_version': 4 if c.family == socket.AF_INET else 6,
        'type': 'udp' if c.type == socket.SOCK_DGRAM else 'tcp',
        'local_address': c.laddr,
        'remote_address': c.raddr,
        'status': c.status if c.type == socket.SOCK_STREAM else None,
        'pid': c.pid
    } for c in connections]


def process_scan():
    processes = []
    for proc in psutil.process_iter():
        try:
            processes.append(proc.as_dict(attrs=[
                'pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline',
                'environ', 'username', 'connections', 'status']))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes
