import iptc
from xml.etree import ElementTree as ET
from sh import netstat, nmap


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


def parse_line(l):
    fields = l.split()
    state = fields[5] if len(fields) > 5 and fields[5] != '-' else None
    program = fields[6] if len(fields) > 6 and fields[6] != '-' else None
    return {
        'proto': fields[0],
        'recv_q': fields[1],
        'send_q': fields[2],
        'local_address': fields[3],
        'foreign_address': fields[4],
        'state': state,
        'program': program}


def netstat_scan():
    """
    Returns all open inet connections with their addresses and PIDs.
    """
    out = netstat(['-pa'])
    lines_str = out.stdout
    lines = lines_str.decode().split('\n')
    list_start = 0
    list_end = len(lines)
    for i, l in enumerate(lines):
        if l.startswith('Active Internet connections'):
            if len(lines) > i and lines[i + 1].startswith('Proto'):
                list_start = i + 2
        elif l.startswith('Active '):
            list_end = i
            break
    return [parse_line(l) for l in lines[list_start:list_end]]
