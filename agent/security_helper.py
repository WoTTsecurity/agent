from . import iptc_helper
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
    chain = iptc_helper.dump_chain('filter', 'INPUT')
    return len(chain) > 0 if chain else False


def get_firewall_rules():
    """Get all FILTER table rules"""
    return iptc_helper.dump_table('filter')


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
                'pid', 'name', 'cmdline', 'username'
            ]))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return processes


def is_app_armor_enabled():
    """
    Returns a True/False if AppArmor is enabled.
    """
    try:
        from sh import aa_status
    except ImportError:
        return False

    # Returns 0 if enabled and 1 if disable
    get_aa_status = aa_status(['--enabled'], _ok_code=[0, 1]).exit_code
    if get_aa_status == 1:
        return False
    return True


def selinux_status():
    """
    Returns a dict as similar to:
        {'enabled': False, 'mode': 'enforcing'}
    """
    selinux_enabled = None
    selinux_mode = None

    try:
        from sh import sestatus
    except ImportError:
        return {'enabled': False}

    # Manually parse out the output for SELinux status
    for line in sestatus().stdout.split(b'\n'):
        row = line.split(b':')

        if row[0].startswith(b'SELinux status'):
            selinux_enabled = row[1].strip() == b'enabled'

        if row[0].startswith(b'Current mode'):
            selinux_mode = row[1].strip()

    return {'enabled': selinux_enabled, 'mode': selinux_mode}


TABLE = 'filter'
DROP_CHAIN = 'WOTT_LOG_DROP'
OUTPUT_CHAIN = 'OUTPUT'
INPUT_CHAIN = 'INPUT'
WOTT_COMMENT = {'comment': 'added by WoTT'}


def prepare_iptables():
    """
    Add a log-drop chain which will log a packet and drop it.

    :return: None
    """
    if not iptc_helper.has_chain(TABLE, DROP_CHAIN):
        iptc_helper.add_chain(TABLE, DROP_CHAIN)
        iptc_helper.add_rule(TABLE, DROP_CHAIN, {'target': {'LOG': {'log-prefix': 'DROP: ', 'log-level': '3'}}})
        iptc_helper.add_rule(TABLE, DROP_CHAIN, {'target': 'DROP'})


def update_iptables(table, chain, rules):
    """
    Insert new rules from the supplied list,
    remove those which are not supplied.

    :param table: table name
    :param chain: chain name
    :param rules: a list of rules in iptc.easy format
    :return: None
    """
    existing = iptc_helper.dump_chain(table, chain)
    for r in existing:
        if r.get('comment', None) == WOTT_COMMENT and r not in rules:
            iptc_helper.delete_rule(table, chain, r)
    for r in rules:
        if r not in existing:
            iptc_helper.add_rule(table, chain, r)


def block_ports(ports_data):
    """
    Block incoming TCP/UDP packets to the ports supplied in the list,
    unblock previously blocked.

    :param ports_data: dict of protocols/ports to be blocked
    :return: None
    """
    prepare_iptables()
    rules = [{
        'protocol': proto,
        proto: {'dport': str(port)},
        'dst': host,
        'target': DROP_CHAIN,
        'comment': WOTT_COMMENT
    } for host, proto, port in ports_data]
    update_iptables(TABLE, INPUT_CHAIN, rules)


def block_networks(network_list):
    """
    Block outgoing packets to the networks supplied in the list,
    unblock previously blocked.

    :param network_list: list of IPs in dot-notation or subnets (<IP>/<mask>)
    :return: None
    """
    prepare_iptables()
    rules = [{'dst': n,
              'target': DROP_CHAIN,
              'comment': WOTT_COMMENT}
             for n in network_list]
    update_iptables(TABLE, OUTPUT_CHAIN, rules)
