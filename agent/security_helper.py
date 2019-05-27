import socket
from pathlib import Path
from socket import SocketKind
import spwd
from typing import List, Tuple

import iptc
import psutil

from . import iptc_helper


def check_for_default_passwords(config_path):
    """
    Check if the 'pi' user current password hash is in our list of default password hashes.
    """
    base_dir = Path(config_path)
    pass_hashes_file_path = base_dir.joinpath('pass_hashes.txt')  # For deb installation.
    if not pass_hashes_file_path.is_file():
        base_dir = Path(__file__).resolve().parent.parent
        pass_hashes_file_path = base_dir.joinpath('misc/pass_hashes.txt')
    with pass_hashes_file_path.open() as f:
        read_data = f.read()
    hashes = read_data.splitlines()
    try:
        hash = spwd.getspnam('pi').sp_pwdp
    except KeyError:
        pass
    else:
        if hash in hashes:
            return True
    return False


def is_firewall_enabled():
    """Check if FILTER INPUT chain contains any rule"""
    chain = iptc_helper.dump_chain('filter', 'INPUT')
    return len(chain) > 0 if chain else False


def get_firewall_rules():
    """Get all FILTER table rules"""
    table = iptc_helper.dump_table('filter').items()
    return {chain_name: [rule for rule in chain
                         if chain_name != 'OUTPUT' or rule.get('comment') != {'comment': WOTT_COMMENT}]
            for chain_name, chain in table}


def netstat_scan():
    """
    Returns all open inet connections with their addresses and PIDs.
    """
    connections = psutil.net_connections(kind='inet')
    return (
        [{
            'ip_version': 4 if c.family == socket.AF_INET else 6,
            'type': 'udp' if c.type == socket.SOCK_DGRAM else 'tcp',
            'local_address': c.laddr,
            'remote_address': c.raddr,
            'status': c.status if c.type == socket.SOCK_STREAM else None,
            'pid': c.pid
        } for c in connections if c.raddr],
        [{
            'ip_version': 4 if c.family == socket.AF_INET else 6,
            'host': c.laddr[0],
            'port': c.laddr[1],
            'proto': {SocketKind.SOCK_STREAM: 'tcp', SocketKind.SOCK_DGRAM: 'udp'}.get(c.type),
            'state': c.status if c.type == socket.SOCK_STREAM else None,
        } for c in connections if not c.raddr and c.laddr]
    )


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
WOTT_COMMENT = 'Added by WoTT'


def prepare_iptables(ipv6: bool):
    """
    Add a log-drop chain which will log a packet and drop it.

    :return: None
    """
    if not iptc_helper.has_chain(TABLE, DROP_CHAIN, ipv6=ipv6):
        iptc_helper.add_chain(TABLE, DROP_CHAIN, ipv6=ipv6)
        iptc_helper.add_rule(TABLE, DROP_CHAIN, {'target': {'LOG': {'log-prefix': 'DROP: ', 'log-level': '3'}}}, ipv6=ipv6)
        iptc_helper.add_rule(TABLE, DROP_CHAIN, {'target': 'DROP'}, ipv6=ipv6)


def update_iptables(table, chain, rules):
    """
    Delete all rules marked by WOTT_COMMENT.
    Then insert new rules from the supplied list.

    :param table: table name
    :param chain: chain name
    :param rules: a list of rules in iptc.easy format
    :return: None
    """
    iptc_helper.batch_begin(table, ipv6=False)
    iptc_helper.batch_begin(table, ipv6=True)

    tbl4 = iptc.Table(table)
    ch4 = iptc.Chain(tbl4, chain)
    tbl6 = iptc.Table6(table)
    ch6 = iptc.Chain(tbl6, chain)

    for ch in (ch4, ch6):
        for r in ch.rules:
            for m in r.matches:
                if m.comment == WOTT_COMMENT:
                    ch.delete_rule(r)
                    break

    for r, ipv6 in rules:
        iptc_helper.add_rule(table, chain, r, ipv6=ipv6)

    iptc_helper.batch_end(table, ipv6=True)
    iptc_helper.batch_end(table, ipv6=False)


def block_ports(ports_data: List[Tuple[str, str, int, bool]]):
    """
    Block incoming TCP/UDP packets to the ports supplied in the list,
    unblock previously blocked.

    :param ports_data: dict of protocols/ports to be blocked
    :return: None
    """
    prepare_iptables(False)
    prepare_iptables(True)
    rules = [({'protocol': proto,
               proto: {'dport': str(port)},
               'dst': host,
               'target': DROP_CHAIN,
               'comment': WOTT_COMMENT
               }, ipv6)
             for host, proto, port, ipv6 in ports_data]
    update_iptables(TABLE, INPUT_CHAIN, rules)


def block_networks(network_list: List[Tuple[str, bool]]):
    """
    Block outgoing packets to the networks supplied in the list,
    unblock previously blocked.

    :param network_list: list of IPs in dot-notation or subnets (<IP>/<mask>)
    :return: None
    """
    prepare_iptables(False)
    prepare_iptables(True)
    rules = [({'dst': n,
               'target': DROP_CHAIN,
               'comment': WOTT_COMMENT
               }, ipv6)
             for n, ipv6 in network_list]
    update_iptables(TABLE, OUTPUT_CHAIN, rules)
