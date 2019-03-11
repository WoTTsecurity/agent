from unittest import mock
import iptc
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


def test_firewall_enabled_pos():
    with mock.patch('iptc.Table') as ipt:
        chain0 = mock.Mock()
        chain0.name = 'INPUT'
        chain0.rules = [object(), object()]
        ipt.return_value = [chain0]
        assert is_firewall_enabled() is True


def test_firewall_enabled_neg():
    with mock.patch('iptc.Table') as ipt:
        chain0 = mock.Mock()
        chain0.name = 'INPUT'
        chain0.rules = []
        ipt.return_value = [chain0]
        assert is_firewall_enabled() is False


def is_firewall_enabled():
    """Check if FILTER INPUT chain contains any rule"""
    filter_table = iptc.Table(iptc.Table.FILTER)
    input_chain = next(filter(lambda c: c.name == 'INPUT', filter_table))
    return not len(input_chain.rules) == 0
