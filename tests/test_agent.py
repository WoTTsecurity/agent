import datetime
import json
from unittest import mock
from pathlib import Path
import pytest
import freezegun
import agent
from agent.journal_helper import logins_last_hour
from agent.rpi_helper import detect_raspberry_pi
from agent.security_helper import nmap_scan, is_firewall_enabled, \
    block_networks, WOTT_COMMENT


def test_detect_raspberry_pi(raspberry_cpuinfo):
    with mock.patch(
            'builtins.open',
            mock.mock_open(read_data=raspberry_cpuinfo),
            create=True
    ):
        metadata = detect_raspberry_pi()
        assert metadata['is_raspberry_pi']
        assert metadata['hardware_model'] == '900092'
        assert metadata['serial_number'] == '00000000ebd5f1e8'


def test_failed_logins():
    with mock.patch('agent.journal_helper.get_journal_records') as gjr:
        gjr.return_value = [
        ]
        result = logins_last_hour()
        assert result == {}

    with mock.patch('agent.journal_helper.get_journal_records') as gjr:
        gjr.return_value = [
            {'MESSAGE': 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.147.17.225'}
        ]
        result = logins_last_hour()
        assert result == {'': {'success': 0, 'failed': 1}}

    with mock.patch('agent.journal_helper.get_journal_records') as gjr:
        gjr.return_value = [
            {'MESSAGE': 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.147.17.225  user=pi'}
        ]
        result = logins_last_hour()
        assert result == {'pi': {'success': 0, 'failed': 1}}

    with mock.patch('agent.journal_helper.get_journal_records') as gjr:
        gjr.return_value = [
            {'MESSAGE': 'PAM 2 more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.147.17.225  user=pi'},
            {'MESSAGE': 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.147.17.225  user=pi'},
            {'MESSAGE': 'PAM 1 more authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.147.17.225  user=pi'},
            {'MESSAGE': 'pam_unix(sshd:session): session opened for user pi by (uid=0)'},
            {'MESSAGE': 'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=10.147.17.225'}
        ]
        result = logins_last_hour()
        assert result == {
            'pi': {'success': 1, 'failed': 4},
            '': {'success': 0, 'failed': 1}}

    with mock.patch('agent.journal_helper.get_journal_records') as gjr:
        gjr.return_value = [
            {'MESSAGE': 'pam_unix(sshd:auth): some other message'},
            {'MESSAGE': 'something unrelated'},
            {'MESSAGE': 'PAM and something unrelated'},
        ]
        result = logins_last_hour()
        assert result == {}


def test_nmap_scan(nmap_fixture):
    with mock.patch('agent.security_helper.nmap') as nmap:
        nmap.return_value.stdout = nmap_fixture
        result = nmap_scan('localhost')
        assert len(result) == 4  # TODO: test keys/values


def test_is_bootstrapping_stat_file(tmpdir):
    agent.CERT_PATH = str(tmpdir)
    with mock.patch('builtins.print') as prn:
        assert agent.is_bootstrapping()
        assert mock.call('No certificate found on disk.') in prn.mock_calls


def test_is_bootstrapping_create_dir(tmpdir):
    notexistent_dir = str(tmpdir / 'notexistent')
    agent.CERT_PATH = notexistent_dir
    with mock.patch('os.makedirs') as md, \
            mock.patch('os.chmod') as chm, \
            mock.patch('builtins.print') as prn:
        assert agent.is_bootstrapping()
        assert md.called_with(notexistent_dir)
        assert chm.called_with(notexistent_dir, 0o700)
        assert mock.call('No certificate found on disk.') in prn.mock_calls


def test_is_bootstrapping_check_filesize(tmpdir):
    crt = tmpdir / 'client.crt'
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(crt)
    with mock.patch('builtins.print') as prn:
        Path(crt).touch()
        assert agent.is_bootstrapping()
        assert mock.call('Certificate found but it is broken') in prn.mock_calls


def test_is_bootstrapping_false_on_valid_cert(tmpdir):
    crt = tmpdir / 'client.crt'
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(crt)
    with mock.patch('builtins.print') as prn:
        Path(crt).write_text('nonzero')
        assert not agent.is_bootstrapping()
        assert not prn.mock_calls


def test_can_read_cert_stat_cert(tmpdir):
    crt = tmpdir / 'client.crt'
    key = tmpdir / 'client.key'
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(crt)
    agent.CLIENT_KEY_PATH = str(key)
    with mock.patch('builtins.print') as prn:
        Path(crt).touch(mode=0o100)
        with pytest.raises(SystemExit):
            agent.can_read_cert()
        assert mock.call('Permission denied when trying to read the certificate file.') in prn.mock_calls


def test_can_read_cert_stat_key(tmpdir):
    crt = tmpdir / 'client.crt'
    key = tmpdir / 'client.key'
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(crt)
    agent.CLIENT_KEY_PATH = str(key)
    with mock.patch('builtins.print') as prn:
        Path(crt).touch(mode=0o600)
        Path(key).touch(mode=0o100)
        with pytest.raises(SystemExit):
            agent.can_read_cert()
        assert mock.call('Permission denied when trying to read the key file.') in prn.mock_calls


def test_can_read_cert_none_on_success(tmpdir):
    crt = tmpdir / 'client.crt'
    key = tmpdir / 'client.key'
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(crt)
    agent.CLIENT_KEY_PATH = str(key)
    with mock.patch('builtins.print'):
        Path(crt).touch(mode=0o600)
        Path(key).touch(mode=0o600)
        can_read = agent.can_read_cert()
        assert can_read is None


def test_get_primary_ip(netif_gateways, netif_ifaddresses):
    with mock.patch('netifaces.gateways') as gw, \
            mock.patch('netifaces.ifaddresses') as ifaddr:
        gw.return_value = netif_gateways
        ifaddr.return_value = netif_ifaddresses
        primary_ip = agent.get_primary_ip()
        assert primary_ip == '192.168.1.3'


def test_get_primary_ip_none_on_exception(netif_gateways_invalid, netif_ifaddresses):
    with mock.patch('netifaces.gateways') as gw, \
            mock.patch('netifaces.ifaddresses') as ifaddr:
        gw.return_value = netif_gateways_invalid
        ifaddr.return_value = netif_ifaddresses
        primary_ip = agent.get_primary_ip()
        assert primary_ip is None


def test_get_certificate_expiration_date(cert):
    with mock.patch(
            'builtins.open',
            mock.mock_open(read_data=cert),
            create=True
    ):
        exp_date = agent.get_certificate_expiration_date()
        assert exp_date.date() == datetime.date(2019, 3, 19)


@freezegun.freeze_time("2019-04-04")
def test_time_for_certificate_renewal(cert):
    with mock.patch(
            'builtins.open',
            mock.mock_open(read_data=cert),
            create=True
    ):
        assert agent.time_for_certificate_renewal()


@freezegun.freeze_time("2019-04-14")
def test_cert_expired(cert):
    with mock.patch(
            'builtins.open',
            mock.mock_open(read_data=cert),
            create=True
    ):
        assert agent.is_certificate_expired()


@pytest.mark.vcr
def test_generate_device_id():
    dev_id = agent.generate_device_id()
    assert dev_id


def test_get_device_id(cert):
    with mock.patch(
            'builtins.open',
            mock.mock_open(read_data=cert),
            create=True
    ):
        device_id = agent.get_device_id()
        assert device_id == '4853b630822946019393b16c5b710b9e.d.wott.local'


def test_generate_cert():  # TODO: parse key and csr
    cert = agent.generate_cert('4853b630822946019393b16c5b710b9e.d.wott.local')
    assert cert['key']
    assert cert['csr']


@pytest.mark.vcr
def test_get_ca_cert():
    ca_bundle = agent.get_ca_cert()
    assert "BEGIN CERTIFICATE" in ca_bundle


def test_get_ca_cert_none_on_fail():
    with mock.patch('requests.get') as req, \
            mock.patch('builtins.print') as prn:
        req.return_value.ok = False
        ca_bundle = agent.get_ca_cert()
    assert ca_bundle is None
    assert mock.call('Failed to get CA...') in prn.mock_calls
    assert prn.call_count == 3


def test_get_open_ports(nmap_fixture, netif_gateways, netif_ifaddresses):
    with mock.patch('agent.security_helper.nmap') as nmap, \
            mock.patch('netifaces.gateways') as gw, \
            mock.patch('netifaces.ifaddresses') as ifaddr:
        nmap.return_value.stdout = nmap_fixture
        gw.return_value = netif_gateways
        ifaddr.return_value = netif_ifaddresses
        result = agent.get_open_ports()
        assert len(result) == 4  # TODO: test keys/values


@pytest.mark.vcr
def test_send_ping(raspberry_cpuinfo, uptime, tmpdir, cert, key, nmap_stdout):
    crt_path = tmpdir / 'client.crt'
    key_path = tmpdir / 'client.key'
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(crt_path)
    agent.CLIENT_KEY_PATH = str(key_path)
    Path(agent.CLIENT_CERT_PATH).write_text(cert)
    Path(agent.CLIENT_KEY_PATH).write_text(key)
    with mock.patch(
            'builtins.open',
            mock.mock_open(read_data=raspberry_cpuinfo),
            create=True
    ), \
    mock.patch('socket.getfqdn') as getfqdn, \
    mock.patch('agent.security_helper.nmap_scan') as nm, \
    mock.patch('agent.security_helper.is_firewall_enabled') as fw, \
    mock.patch('agent.security_helper.get_firewall_rules') as fr, \
    mock.patch('agent.security_helper.process_scan') as ps, \
    mock.patch('agent.security_helper.block_ports') as bp, \
    mock.patch('agent.security_helper.block_networks') as bn, \
    mock.patch('builtins.print') as prn, \
    mock.patch(
        'builtins.open',
        mock.mock_open(read_data=uptime),
        create=True
    ):  # noqa E213
        nm.return_value = []
        fw.return_value = False
        fr.return_value = {}
        ps.return_value = []
        getfqdn.return_value = 'localhost'
        bp.return_value = None
        bn.return_value = None
        ping = agent.send_ping()
        assert ping is None
        assert prn.call_count == 0 or (prn.call_count == 1 and mock.call('Ping failed.') in prn.mock_calls)


@pytest.mark.vcr
def test_renew_cert(raspberry_cpuinfo, tmpdir, cert, key):
    crt_path = tmpdir / 'client.crt'
    key_path = tmpdir / 'client.key'
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(crt_path)
    agent.CLIENT_KEY_PATH = str(key_path)
    Path(agent.CLIENT_CERT_PATH).write_text(cert)
    Path(agent.CLIENT_KEY_PATH).write_text(key)
    with mock.patch(
            'builtins.open',
            mock.mock_open(read_data=raspberry_cpuinfo),
            create=True
    ), \
    mock.patch('socket.getfqdn') as getfqdn, \
    mock.patch('builtins.print') as prn:  # noqa E213
        getfqdn.return_value = 'localhost'
        res = agent.renew_expired_cert(None, None)
        assert res is None
        assert (prn.call_count == 2 and mock.call('Failed to submit CSR...') in prn.mock_calls)


@pytest.mark.vcr
def test_say_hello_failed(tmpdir, invalid_cert, invalid_key):
    crt_path = tmpdir / 'client.crt'
    key_path = tmpdir / 'client.key'
    Path(crt_path).write_text(invalid_cert)
    Path(key_path).write_text(invalid_key)
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(crt_path)
    agent.CLIENT_KEY_PATH = str(key_path)
    with mock.patch('builtins.print') as prn:
        with pytest.raises(json.decoder.JSONDecodeError):
            _ = agent.say_hello()
        assert mock.call('Hello failed.') in prn.mock_calls


@pytest.mark.vcr
def test_say_hello_ok(tmpdir, cert, key):
    crt_path = tmpdir / 'client.crt'
    key_path = tmpdir / 'client.key'
    Path(crt_path).write_text(cert)
    Path(key_path).write_text(key)
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(crt_path)
    agent.CLIENT_KEY_PATH = str(key_path)
    hello = agent.say_hello()
    assert hello['message']


def test_uptime(uptime):
    with mock.patch(
            'builtins.open',
            mock.mock_open(read_data=uptime),
            create=True
    ):
        up = agent.get_uptime()
        assert up == 60


def test_firewall_enabled_pos():
    with mock.patch('iptc.Table') as iptcTable, \
            mock.patch('iptc.Chain') as iptcChain:
        iptcTable.return_value = None
        chain0 = mock.Mock()
        chain0.name = 'INPUT'
        chain0.rules = [object()]
        iptcChain.return_value = chain0
        assert is_firewall_enabled() is True


def test_firewall_enabled_neg():
    with mock.patch('iptc.Table') as iptcTable, \
            mock.patch('iptc.Chain') as iptcChain:
        iptcTable.return_value = None
        chain0 = mock.Mock()
        chain0.name = 'INPUT'
        chain0.rules = []
        iptcChain.return_value = chain0
        assert is_firewall_enabled() is False


def test_blocking():
    with mock.patch('iptc.easy.dump_chain') as dump_chain,\
            mock.patch('iptc.easy.add_rule') as add_rule:
        dump_chain.return_value = ([])
        block_networks(['10.10.10.10'])
        assert add_rule.has_calls([
            mock.call({'dst': '10.10.10.10', 'target': WOTT_COMMENT, 'comment': WOTT_COMMENT})
        ])

    with mock.patch('iptc.easy.dump_chain') as dump_chain,\
            mock.patch('iptc.easy.add_rule') as add_rule:
        dump_chain.return_value = ([
            {'dst': '10.10.10.10', 'target': WOTT_COMMENT, 'comment': WOTT_COMMENT}
        ])
        block_networks(['10.10.10.10'])
        assert add_rule.has_calls([
            mock.call({'dst': '10.10.10.10', 'target': WOTT_COMMENT, 'comment': WOTT_COMMENT})
        ])

    with mock.patch('iptc.easy.dump_chain') as dump_chain, \
            mock.patch('iptc.easy.delete_rule') as delete_rule:
        dump_chain.return_value = ([
            {'dst': '10.10.10.10', 'target': WOTT_COMMENT, 'comment': WOTT_COMMENT}
        ])
        block_networks([])
        assert delete_rule.has_calls([
            mock.call({'dst': '10.10.10.10', 'target': WOTT_COMMENT, 'comment': WOTT_COMMENT})
        ])
