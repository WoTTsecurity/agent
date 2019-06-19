import asyncio
import datetime
import json
from unittest import mock
from pathlib import Path
import time

import pytest
import freezegun

import agent
from agent.journal_helper import logins_last_hour
from agent.rpi_helper import detect_raspberry_pi
from agent.security_helper import is_firewall_enabled, block_networks, update_iptables, WOTT_COMMENT, block_ports
from agent.security_helper import check_for_default_passwords
from agent import executor


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


def test_is_bootstrapping_stat_file(tmpdir):
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(tmpdir / 'client.crt')
    with mock.patch('builtins.print') as prn:
        assert agent.is_bootstrapping()
        assert mock.call('No certificate found on disk.') in prn.mock_calls


def test_is_bootstrapping_create_dir(tmpdir):
    notexistent_dir = tmpdir / 'notexistent'
    agent.CERT_PATH = str(notexistent_dir)
    agent.CLIENT_CERT_PATH = str(notexistent_dir / 'client.crt')
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
        Path(agent.CLIENT_CERT_PATH).touch()
        assert agent.is_bootstrapping()
        assert mock.call('Certificate found but it is broken') in prn.mock_calls


def test_is_bootstrapping_false_on_valid_cert(tmpdir):
    crt = tmpdir / 'client.crt'
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(crt)
    with mock.patch('builtins.print') as prn:
        Path(agent.CLIENT_CERT_PATH).write_text('nonzero')
        assert not agent.is_bootstrapping()
        assert not prn.mock_calls


def test_can_read_cert_stat_cert(tmpdir):
    crt = tmpdir / 'client.crt'
    key = tmpdir / 'client.key'
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(crt)
    agent.CLIENT_KEY_PATH = str(key)
    with mock.patch('builtins.print') as prn:
        # Path(crt).touch(mode=0o100)
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
        Path(agent.CLIENT_CERT_PATH).touch(mode=0o600)
        # Path(agent.CLIENT_KEY_PATH).touch(mode=0o100)
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
        Path(agent.CLIENT_CERT_PATH).touch(mode=0o600)
        Path(agent.CLIENT_KEY_PATH).touch(mode=0o600)
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
    ), mock.patch('agent.can_read_cert') as cr:
        cr.return_value = True
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
    ), mock.patch('agent.can_read_cert') as cr:
        cr.return_value = True
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


def test_get_open_ports(net_connections_fixture, netstat_result):
    with mock.patch('psutil.net_connections') as net_connections:
        net_connections.return_value = net_connections_fixture
        connections_ports = agent.get_open_ports()
        assert connections_ports == [netstat_result[1]]


@pytest.mark.vcr
def test_send_ping(raspberry_cpuinfo, uptime, tmpdir, cert, key, net_connections_fixture):
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
    mock.patch('psutil.net_connections') as net_connections, \
    mock.patch('agent.security_helper.is_firewall_enabled') as fw, \
    mock.patch('agent.security_helper.get_firewall_rules') as fr, \
    mock.patch('agent.security_helper.check_for_default_passwords') as chdf, \
    mock.patch('agent.security_helper.process_scan') as ps, \
    mock.patch('agent.security_helper.block_ports') as bp, \
    mock.patch('agent.security_helper.block_networks') as bn, \
    mock.patch('agent.journal_helper.logins_last_hour') as logins, \
    mock.patch('builtins.print') as prn, \
    mock.patch(
        'builtins.open',
        mock.mock_open(read_data=uptime),
        create=True
    ):  # noqa E213
        net_connections.return_value = net_connections_fixture[0],
        fw.return_value = False
        fr.return_value = {}
        chdf.return_value = False
        ps.return_value = []
        getfqdn.return_value = 'localhost'
        bp.return_value = None
        bn.return_value = None
        logins.return_value = {}
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
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(crt_path)
    agent.CLIENT_KEY_PATH = str(key_path)
    Path(agent.CLIENT_CERT_PATH).write_text(invalid_cert)
    Path(agent.CLIENT_KEY_PATH).write_text(invalid_key)
    with mock.patch('builtins.print') as prn:
        with pytest.raises(json.decoder.JSONDecodeError):
            _ = agent.say_hello()
        assert mock.call('Hello failed.') in prn.mock_calls


@pytest.mark.vcr
def test_say_hello_ok(tmpdir, cert, key):
    crt_path = tmpdir / 'client.crt'
    key_path = tmpdir / 'client.key'
    agent.CERT_PATH = str(tmpdir)
    agent.CLIENT_CERT_PATH = str(crt_path)
    agent.CLIENT_KEY_PATH = str(key_path)
    Path(agent.CLIENT_CERT_PATH).write_text(cert)
    Path(agent.CLIENT_KEY_PATH).write_text(key)
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
    with mock.patch('agent.iptc_helper.get_policy') as get_policy:
        get_policy.return_value = 'DROP'
        assert is_firewall_enabled() is True


def test_firewall_enabled_neg():
    with mock.patch('agent.iptc_helper.get_policy') as get_policy:
        get_policy.return_value = 'ACCEPT'
        assert is_firewall_enabled() is False


def test_check_for_default_passwords_pos():
    with mock.patch('pathlib.Path.open', mock.mock_open(read_data='pi:raspberry')),\
            mock.patch('spwd.getspall') as getspnam:
        # this is a real shadow record for password "raspberry"
        getspnam.return_value = [
            mock.Mock(
                sp_pwdp='$6$2tSrLNr4$XblkH.twWBJB.6zxbtyDM4z3Db55SOqdi3MBYPwNXF1Kv5FCGS6jCDdVNsr50kctHZk/W0u2AtyomcQ16EVZQ/',
                sp_namp='pi'
            )
        ]
        assert check_for_default_passwords('/doesntmatter/file.txt')


def test_check_for_default_passwords_neg():
    with mock.patch('pathlib.Path.open', mock.mock_open(read_data='pi:raspberry')),\
            mock.patch('spwd.getspall') as getspnam:
        # this is a real shadow record for password which is not "raspberry"
        getspnam.return_value = [
            mock.Mock(
                sp_pwdp='$6$/3W/.H6/$nncROMeVQxTEKRcjCfOwft08WPJm.JLnrlli0mutPZ737kImtHhcROgrYz7k6osr0XwuPDlwRfY.r584iQ425/',
                sp_namp='pi'
            )
        ]
        assert not check_for_default_passwords('/doesntmatter/file.txt')


def test_block_networks(ipt_networks, ipt_rules):
    rule1, rule2 = ipt_rules
    net1, net2 = ipt_networks

    # Initial state: no networks are blocked
    # Input: two networks (net1, net2)
    # Result: net1 and net2 are blocked
    with mock.patch('agent.iptc_helper.has_chain') as has_chain,\
            mock.patch('agent.iptc_helper.add_rule') as add_rule, \
            mock.patch('iptc.Table'), \
            mock.patch('iptc.Table6'), \
            mock.patch('iptc.Chain'):
        has_chain.return_value = True

        block_networks([net1, net2])
        add_rule.assert_has_calls([
            mock.call('filter', 'OUTPUT', rule1, ipv6=False),
            mock.call('filter', 'OUTPUT', rule2, ipv6=False)
        ])

    # Initial state: net1 is blocked
    # Input: another network: net2
    # Result: net2 gets blocked, net1 gets unblocked
    with mock.patch('agent.iptc_helper.has_chain') as has_chain, \
            mock.patch('agent.iptc_helper.add_rule') as add_rule, \
            mock.patch('iptc.Table'), \
            mock.patch('iptc.Table6'), \
            mock.patch('iptc.Chain'):
        has_chain.return_value = True

        block_networks([net2])
        add_rule.assert_has_calls([
            mock.call('filter', 'OUTPUT', rule2, ipv6=False)
        ])

    # Initial state: empty
    # Input: empty
    # Result: nothing happens
    with mock.patch('agent.iptc_helper.has_chain') as has_chain, \
            mock.patch('agent.iptc_helper.add_rule') as add_rule, \
            mock.patch('iptc.Table'), \
            mock.patch('iptc.Table6'), \
            mock.patch('iptc.Chain'):
        has_chain.return_value = True

        block_networks([])
        add_rule.assert_not_called()


def test_block_ports(ipt_ports, ipt_ports_rules):
    with mock.patch('agent.iptc_helper.has_chain') as has_chain, \
            mock.patch('agent.iptc_helper.add_rule') as add_rule, \
            mock.patch('iptc.Table'), \
            mock.patch('iptc.Table6'), \
            mock.patch('iptc.Chain'):
        has_chain.return_value = True

        block_ports(ipt_ports)
        add_rule.assert_has_calls([
            mock.call('filter', 'INPUT', r, ipv6=ipv6)
            for r, ipv6 in ipt_ports_rules
        ])


def test_delete_rules():
    with mock.patch('agent.iptc_helper.has_chain') as has_chain, \
            mock.patch('agent.iptc_helper.batch_begin'), \
            mock.patch('agent.iptc_helper.batch_end'), \
            mock.patch('iptc.Table'), \
            mock.patch('iptc.Table6'), \
            mock.patch('iptc.Chain') as iptcChain:
        has_chain.return_value = True

        # Initial state: one rule (r) marked by WOTT_COMMENT, another rule (r0) unmarked
        # Input: empty
        # Result: the marked rule (r) gets deleted, unmarked one (r0) stays
        r = mock.Mock()
        r0 = mock.Mock()
        m = mock.Mock()
        ch = mock.Mock()
        m.comment = WOTT_COMMENT
        r.matches = [m]
        r0.matches = [mock.Mock()]
        ch.rules = [r, r0]
        iptcChain.return_value = ch

        update_iptables('filter', 'INPUT', [])

        ch.delete_rule.assert_called_with(r)


def test_fetch_credentials(tmpdir):
    executor.Locker.LOCKDIR = str(tmpdir)
    agent.CREDENTIALS_PATH = str(tmpdir)
    json3_path_str = str(tmpdir / 'name3.json')
    json3_path = Path(json3_path_str)
    json3_path.write_text('nonzero')

    mock_resp = mock.Mock()
    mock_resp.raise_status = 200
    mock_resp.json = mock.Mock(
        return_value=[
            {'name': 'name1', 'key': 'key1', 'value': 'v1'},
            {'name': 'name2', 'key': 'key1', 'value': 'v21'},
            {'name': 'name2', 'key': 'key2', 'value': 'v22'},
        ]
    )
    mock_resp.return_value.ok = True
    with mock.patch('builtins.print'), \
            mock.patch('agent.can_read_cert') as cr, \
            mock.patch('requests.get') as req, \
            mock.patch('builtins.print'):

        cr.return_value = True
        req.return_value = mock_resp
        mock_resp.return_value.ok = True
        agent.fetch_credentials(False, False)

        assert Path.exists(tmpdir / 'name1.json')
        assert Path.exists(tmpdir / 'name2.json')
        assert Path.exists(json3_path) is False
        with open(str(tmpdir / 'name1.json')) as f:
            assert json.load(f) == {"key1": "v1"}

        with open(str(tmpdir / 'name2.json')) as f:
            assert json.load(f) == {"key1": "v21", "key2": "v22"}


def test_fetch_credentials_no_dir(tmpdir):
    executor.Locker.LOCKDIR = str(tmpdir)
    agent.CREDENTIALS_PATH = str(tmpdir / 'notexist')
    file_path1 = tmpdir / 'notexist' / 'name1.json'
    file_path2 = tmpdir / 'notexist' / 'name2.json'

    mock_resp = mock.Mock()
    mock_resp.raise_status = 200
    mock_resp.json = mock.Mock(
        return_value=[
            {'name': 'name1', 'key': 'key1', 'value': 'v1'},
            {'name': 'name2', 'key': 'key1', 'value': 'v21'}
        ]
    )
    mock_resp.return_value.ok = True
    with mock.patch('builtins.print'), \
            mock.patch('agent.can_read_cert') as cr, \
            mock.patch('requests.get') as req, \
            mock.patch('builtins.print'):

        cr.return_value = True
        req.return_value = mock_resp
        mock_resp.return_value.ok = True
        agent.fetch_credentials(False, False)

        assert Path.exists(file_path1)
        assert Path.exists(file_path2)
        with open(str(file_path1)) as f:
            assert json.load(f) == {"key1": "v1"}

        with open(str(file_path2)) as f:
            assert json.load(f) == {"key1": "v21"}


def _is_parallel(tmpdir, use_lock: bool, use_pairs: bool = False):
    """
    Execute two "sleepers" at once.
    :param tmpdir: temp directory where logs and locks will be stored (provided by pytest)
    :param use_lock: use executor.Locker to execute exclusively
    :return: whether the two tasks were seen executing in parallel (boolean value)
    """
    def _work(f: Path):
        """The actual workload: sleep and write before/after timestamps to provided file"""
        of = f.open('a+')
        of.write('{} '.format(time.time()))
        time.sleep(0.1)
        of.write('{}\n'.format(time.time()))

    def sleeper(lock: bool, f: Path, lockname: str):
        """This task will be executed by executor."""
        executor.Locker.LOCKDIR = str(tmpdir)  # can't use /var/lock in CircleCI environment
        if lock:
            with executor.Locker(lockname):
                _work(f)
        else:
            _work(f)

    def stop_exe():
        """Stop execution of tasks launched by executor."""
        for fut in futs:
            fut.cancel()
        for exe in exes:
            exe.stop()
        asyncio.get_event_loop().stop()

    def find_parallel(first_pairs, second_pairs):
        parallel = False
        for begin1, end1 in first_pairs:
            # Find a pair in second_pairs overlapping with first_pair.
            # That means execution was overlapped (parallel).
            for begin2, end2 in second_pairs:
                if begin2 <= begin1 <= end2 or begin2 <= end1 <= end2:
                    parallel = True
                    break
            if parallel:
                break
        return parallel

    def is_parallel(timestamp_files):
        # Parse timestamp files. Split them into (begin, end) tuples.
        file_time_pairs = []
        for f in timestamp_files:
            of = f.open('r')
            times = []
            for line in of.read().splitlines():
                begin, end = line.split()
                times.append((float(begin), float(end)))
            file_time_pairs.append(times)

        first_pairs, second_pairs = file_time_pairs
        return find_parallel(first_pairs, second_pairs) or find_parallel(second_pairs, first_pairs)

    # Schedule two identical tasks to executor. They will write before/after timestamps
    # to their files every 100 ms.
    test_files = [tmpdir / 'test_locker_' + str(i) for i in range(2)]
    exes = [executor.Executor(0.1, sleeper, (use_lock, test_file, 'one')) for test_file in test_files]

    # If testing independent locking, schedule another couple of tasks with another lock and another
    # set of timestamp files.
    if use_pairs:
        test_files_2 = [tmpdir / 'test_locker_2_' + str(i) for i in range(2)]
        exes += [executor.Executor(0.1, sleeper, (use_lock, test_file, 'two')) for test_file in test_files_2]

    futs = [executor.schedule(exe) for exe in exes]

    # Stop this after 3 seconds
    asyncio.get_event_loop().call_later(3, stop_exe)
    executor.spin()
    if use_lock:
        # When using Locker the tasks need some additional time to stop.
        time.sleep(3)

    if use_pairs:
        # If testing independent locking, find out:
        # - whether first couple of tasks were executed in parallel
        # - whether second couple of tasks were executed in parallel
        # - whether tasks from both couples were executed in parallel
        return is_parallel(test_files), \
            is_parallel(test_files_2), \
            is_parallel((test_files[0], test_files_2[0]))
    else:
        return is_parallel(test_files)


def test_locker(tmpdir):
    assert not _is_parallel(tmpdir, True)


def test_no_locker(tmpdir):
    assert _is_parallel(tmpdir, False)


def test_independent_lockers(tmpdir):
    one, two, both = _is_parallel(tmpdir, True, True)
    assert (one, two, both) == (False, False, True)
