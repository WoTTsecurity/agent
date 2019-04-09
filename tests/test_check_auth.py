import pytest
from unittest.mock import patch

from agent.checks import auth


class TestAuthResult:

    def test_success(self):
        record = '# Jun 21 06:47:01 debian-server CRON[13006]: pam_unix(cron:session): session opened for user root by (uid=0)'  # noqa
        user, result = auth.auth_result(record)
        assert user == 'root'
        assert result is auth.AuthResult.SUCCESS


    def test_failures(self):
        record = 'Mar 08 03:31:12 wott0 sshd[4698]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.x.y'  # noqa
        user, result = auth.auth_result(record)
        assert user == ''
        assert result is auth.AuthResult.FAILURE

        record = 'Jun 29 17:07:45 SVA1 sshd[15588]: PAM 1 more authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=pik.spbstu.ru user=vladik'  # noqa
        user, result = auth.auth_result(record)
        assert user == 'vladik'
        assert result is auth.AuthResult.FAILURE


    def test_skip(self):
        record = 'Some garbage'
        user, result = auth.auth_result(record)
        assert user is result is None


class TestAuthResults:

    def test_empty_journal(self):
        results = auth.auth_results([])
        assert results == {}

    def test_one_entry(self):
        results = auth.auth_results([
            '# Jun 21 06:47:01 debian-server CRON[13006]: pam_unix(cron:session): session opened for user ubuntu by (uid=0)',  # noqa
        ])
        assert results == {'ubuntu': {'successful': 1, 'failed': 0}}

        results = auth.auth_results([
            'Mar 08 03:31:12 wott0 sshd[4698]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.x.y',  # noqa
        ])
        assert results == {'': {'successful': 0, 'failed': 1}}

    def test_multiple_entries(self):
        results = auth.auth_results([
            '# Jun 21 06:47:01 debian-server CRON[13006]: pam_unix(cron:session): session opened for user ubuntu by (uid=0)',  # noqa
            'Mar 08 03:31:12 wott0 sshd[4698]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.x.y user=ubuntu',  # noqa
            'Mar 08 03:31:12 wott0 sshd[4698]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.x.y user=root',  # noqa
            'Some garbage',
            'Mar 08 03:31:12 wott0 sshd[4698]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.x.y user=root',  # noqa
        ])
        assert results == {'root': {'successful': 0, 'failed': 2},
                           'ubuntu': {'successful': 1, 'failed': 1}}
