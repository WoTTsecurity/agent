import time
import enum
import typing
import collections

import systemd.journal

SYSLOG_AUTHPRIV = 10


def check(timespan=60 * 60):
    """
    Generator that yields AUTHPRIV messages from journald
    for the specified time span.

    :param timespan: Yield records only for this time span.
        Default is 1 hour.
    """
    journal = systemd.journal.Reader()
    journal.log_level(systemd.journal.LOG_INFO)
    journal.add_match(SYSLOG_FACILITY=SYSLOG_AUTHPRIV)
    journal.seek_realtime(time.time() - timespan)
    return auth_results(entry['MESSAGE'] for entry in journal)


class AuthResult(enum.Enum):
    SUCCESS = 1
    FAILURE = 2


def auth_results(records):
    """
    Check authentication results for the specified iterable of records.
    """
    results = collections.defaultdict(
        lambda: {'successful': 0, 'failed': 0},
    )
    for record in records:
        user, result = auth_result(record)
        if result is AuthResult.SUCCESS:
            results[user]['successful'] += 1
        elif result is AuthResult.FAILURE:
            results[user]['failed'] += 1
        else:
            continue
    return results


def auth_result(record) -> typing.Tuple[str, AuthResult]:
    """
    Parse authentication result from a single journal record.

    :returns: A tuple of (user, AuthResult.SUCCESS|AuthResult.FAILURE).
        Both can be None.
    """
    user = result = None
    if 'authentication failure' in record:
        # Possible records:
        # Mar 08 03:31:12 wott0 sshd[4698]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.x.y  # noqa
        # Jun 29 17:07:45 SVA1 sshd[15588]: PAM 1 more authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=pik.spbstu.ru user=vladik  # noqa
        _, rest = record.split('; ', 1)
        tags = dict(pair.split('=') for pair in rest.split(' '))
        user = tags.get('user', '')
        result = AuthResult.FAILURE
    elif 'session opened for user' in record:
        # Possible records:
        # Jun 21 06:47:01 debian-server CRON[13006]: pam_unix(cron:session): session opened for user root by (uid=0)
        user = record.rsplit(' ', 3)[-3]
        result = AuthResult.SUCCESS
    return user, result
