from systemd import journal
import time


def get_journal_records():
    '''
    Get syslog records as returned by
        journalctl -l SYSLOG_FACILITY=10 --priority=5 --since "1 hour ago"
    '''
    j = journal.Reader()
    j.this_boot()
    j.log_level(journal.LOG_INFO)
    last_hour = time.time() - 60**2
    j.seek_realtime(last_hour)
    j.add_match(SYSLOG_FACILITY=10)
    return j


def logins(entries):
    '''
    Returns the number of failed or successful login attempts per user as
        {'<user>': {'success': <N>, 'failed': '<N>'}, ...}

    Failed attempts are logged in the system journal like this:
        pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=<ip>  user=<user>
        PAM 1 more authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=<ip>  user=<user>
        PAM <n> more authentication failures; logname= uid=0 euid=0 tty=ssh ruser= rhost=<ip>  user=<user>
    Successful attempts are logged like this:
        pam_unix(sshd:session): session opened for user pi by (uid=0)
    '''
    MSG_AUTH_FAIL = 'pam_unix(sshd:auth): authentication failure;'
    MSG_SESSION_OPENED = 'pam_unix(sshd:session): session opened for user'
    MSG_MORE_FAILURE = 'more authentication failure'

    username = ''
    res = {}

    def logins_by_username(username):
        if username not in res:
            res[username] = {'failed': 0, 'success': 0}
        return res[username]

    for entry in entries:
        m = entry['MESSAGE']
        if m.startswith(MSG_AUTH_FAIL):
            u = m.split()[-1]
            if u.startswith('user='):
                username = u.split('=')[1]
            else:
                username = ''
            logins_by_username(username)['failed'] += 1
        elif m.startswith('PAM ') and MSG_MORE_FAILURE in m:
            u = m.split()[-1]
            if u.startswith('user='):
                username = u.split('=')[1]
            else:
                username = ''
            logins_by_username(username)['failed'] += int(m.split()[1])
        elif m.startswith(MSG_SESSION_OPENED):
            username = m.split()[-3]
            logins_by_username(username)['success'] += 1

    return res


def logins_last_hour():
    return logins(get_journal_records())
