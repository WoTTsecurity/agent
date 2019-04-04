from systemd import journal
import time


def get_journal_records():
    '''
    Get syslog records as returned by
        journalctl -l SYSLOG_FACILITY=10 --priority=5 --since "1 hour ago"
    '''
    j = journal.Reader()
    j.this_boot()
    j.log_level(journal.LOG_NOTICE)
    last_hour = time.time() - 60**2
    j.seek_realtime(last_hour)
    j.add_match(SYSLOG_FACILITY=10)
    return j

def failed_logins(entries):
    '''
    Returns the number of failed login attempts (password auth). The code looks
    for the following lines in the system journal:
        pam_unix(sshd:auth): check pass; user unknown
        pam_unix(sshd:auth): authentication failure; ...
    
    These lines usually come in pairs, however one of the two may be outside the
    time limit, so the code counts them separately and returns the max count.
    '''
    MSG1 = 'pam_unix(sshd:auth): check pass; user unknown'
    MSG2 = 'pam_unix(sshd:auth): authentication failure;'

    n1, n2 = 0, 0
    for entry in entries:
        m = entry['MESSAGE']
        print(m)
        if m.startswith(MSG1):
            n1 += 1
        elif m.startswith(MSG2):
            n2 += 1
    print('counts: {}, {}'.format(n1, n2))
    return max(n1, n2)

def failed_logins_last_hour():
    return failed_logins(get_journal_records())
