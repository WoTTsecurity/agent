import argparse
import asyncio
import logging

from . import run, get_device_id, get_open_ports, say_hello, get_claim_token, get_claim_url, upgrade, executor
from . import fetch_credentials, fetch_device_metadata, setup_logging
from .security_helper import patch_sshd_config

logger = logging.getLogger('agent')


def main():
    actions = {
        'whoami': (get_device_id, "Print node ID."),
        'portscan': (get_open_ports, "Print open ports."),
        'test-cert': (say_hello, "Validate node certificate."),
        'claim-token': (get_claim_token, "Print claim token."),
        'claim-url': (get_claim_url, "Print claim URL."),
        'daemon': (run_daemon, "Run as daemon"),
        'node-metadata': (fetch_device_metadata, "Fetch node specific, secret metadata."),
        'credentials': (fetch_credentials, "Fetch credentials."),
    }

    patches = {
        'openssh-empty-password':
            ('OpenSSH: Disable logins with empty password', 'PermitEmptyPasswords'),
        'openssh-root-login':
            ('OpenSSH: Disable root login', 'PermitRootLogin'),
        'openssh-password-auth':
            ('OpenSSH: Disable password authentication', 'PasswordAuthentication'),
        'openssh-agent-forwarding':
            ('OpenSSH: Disable agent forwarding', 'AllowAgentForwarding'),
        'openssh-protocol':
            ('\tOpenSSH: Force protocol version 2', 'Protocol'),
        'openssh-client-alive-interval':
            ('OpenSSH: Active Client Interval', 'ClientAliveInterval'),
        'openssh-client-alive-count-max':
            ('OpenSSH: Active Client Max Count', 'ClientAliveCountMax'),
        'openssh-host-based-auth':
            ('OpenSSH: Host-based Authentication', 'HostbasedAuthentication'),
        'openssh-ignore-rhosts':
            ('OpenSSH: Ignore rhosts', 'IgnoreRhosts'),
        'openssh-log-level':
            ('\tOpenSSH: Log Level', 'LogLevel'),
        'openssh-login-grace-time':
            ('OpenSSH: Login Grace Time', 'LoginGraceTime'),
        'openssh-max-auth-tries':
            ('OpenSSH: Max Auth Tries', 'MaxAuthTries'),
        'openssh-permit-user-env':
            ('OpenSSH: Permit User Environment', 'PermitUserEnvironment'),
        'openssh-x11-forwarding':
            ('OpenSSH: X11 Forwarding', 'X11Forwarding')
    }
    patch_help_string = "One of the following:\n" + "\n".join(
        ["{}\t{}".format(k, v[0]) for k, v in patches.items()])

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="""
Streamlined security audit for your infrastructure.
When called without arguments, generates node certificate
or renews it if necessary.
""",
        prog="wott-agent")
    subparsers = parser.add_subparsers(help='Choose one of the following:', dest='action')
    for action, desc in actions.items():
        subparsers.add_parser(action, help=desc[1],
                              formatter_class=argparse.RawTextHelpFormatter)
    parser_patch = subparsers.add_parser('patch', help='patch the system',
                                         formatter_class=argparse.RawTextHelpFormatter)
    parser_patch.add_argument('patch_name',
                              choices=patches.keys(),
                              metavar='patch_name',
                              help=patch_help_string)
    parser_upgrade = subparsers.add_parser('upgrade', help='upgrade packages',
                                           formatter_class=argparse.RawTextHelpFormatter)
    parser_upgrade.add_argument('packages', metavar='pkg', nargs='+', help='packages to upgrade')
    parser.add_argument(
        '--dev',
        required=False,
        action="store_true",
        help="Developer mode: work with locally running server.")
    parser.add_argument(
        '--debug',
        required=False,
        action="store_true",
        help="Debug mode: set log level to DEBUG.")
    args = parser.parse_args()

    level = logging.DEBUG if args.debug is True else None
    if args.action == 'daemon':
        setup_logging(level=level, log_format="%(asctime)s - %(name)s - %(threadName)s - %(levelname)s - %(message)s")
    else:
        setup_logging(level=level, daemon=False,
                      log_format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    action = args.action
    if not action:
        logger.info("start in ping mode...")
        run(ping=True, dev=args.dev)
    elif action == 'daemon':
        logger.info("start in daemon mode...")
        run_daemon(dev=args.dev)
    elif action == 'patch':
        patch_sshd_config(patches[args.patch_name][1])
        run(ping=True, dev=args.dev)
    elif action == 'upgrade':
        upgrade(args.packages)
        run(ping=True, dev=args.dev)
    else:
        run(ping=False, dev=args.dev)
        print(actions[args.action][0](dev=args.dev))


PING_INTERVAL = 60 * 60
PING_TIMEOUT = 10 * 60
CREDS_INTERVAL = 15 * 60
CREDS_TIMEOUT = 1 * 60
# secret device-specific metadata fetching time constants
DEV_MD_INTERVAL = 15 * 60
DEV_MD_TIMEOUT = 1 * 60


def run_daemon(dev):
    exes = [
        executor.Executor(PING_INTERVAL, run, (True, dev, logger), timeout=PING_TIMEOUT),
        executor.Executor(CREDS_INTERVAL, fetch_credentials, (dev, logger), timeout=CREDS_TIMEOUT),
        executor.Executor(DEV_MD_INTERVAL, fetch_device_metadata, (dev, logger), timeout=DEV_MD_TIMEOUT)
    ]
    futures = [executor.schedule(exe) for exe in exes]

    def stop_exe():
        logger.info('Stopping all tasks...')
        for fut in futures:
            fut.cancel()
        for exe in exes:
            exe.stop()
        asyncio.get_event_loop().stop()
        logger.info('All tasks stopped.')

    try:
        executor.spin()
        logger.info('Daemon exiting.')
    except KeyboardInterrupt:
        logger.info('Daemon was interrupted!')
        stop_exe()


if __name__ == '__main__':
    main()
