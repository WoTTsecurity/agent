import argparse
import asyncio
import logging

from . import run, get_device_id, get_open_ports, say_hello, get_claim_token, get_claim_url, executor
from . import fetch_credentials, fetch_device_metadata, setup_logging, logger


def main():
    actions = {
        'whoami': (get_device_id, "Print device ID."),
        'portscan': (get_open_ports, "Print open ports."),
        'test-cert': (say_hello, "Validate device certificate."),
        'claim-token': (get_claim_token, "Print claim token."),
        'claim-url': (get_claim_url, "Print claim URL."),
        'daemon': (run_daemon, "Run as daemon"),
        'dev-metadata': (fetch_device_metadata, "Fetch device specific, secret metadata.")
    }
    help_string = "One of the following:\n\n" + "\n".join(
        ["{: <12} {: <}".format(k, v[1]) for k, v in actions.items()])
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description="""
Let's Encrypt for IoT (with more bells and whistles).
When called without arguments, generates device certificate
or renews it if necessary.
""",
        prog="wott-agent")
    parser.add_argument('action',
                        nargs='?',
                        choices=actions.keys(),
                        metavar='action',
                        help=help_string)
    parser.add_argument(
        '--dev',
        required=False,
        action="store_true",
        help="Developer mode: work with locally running server.")
    args = parser.parse_args()

    if args.action == 'daemon':
        setup_logging(level=logging.INFO,
                      log_format="%(asctime)s - %(name)s - %(threadName)s - %(levelname)s - %(message)s")
    else:
        setup_logging(level=logging.INFO, daemon=False,
                      log_format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    if not args.action:
        logger.info("start in ping mode...")
        run(ping=True, dev=args.dev)
    elif args.action == 'daemon':
        logger.info("start in daemon mode...")
        run_daemon(dev=args.dev)
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
