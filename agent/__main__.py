import argparse
from . import run, get_device_id, get_open_ports, say_hello,\
    get_claim_token, get_claim_url


def main():
    actions = {
        'whoami': get_device_id,
        'portscan': get_open_ports,
        'test-cert': say_hello,
        'claim-token': get_claim_token,
        'claim-url': get_claim_url
    }
    parser = argparse.ArgumentParser()
    parser.add_argument('action', nargs='?',
                        choices=actions.keys())
    parser.add_argument('--debug', action='store_true')
    args = parser.parse_args()
    if not args.action:
        run(ping=True, debug=args.debug)
    else:
        run(ping=False, debug=args.debug)
        print(actions[args.action]())


if __name__ == '__main__':
    main()
