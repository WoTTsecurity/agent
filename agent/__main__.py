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
    args = parser.parse_args()
    if not args.action:
        run(True)
    else:
        run(False)
        print(actions[args.action]())


if __name__ == '__main__':
    main()
