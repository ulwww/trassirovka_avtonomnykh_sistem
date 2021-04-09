import socket
import sys
import random
from urllib.request import urlopen
from json import load
from collections import namedtuple


HopResults = namedtuple('HopResults',
                        ['reached', 'successful', 'ip', 'values'])


def send_and_get_response(ip: str, ttl_hops: int) -> HopResults:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
    sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl_hops)
    sock.settimeout(1)

    flag_reached = False
    flag_successful = False
    ip_callback = None
    values = []

    for _ in range(3):
        message, id_message = create_icmp_message()
        sock.sendto(message, (ip, 0))
        ip_callback, id_callback = receive_callback(sock, id_message)

        if ip_callback is not None and id_callback == id_message:
            flag_reached = ip_callback == ip
            flag_successful = True
            values = get_data_from_ip(ip_callback)
            break

    return HopResults(
        reached=flag_reached,
        successful=flag_successful,
        ip=ip_callback,
        values=values)


def create_icmp_message() -> (bytes, int):
    id_message = random.randint(0, 2 ** 16 - 1)

    return b'\x08\x00' + \
           socket.htons(get_checksum(
               b'\x08\x00\x00\x00' +
               id_message.to_bytes(2, 'big') +
               b'\x00\x01')).to_bytes(2, 'little') + \
           id_message.to_bytes(2, 'big') + b'\x00\x01', id_message


def get_checksum(_bytes: bytes) -> int:
    _sum = 0
    count_start = 0
    count_end = len(_bytes)

    while count_start < count_end:
        this_val = (_bytes[count_start + 1]) * 2 ** 8 + (_bytes[count_start])
        _sum = _sum + this_val
        _sum = _sum & 0xffffffff
        count_start = count_start + 2

    if count_end < len(_bytes):
        _sum = _sum + (_bytes[len(_bytes) - 1])
        _sum = _sum & 0xffffffff

    _sum = (_sum >> 16) + (_sum & 0xffff)
    _sum = _sum + (_sum >> 16)
    res = ~_sum
    res = res & 0xffff
    res = res >> 8 | (res << 8 & 0xff00)

    return res


def receive_callback(sock: socket.socket, id_wait: int) -> (str, int):
    try:
        data_received, address = sock.recvfrom(2 ** 10)
        id_received = int.from_bytes(data_received[-4:-2], 'big')

        if id_received == id_wait:
            return address[0], id_received
        else:
            return receive_callback(sock, id_wait)
    except socket.timeout:
        return None, None


def get_data_from_ip(ip: str) -> dict:
    res = urlopen('https://ipinfo.io/' + ip + '/json')
    data = load(res)

    _dict = dict()
    if 'org' in data.keys():
        temp = data['org'].split()
        _dict['AS'] = temp[0]
        _dict['Provider'] = ' '.join(temp[1:])
    if 'country' in data.keys():
        _dict['Country'] = data['country']

    return _dict


def print_hop(results: HopResults, line_number: int) -> None:
    if results.reached or results.successful:
        print('{:>3}.  {:<15}  '.format(line_number, results.ip), end='')

        if len(results.values) != 0:
            if type(results.values) == dict:
                temp = '; '.join(f'{key}: {value}'
                                 for key, value in results.values.items())
            else:
                temp = '; '.join(value for value in results.values)
            print(f'[{temp}]')
        else:
            print()
    else:
        print('{:>3}.  The waiting interval for '
              'the request has been exceeded.'.format(line_number))


if __name__ == '__main__':
    try:
        if len(sys.argv) < 2:
            sys.exit(-1)

        ip = sys.argv[1]
        try:
            socket.inet_aton(ip)
        except socket.error:
            try:
                ip = socket.gethostbyname(ip)
            except socket.gaierror:
                print('Incorrect!')
                sys.exit(-1)

        print(f'Tracing the route to {ip} with a maximum number of hops 50:')

        for i in range(50):
            result = send_and_get_response(ip, i + 1)
            print_hop(result, line_number=i + 1)

            if result.reached:
                sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(-1)
