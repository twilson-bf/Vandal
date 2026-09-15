"""Standalone, logged forward and reverse DNS validation processes."""
import argparse
import ipaddress
import json
from pathlib import Path
import dns.exception
import dns.reversename
import dns.resolver
from .db import now


DEFAULT_RESOLVERS = ('1.1.1.1', '8.8.8.8')


def query(resolver, name, record_type):
    """Return a lossless-enough DNS observation without aborting the scan."""
    result = {'query_type': record_type, 'rcode': 'NOERROR', 'values': []}
    try:
        answer = resolver.resolve(name, record_type, raise_on_no_answer=False)
        result['raw_response'] = answer.response.to_text()
        result['values'] = sorted(r.to_text().rstrip('.') for r in answer) if answer.rrset else []
        result['ttl'] = answer.rrset.ttl if answer.rrset else None
        if not answer.rrset:
            result['rcode'] = 'NODATA'
    except dns.resolver.NXDOMAIN:
        result['rcode'] = 'NXDOMAIN'
    except dns.exception.DNSException as exc:
        result['rcode'] = type(exc).__name__
        result['error'] = str(exc)
    return result


def resolver_at(address):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [address]
    resolver.lifetime = 5
    return resolver


def dns_validate(inputs, output):
    with Path(output).open('w') as stream:
        for host in Path(inputs).read_text().splitlines():
            for resolver_ip in DEFAULT_RESOLVERS:
                resolver = resolver_at(resolver_ip)
                for record_type in ('A', 'AAAA', 'CNAME'):
                    record = dict(host=host, resolver=resolver_ip, query_type=record_type, timestamp=now(), rcode='NOERROR')
                    response = query(resolver, host, record_type)
                    record.update({k: v for k, v in response.items() if k not in ('query_type', 'values')})
                    record[record_type.lower()] = response['values']
                    stream.write(json.dumps(record) + '\n')
                    stream.flush()
                    print(f'{host} {resolver_ip} {record_type} {record["rcode"]}', flush=True)


def reverse_validate(inputs, output, resolvers=DEFAULT_RESOLVERS):
    """Resolve IPs to PTR names, then forward-confirm each returned name."""
    with Path(output).open('w') as stream:
        for address in Path(inputs).read_text().splitlines():
            original = ipaddress.ip_address(address)
            pointer = dns.reversename.from_address(address).to_text()
            for resolver_ip in resolvers:
                resolver = resolver_at(resolver_ip)
                ptr = query(resolver, pointer, 'PTR')
                names = ptr['values']
                forward = []
                for hostname in names:
                    answers = []
                    lookups = {}
                    for record_type in ('A', 'AAAA'):
                        response = query(resolver, hostname, record_type)
                        lookups[record_type.lower()] = response
                        answers.extend(response['values'])
                    confirmed = any(ipaddress.ip_address(candidate) == original for candidate in answers)
                    state = 'confirmed' if confirmed else 'forward-mismatch' if answers else 'ptr-only'
                    forward.append({'hostname': hostname, 'status': state, 'addresses': sorted(set(answers)), 'lookups': lookups})
                status = ('lookup-failed' if ptr['rcode'] not in ('NOERROR', 'NODATA') else
                          'no-ptr' if not names else
                          'confirmed' if any(item['status'] == 'confirmed' for item in forward) else
                          'forward-mismatch' if any(item['status'] == 'forward-mismatch' for item in forward) else 'ptr-only')
                record = {
                    'host': address, 'resolver': resolver_ip, 'query_type': 'PTR',
                    'query_name': pointer, 'timestamp': now(), 'rcode': ptr['rcode'],
                    'ptr': names, 'ttl': ptr.get('ttl'), 'raw_response': ptr.get('raw_response', ''),
                    'error': ptr.get('error', ''), 'status': status, 'forward': forward,
                    'confirmed_names': [item['hostname'] for item in forward if item['status'] == 'confirmed'],
                }
                stream.write(json.dumps(record) + '\n')
                stream.flush()
                print(f'{address} {resolver_ip} PTR {record["rcode"]} {status}', flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Vandal DNS probes')
    parser.add_argument('mode', choices=('dns', 'reverse'))
    parser.add_argument('targets')
    parser.add_argument('output')
    parser.add_argument('--resolvers', default=','.join(DEFAULT_RESOLVERS))
    args = parser.parse_args()
    if args.mode == 'dns':
        dns_validate(args.targets, args.output)
    else:
        reverse_validate(args.targets, args.output, tuple(filter(None, args.resolvers.split(','))))
