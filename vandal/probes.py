"""Standalone, logged independent DNS validation process."""
import json
from pathlib import Path
import sys
import dns.resolver
from .db import now


def dns_validate(inputs, output):
    with Path(output).open('w') as stream:
        for host in Path(inputs).read_text().splitlines():
            for resolver_ip in ('1.1.1.1', '8.8.8.8'):
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [resolver_ip]
                resolver.lifetime = 5
                for record_type in ('A', 'AAAA', 'CNAME'):
                    record = dict(host=host, resolver=resolver_ip, query_type=record_type, timestamp=now(), rcode='NOERROR')
                    try:
                        answer = resolver.resolve(host, record_type, raise_on_no_answer=False)
                        record['raw_response'] = answer.response.to_text()
                        record[record_type.lower()] = sorted(r.to_text().rstrip('.') for r in answer) if answer.rrset else []
                        record['ttl'] = answer.rrset.ttl if answer.rrset else None
                        if not answer.rrset:
                            record['rcode'] = 'NODATA'
                    except dns.resolver.NXDOMAIN:
                        record['rcode'] = 'NXDOMAIN'
                    except dns.exception.DNSException as exc:
                        record['rcode'] = type(exc).__name__
                        record['error'] = str(exc)
                    stream.write(json.dumps(record) + '\n')
                    stream.flush()
                    print(f'{host} {resolver_ip} {record_type} {record["rcode"]}', flush=True)


if __name__ == '__main__':
    if len(sys.argv) != 4 or sys.argv[1] != 'dns':
        raise SystemExit('Usage: python -m vandal.probes dns TARGET_FILE OUTPUT_FILE')
    dns_validate(sys.argv[2], sys.argv[3])
