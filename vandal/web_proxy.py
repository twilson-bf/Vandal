"""Job-local HTTP proxy: pin DNS sockets and enforce scope on every connection."""
import http.server
import ipaddress
import select
import socket
import socketserver
from urllib.parse import urlsplit
from .scope_rules import matcher


class ScopeProxy(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    def __init__(self, candidates, excluded, eid=None, log=None):
        self.eid, self.log = eid, log
        self.allowed = {(c['host'].lower(),c['port']) for c in candidates}
        self.excluded = matcher(excluded)
        self.resolutions = {}
        super().__init__(('127.0.0.1',0), ProxyRequest)

    def destination(self, host, port):
        if self.eid is not None:
            from .db import connect
            with connect() as con:
                self.excluded = matcher([r[0] for r in con.execute("SELECT target FROM scope_rules WHERE engagement_id=? AND action='exclude'",(self.eid,))])
        host = host.lower().rstrip('.')
        if (host,port) not in self.allowed or self.excluded(host): raise ValueError('Destination is outside this web job')
        ips = sorted({a[4][0] for a in socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)})
        if not ips or any(self.excluded(ip) for ip in ips): raise ValueError('DNS answer matches an exclusion')
        self.resolutions.setdefault(host,set()).update(ips)
        if self.log:
            import json
            with self.log.open('a') as f: f.write(json.dumps({'host':host,'ips':ips})+'\n')
        error = None
        for ip in ips:
            try: return socket.create_connection((ip,port),timeout=10)
            except OSError as exc: error = exc
        raise error or ValueError('No destination address')


class ProxyRequest(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self,*args): pass
    def do_CONNECT(self): self.forward(True)
    def do_GET(self): self.forward(False)
    def do_HEAD(self): self.forward(False)
    def do_POST(self): self.forward(False)
    def forward(self, tunnel):
        upstream = None
        try:
            u = urlsplit(('https://' if tunnel else '')+self.path)
            if not u.hostname or u.username or u.password or u.scheme not in ('http','https'): raise ValueError('Invalid proxy URL')
            upstream = self.server.destination(u.hostname,u.port or (443 if u.scheme=='https' else 80))
            if tunnel:
                self.send_response(200);self.end_headers()
            else:
                path = u.path or '/'
                if u.query: path += '?'+u.query
                headers = ''.join(f'{k}: {v}\r\n' for k,v in self.headers.items() if k.lower() not in ('proxy-connection','proxy-authorization','connection'))
                upstream.sendall(f'{self.command} {path} HTTP/1.1\r\n{headers}Connection: close\r\n\r\n'.encode('latin1'))
                length = int(self.headers.get('Content-Length','0'))
                if length>1024*1024: raise ValueError('Request too large')
                if length: upstream.sendall(self.rfile.read(length))
            while True:
                ready,_,_=select.select([self.connection,upstream],[],[],30)
                if not ready: break
                for source in ready:
                    chunk = source.recv(65536)
                    if not chunk: return
                    (upstream if source is self.connection else self.connection).sendall(chunk)
        except Exception as exc:
            try:
                self.send_response(502);self.send_header('X-Vandal-Proxy-Error','1');self.send_header('Content-Length','0');self.end_headers()
            except OSError: pass
        finally:
            self.close_connection=True
            if upstream: upstream.close()
