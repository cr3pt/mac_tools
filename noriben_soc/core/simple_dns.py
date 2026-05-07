"""Minimal DNS responder for WPAD name. Uses dnslib if available, otherwise is a noop.
Responds to queries for 'wpad' or 'wpad.local' with configured A record.
"""
import logging
import os

LOG = logging.getLogger('noriben.dns')
WPAD_NAME = os.getenv('NET_PROXY_WPAD_NAME', 'wpad')
WPAD_ADDR = os.getenv('NET_PROXY_WPAD_ADDR', '10.0.2.2')

try:
    from dnslib import DNSRecord, QTYPE, RR, A
    HAS_DNSLIB = True
except Exception:
    HAS_DNSLIB = False

_server = None

async def start_dns(bind_host: str = '127.0.0.1', port: int = 5300):
    if not HAS_DNSLIB:
        LOG.warning('dnslib not available — DNS responder disabled')
        return None

    import asyncio
    loop = asyncio.get_running_loop()

    def handle(sock):
        data, addr = sock.recvfrom(512)
        try:
            req = DNSRecord.parse(data)
            qname = str(req.q.qname).rstrip('.')
            qtype = QTYPE[req.q.qtype]
            LOG.debug('DNS query %s %s from %s', qname, qtype, addr)
            if qname == WPAD_NAME or qname == WPAD_NAME + '.local':
                reply = req.reply()
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(WPAD_ADDR), ttl=60))
                sock.sendto(reply.pack(), addr)
            else:
                # Not handled
                pass
        except Exception:
            LOG.exception('Failed to handle DNS')

    sock = socket = __import__('socket')
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind((bind_host, port))

    loop.add_reader(server.fileno(), handle, server)
    LOG.info('DNS responder started on %s:%d (wpad=%s -> %s)', bind_host, port, WPAD_NAME, WPAD_ADDR)
    return server

async def stop_dns(server):
    try:
        server.close()
    except Exception:
        pass
