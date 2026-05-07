"""Simple HTTP proxy with allowlist for use by guest VMs.
Supports CONNECT tunneling for HTTPS and basic HTTP forwarding.
Configure the guest to use this proxy (e.g., HTTP proxy 10.0.2.2:3128) or set browser proxy settings.
"""
import asyncio
import logging
import os
import socket

LOG = logging.getLogger("noriben.netproxy")

ALLOWLIST = [h.strip().lower() for h in os.getenv('NET_PROXY_ALLOWLIST', 'example.com').split(',') if h.strip()]
PORT = int(os.getenv('NET_PROXY_PORT', '3128'))
BIND_HOST = os.getenv('NET_PROXY_BIND', '127.0.0.1')

async def _pipe(reader, writer):
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

async def handle_client(reader, writer):
    peer = writer.get_extra_info('peername')
    try:
        line = await reader.readline()
        if not line:
            return
        first = line.decode(errors='ignore').strip()
        parts = first.split(' ')
        if len(parts) < 2:
            return
        method, target = parts[0], parts[1]

        # CONNECT method for HTTPS
        if method.upper() == 'CONNECT':
            host, port = target.split(':') if ':' in target else (target, 443)
            if not _allowed(host):
                LOG.warning('Blocked CONNECT to %s from %s', host, peer)
                writer.write(b'HTTP/1.1 403 Forbidden\r\n\r\n')
                await writer.drain()
                return
            try:
                remote_reader, remote_writer = await asyncio.open_connection(host, int(port))
            except Exception:
                writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                await writer.drain()
                return
            writer.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            await writer.drain()
            await asyncio.gather(_pipe(reader, remote_writer), _pipe(remote_reader, writer))
            return

        # Otherwise assume HTTP request; gather headers
        headers = []
        while True:
            h = await reader.readline()
            if not h or h in (b"\r\n", b"\n"):
                break
            headers.append(h.decode(errors='ignore'))
        # Extract Host header
        host = None
        for h in headers:
            if h.lower().startswith('host:'):
                host = h.split(':',1)[1].strip()
                break
        if not host:
            # try to parse from target
            if '://' in target:
                host = target.split('://',1)[1].split('/',1)[0]
            else:
                host = target
        host_only = host.split(':')[0]
        if not _allowed(host_only):
            LOG.warning('Blocked HTTP to %s from %s', host_only, peer)
            writer.write(b'HTTP/1.1 403 Forbidden\r\n\r\n')
            await writer.drain()
            return

        # open remote
        try:
            remote_reader, remote_writer = await asyncio.open_connection(host_only, int(host.split(':')[1]) if ':' in host else 80)
        except Exception:
            writer.write(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            await writer.drain()
            return

        # forward the initial request line and headers
        remote_writer.write((first + '\r\n').encode())
        for h in headers:
            remote_writer.write(h.encode())
        remote_writer.write(b'\r\n')
        await remote_writer.drain()

        await asyncio.gather(_pipe(reader, remote_writer), _pipe(remote_reader, writer))
    except Exception:
        LOG.exception('Proxy handler error')
    finally:
        try:
            writer.close()
        except Exception:
            pass

def _allowed(hostname: str) -> bool:
    hn = hostname.lower()
    # exact match or suffix match
    for a in ALLOWLIST:
        if hn == a or hn.endswith('.' + a):
            return True
    return False

_server = None

async def start_proxy(bind_host: str = BIND_HOST, port: int = PORT):
    global _server
    if _server:
        return _server
    LOG.info('Starting net proxy on %s:%d (allowlist=%s)', bind_host, port, ALLOWLIST)
    _server = await asyncio.start_server(handle_client, bind_host, port)
    return _server

async def stop_proxy():
    global _server
    if not _server:
        return
    _server.close()
    await _server.wait_closed()
    _server = None

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(start_proxy())
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass
