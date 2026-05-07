"""Simple WPAD/PAC generator server.
Serves /wpad.dat pointing to the configured proxy host:port.
"""
import asyncio
import logging
import os

LOG = logging.getLogger('noriben.wpad')
BIND = os.getenv('NET_PROXY_BIND', '127.0.0.1')
PORT = int(os.getenv('NET_PROXY_WPAD_PORT', '3129'))
PROXY_HOST = os.getenv('NET_PROXY_BIND', '127.0.0.1')
PROXY_PORT = int(os.getenv('NET_PROXY_PORT', '3128'))

async def _handle(reader, writer):
    try:
        line = await reader.readline()
        if not line:
            return
        request = line.decode(errors='ignore').strip()
        # read and discard headers
        while True:
            h = await reader.readline()
            if not h or h in (b"\r\n", b"\n"):
                break
        if request.startswith('GET') and ('/wpad.dat' in request or 'wpad.dat' in request):
            pac = f"function FindProxyForURL(url, host) {{ return 'PROXY {PROXY_HOST}:{PROXY_PORT}'; }}"
            resp = (
                'HTTP/1.1 200 OK\r\n'
                'Content-Type: application/x-ns-proxy-autoconfig\r\n'
                f'Content-Length: {len(pac)}\r\n'
                '\r\n'
                f'{pac}'
            )
            writer.write(resp.encode())
            await writer.drain()
        else:
            writer.write(b'HTTP/1.1 404 Not Found\r\n\r\n')
            await writer.drain()
    except Exception:
        LOG.exception('WPAD handler error')
    finally:
        try:
            writer.close()
        except Exception:
            pass

_server = None

async def start_wpad(bind_host: str = BIND, port: int = PORT):
    global _server
    if _server:
        return _server
    LOG.info('Starting WPAD server on %s:%d', bind_host, port)
    _server = await asyncio.start_server(_handle, bind_host, port)
    return _server

async def stop_wpad():
    global _server
    if not _server:
        return
    _server.close()
    await _server.wait_closed()
    _server = None

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    try:
        asyncio.run(start_wpad())
        asyncio.get_event_loop().run_forever()
    except KeyboardInterrupt:
        pass
