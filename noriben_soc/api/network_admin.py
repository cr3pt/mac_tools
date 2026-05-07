from fastapi import APIRouter, Depends, HTTPException
from .admin import admin_required

router = APIRouter()

@router.get('/network/helpers/status')
async def network_helpers_status(user: str = Depends(admin_required)):
    """Return status of host-side network helpers (proxy, wpad, dns) and proxy counters."""
    status = {}
    try:
        from ..core import net_proxy
        status['proxy'] = net_proxy.get_status()
    except Exception:
        status['proxy'] = {'error': 'net_proxy not available'}
    try:
        from ..core import wpad
        status['wpad'] = {'running': getattr(wpad, '_server', None) is not None}
    except Exception:
        status['wpad'] = {'error': 'wpad not available'}
    try:
        from ..core import simple_dns
        status['dns'] = {'running': getattr(simple_dns, '_server', None) is not None}
    except Exception:
        status['dns'] = {'error': 'dns not available'}
    return status

@router.post('/network/helpers/start')
async def network_helpers_start(user: str = Depends(admin_required)):
    res = {}
    try:
        from ..core import net_proxy
        await net_proxy.start_proxy()
        res['proxy'] = net_proxy.get_status()
    except Exception as e:
        res['proxy'] = {'error': str(e)}
    try:
        from ..core import wpad
        await wpad.start_wpad()
        res['wpad'] = {'running': True}
    except Exception as e:
        res['wpad'] = {'error': str(e)}
    try:
        from ..core import simple_dns
        dns_srv = await simple_dns.start_dns()
        res['dns'] = {'running': dns_srv is not None}
    except Exception as e:
        res['dns'] = {'error': str(e)}
    return res

@router.post('/network/helpers/stop')
async def network_helpers_stop(user: str = Depends(admin_required)):
    res = {}
    try:
        from ..core import net_proxy
        await net_proxy.stop_proxy()
        res['proxy'] = {'running': False}
    except Exception as e:
        res['proxy'] = {'error': str(e)}
    try:
        from ..core import wpad
        await wpad.stop_wpad()
        res['wpad'] = {'running': False}
    except Exception as e:
        res['wpad'] = {'error': str(e)}
    try:
        from ..core import simple_dns
        await simple_dns.stop_dns(getattr(simple_dns, '_server', None))
        res['dns'] = {'running': False}
    except Exception as e:
        res['dns'] = {'error': str(e)}
    return res

@router.get('/network/proxy/stats')
async def proxy_stats(user: str = Depends(admin_required)):
    try:
        from ..core import net_proxy
        st = net_proxy.get_status()
        return {'ok': True, 'stats': st}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
