import aiohttp
REQUIRED = [
    'Content-Security-Policy',
    'X-Frame-Options',
    'Strict-Transport-Security',
    'X-Content-Type-Options',
    'Referrer-Policy'
]
async def check_headers(session, url):
    try:
        async with session.get(url, timeout=10) as resp:
            headers = {k:v for k,v in resp.headers.items()}
            missing = [h for h in REQUIRED if h not in headers]
            return {'present':headers,'missing':missing}
    except Exception as e:
        return {'error':str(e)}
