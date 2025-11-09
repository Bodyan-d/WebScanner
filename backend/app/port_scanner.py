import asyncio, socket, shutil, subprocess
from urllib.parse import urlparse
TOP_PORTS = [80,443,21,22,25,53,110,143,3306,5432,8000,8080,8443]
async def _tcp_check(host, port, timeout=1.0):
    loop = asyncio.get_event_loop()
    def _sync():
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except:
            return False
    return await loop.run_in_executor(None, _sync)
async def tcp_scan(host, ports=TOP_PORTS):
    tasks = [_tcp_check(host,p) for p in ports]
    res = await asyncio.gather(*tasks)
    return {p:bool(ok) for p,ok in zip(ports,res)}
def nmap_scan(host):
    if shutil.which("nmap"):
        try:
            out = subprocess.check_output(["nmap","-Pn","-p",",".join(str(x) for x in TOP_PORTS), host], text=True, stderr=subprocess.STDOUT, timeout=60)
            return {"ok":True,"output":out}
        except Exception as e:
            return {"ok":False,"error":str(e)}
    return {"ok":False,"error":"nmap not installed"}
