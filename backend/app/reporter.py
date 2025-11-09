import os, json
from datetime import datetime
from .config import OUTPUT_DIR
def ensure_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
def build_report(target, parts):
    ensure_dir()
    ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    fname = os.path.join(OUTPUT_DIR, f'report_{target.replace("://","_").replace("/","_")}_{ts}.json')
    data = {'target':target,'generated':ts,'results':parts}
    with open(fname,'w',encoding='utf-8') as f:
        json.dump(data,f,indent=2,ensure_ascii=False)
    return fname
