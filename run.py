#!/usr/bin/env python3
"""Start vandal with the repo-local interpreter, web server and worker."""
import os
import argparse
import ipaddress
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
python = root / '.venv/bin/python'
if sys.prefix != str(root / '.venv') and python.exists():
    os.execv(str(python), [str(python), str(__file__), *sys.argv[1:]])

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wsl', action='store_true', help='Listen on WSL interfaces and allow the current WSL IP addresses')
    parser.add_argument('--allow-host', action='append', default=[], help='Additional HTTP host name or IP allowed to reach Vandal')
    args = parser.parse_args()
    if args.allow_host:
        os.environ['VANDAL_ALLOWED_HOSTS'] = ','.join([os.getenv('VANDAL_ALLOWED_HOSTS', 'localhost,127.0.0.1,::1,testserver'), *args.allow_host])
    if args.wsl:
        addresses = [str(ipaddress.ip_address(value)) for value in
                     subprocess.check_output(['hostname', '-I'], text=True).split()]
        if not addresses:
            parser.error('No WSL interface addresses found')
        os.environ['VANDAL_HOST'] = '0.0.0.0'
        allowed = os.getenv('VANDAL_ALLOWED_HOSTS', 'localhost,127.0.0.1,::1,testserver')
        os.environ['VANDAL_ALLOWED_HOSTS'] = ','.join([allowed, *addresses])
        for address in addresses:
            if ipaddress.ip_address(address).version == 4:
                print(f'Windows access: http://{address}:{os.getenv("VANDAL_PORT", "8765")}', flush=True)
    import uvicorn
    uvicorn.run('vandal.app:app', host=os.getenv('VANDAL_HOST', '127.0.0.1'), port=int(os.getenv('VANDAL_PORT', '8765')), workers=1)
