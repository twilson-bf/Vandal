# Dependency locks

`runtime.in` lists intended application dependencies. `bbot.in` pins the separately
installed discovery framework. Their `.lock` files include exact transitive versions
and distribution hashes. Regenerate intentionally using uv, then review the diff:

```bash
uv pip compile --universal --python-version 3.11 --generate-hashes --no-header runtime.in -o runtime.lock
uv pip compile --universal --python-version 3.11 --generate-hashes --no-header bbot.in -o bbot.lock
```

Run these commands from this directory. Runtime installation uses standard pip with
`--require-hashes`; uv is not an installation prerequisite. Locks resolve supported
Python versions, while actual environment smoke tests are performed on the local
interpreter. A changed interpreter should use a fresh environment, not reuse an old
virtualenv implicitly.

`tools.lock.json` contains explicit upstream release URLs and SHA-256 digests obtained
from official GitHub release asset metadata. Updating requires selecting a release and
replacing both architecture records, then testing its CLI compatibility. The installer
never resolves `latest`, executes remote install scripts, or runs tool self-updaters.

Binary sources:

- https://github.com/projectdiscovery/dnsx/releases
- https://github.com/projectdiscovery/httpx/releases
- https://github.com/sensepost/gowitness/releases
- https://github.com/projectdiscovery/katana/releases
- https://github.com/projectdiscovery/nuclei/releases
- https://github.com/projectdiscovery/tlsx/releases

BBOT: https://pypi.org/project/bbot/

Nessus is intentionally vendor-managed; importing reports does not require Nessus
locally. System package security updates remain the operator's normal OS maintenance.

