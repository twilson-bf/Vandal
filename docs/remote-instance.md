# Remote instance

Migrated from WSL on 2026-09-09.

- EC2: `i-089678cc594e375ee` (`kohler-rt-ext`)
- SSH: `ubuntu@35.87.45.76`, using an SSH agent
- App: `http://100.126.113.97:8765`
- Tailscale DNS: `i-089678cc594e375ee.tailnet-ce56.ts.net`
- Directory: `/home/ubuntu/dev/vandal`

The app currently binds to `0.0.0.0:8765`, as requested after migration. No public security-group opening was added. Use an SSH tunnel unless the surrounding network rules explicitly permit another internal path.

At cutover, Tailscale peer pings worked from Windows, but TCP 8765 timed out even with the server firewall allowing it and ShieldsUp disabled. Direct access may require a tailnet access-rule change. An SSH tunnel was started in WSL and verified from Windows (HTTP 200), providing access at `http://127.0.0.1:8765`. The app at that URL runs on EC2.

To recreate the tunnel after a workstation restart, with your SSH agent available, run in WSL:

```sh
ssh -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -N \
  -L 127.0.0.1:8765:100.126.113.97:8765 ubuntu@35.87.45.76
```

The initial background tunnel uses control socket `/tmp/vandal-remote-tunnel.sock`; stop it with `ssh -S /tmp/vandal-remote-tunnel.sock -O exit ubuntu@35.87.45.76`.

Existing accounts and passwords were preserved with the database, scope, scans, and screenshots. The final transfer was checked against file SHA-256 hashes, database table counts, account/password hashes, and SQLite integrity checks. The remote regression suite passed all 52 tests, and a localhost-only browser capture verified Chromium under the service user.

## Service operations

Run on the remote host:

```sh
sudo systemctl status vandal
sudo systemctl restart vandal
sudo journalctl -u vandal -n 100 --no-pager
```

The service starts at boot after Tailscale. Its unit is `/etc/systemd/system/vandal.service`; configuration is `/home/ubuntu/dev/vandal/.env.service`. Background workers are enabled.

The host's native Python is newer than the supported dependency versions, so the installation uses Python 3.11 at `/home/ubuntu/.local/share/vandal/python/bin/python3` and the app's `.venv`. To repeat dependency installation:

```sh
cd /home/ubuntu/dev/vandal
VANDAL_PYTHON=/home/ubuntu/.local/share/vandal/python/bin/python3 ./install.sh --extras
```

## Local copy

The WSL instance is stopped and retained at `/home/gh0st/dev/vandal`. Its database backup is `data/migration-backups/20260909T153125Z/vandal.db`. It will become stale as the remote instance changes; do not restart it as a replacement without first synchronizing the latest remote data. Stop the service before copying the entire data directory, or use a consistent SQLite backup and synchronize scan artifacts while jobs are stopped.
