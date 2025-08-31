# ClamAV Sidecar

Document uploads can be scanned for viruses using a ClamAV daemon.
Start a `clamav` container alongside the portal and enable scanning with
`AV_SCAN_ENABLED=1`.

`clamdscan` connects to the daemon using either a UNIX socket or TCP. Configure
one of the following environment variables as needed:

- `CLAMD_SOCKET`: path to the clamd socket inside the portal container.
- `CLAMD_HOST` and `CLAMD_PORT`: host and port of the clamd service.

When enabled, each upload is scanned and the result is recorded in the audit
log via `log_action(..., "av_scan")`. Infected files are rejected with a
"Virus detected" error.
