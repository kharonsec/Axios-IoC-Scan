# Axios IoC Scan

IOC (Indicator of Compromise) scanner for the **axios npm supply chain attack** disclosed on **2026-03-31**.

Malicious versions `axios@1.14.1` and `axios@0.30.4` were published to npm with a trojanized dependency (`plain-crypto-js@4.2.1`) that delivered a cross-platform RAT communicating with `sfrclak.com` (`142.11.206.73:8000`).

## Quick Start

```bash
chmod +x axios-ioc-scan.sh
sudo ./axios-ioc-scan.sh
```

Root is recommended for full filesystem, network, and log visibility. The exit code equals the number of IOCs found (0 = clean).

## What It Checks

| # | Category | Details |
|---|----------|---------|
| 1 | **Filesystem** | RAT payloads on Linux (`/tmp/ld.py`), macOS (`com.apple.act.mond`), Windows/WSL (`wt.exe`, VBS/PS1 droppers) |
| 2 | **Processes** | Running RAT or dropper processes |
| 3 | **Network** | Active C2 connections, DNS logs (Pi-hole, AdGuard, dnsmasq, systemd-resolved), web server logs (Nginx, Apache, Caddy, Traefik), IDS alerts (Suricata, Snort), system journal |
| 4 | **npm/Node.js** | `plain-crypto-js` in `node_modules`, compromised versions in lockfiles, npm cache |
| 5 | **Docker** | Images built during the exposure window (2026-03-31 00:21–03:30 UTC) |
| 6 | **CrowdSec** | Whether the C2 IP is banned |
| 7 | **Firewall** | C2 IP block status in iptables, nftables, or macOS pf |

## IOC Summary

| Indicator | Value |
|-----------|-------|
| C2 Domain | `sfrclak.com` |
| C2 IP | `142.11.206.73` |
| C2 Port | `8000` |
| Malicious axios versions | `1.14.1`, `0.30.4` |
| Malicious dependency | `plain-crypto-js@4.2.1` |
| Exposure window (UTC) | 2026-03-31 00:21 — 03:30 |
| Advisory | GHSA-fw8c-xr5c-95f9 / MAL-2026-2306 |

## If IOCs Are Found

1. **Isolate** the machine from the network immediately
2. **Rotate** all credentials (npm tokens, SSH keys, cloud keys, API tokens, `.env` files)
3. **Block** `142.11.206.73` / `sfrclak.com` at all egress points
4. **Rebuild** from a clean image — do not attempt to clean in place
5. **Audit** CI/CD pipelines for runs during the exposure window

## Preventive Measures

- Pin axios to `1.14.0` (or `0.30.3` for legacy)
- Use `npm ci` with committed lockfiles in all CI/CD
- Set quarantine period: `npm config set min-release-age 3`
- Block the C2 IP/domain proactively at the firewall
- Require OIDC/SLSA provenance for critical dependencies

## Platform Support

Tested on: Ubuntu 22.04/24.04, Debian 12, Fedora 40, Arch, Alpine, macOS 14+

## References

- [Wiz Research](https://www.wiz.io/blog/axios-npm-compromised-in-supply-chain-attack)
- [Huntress SOC](https://www.huntress.com/blog/supply-chain-compromise-axios-npm-package)
- [Snyk](https://snyk.io/blog/axios-npm-package-compromised-supply-chain-attack-delivers-cross-platform/)
- [Joe Desimone / Elastic (IOC gist)](https://gist.github.com/joe-desimone/36061dabd2bc2513705e0d083a9673e7)
- StepSecurity, Socket Security, @cyberraiju IOC list

## License

MIT
