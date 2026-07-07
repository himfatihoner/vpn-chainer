# Screenshots

Place PNGs here with these exact filenames so the main README's image
references resolve:

| File | What to capture |
|---|---|
| `banner.png` | Full `sudo vpn-chainer up …` run from banner to chain plan, with chain orbit visible. |
| `orbit.png` | Just the topology block — `chain_flow` line plus the concentric `chain_orbit` rings with hop IPs. |
| `postcheck.png` | The "Post-up anonymity verification" section with all green ✓ and the verdict line. |
| `status.png` | `vpn-chainer status` output showing an ACTIVE chain. |
| `verify.png` | `sudo ./verify_chain.sh` output covering namespaces, tunnels, exit IPs, lockdown, wire isolation. |

## Capturing tips

- Set the terminal width to **100 cols** so the banner and tagline both fit
  cleanly.
- Use a colour scheme with a dark background — the cyan→magenta gradient and
  the green ✓ pop best.
- `VPNCHAINER_FORCE_COLOR=1` if you're piping or scripting — forces ANSI on.
- Crop tightly around the relevant block; don't include the user's prompt
  unless it's part of the demo.
- PNG (lossless) is preferred over JPG — the ASCII art has sharp edges that
  JPG smears.
