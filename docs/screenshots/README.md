# Screenshots

These PNGs back the main README's image references:

| File | What it shows |
|---|---|
| `banner.png` | The `vpn-chainer up` banner — real output of `util.banner()`. |
| `orbit.png` | The topology block — real output of `chain_flow` + `chain_orbit` (example hop IPs). |
| `postcheck.png` | The "Post-up anonymity verification" section, all-green verdict. |
| `status.png` | `vpn-chainer status` for an ACTIVE 3-hop chain. |
| `verify.png` | `verify_chain.sh` output covering namespaces, tunnels, exit IPs, lockdown, wire isolation. |

`banner.png` and `orbit.png` are the tool's real rendering output. `status.png`,
`postcheck.png` and `verify.png` are **representative** — rendered from the tool's
own formatting code with example data (RFC 5737 documentation IPs like
`203.0.113.9`), since a real capture needs root plus live VPN endpoints. To
replace any of them with a genuine capture from your own run, keep the same
filename and re-run `git add -f docs/screenshots/*.png` (this folder's PNGs are
gitignored).

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
