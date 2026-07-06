# Kitchen Micro-Segmenter

> Turns a commercial-kitchen device inventory into a **zero-trust, default-deny** nftables
> ruleset — so a compromised sardine-inventory sensor **can't pivot to the POS master**.
>
> Part of the **Technika11y** suite · *Root access for everyone.*

![status](https://img.shields.io/badge/status-pre--alpha-orange)
![license](https://img.shields.io/badge/license-Apache--2.0-blue)
![python](https://img.shields.io/badge/python-3.10%2B-informational)

---

## Status — read this first

**Pre-alpha (`v0.1.0a0`). Honest state of the code:**

| Capability | State |
|---|---|
| Policy model: zones with trust tiers, devices, sanctioned flows | ✅ works |
| Zero-trust linter: flags any lower-trust → higher-trust flow (the pivot risk) | ✅ works |
| Linter: orphan devices, unknown zones, unknown trust tiers | ✅ works |
| `generate` default-deny nftables ruleset with explicit allows | ✅ works |
| **Fails closed** — refuses to emit rules from an invalid policy; never auto-applies | ✅ works |
| YAML inventories, IPv6, per-device (not per-zone) rules | ⚠️ not built — [roadmap](#roadmap) |
| Live host discovery / agent | ❌ out of scope by design (you supply the inventory) |

This table is the honesty contract: it states exactly what runs. If a row overstates the code,
that's a bug — file it.

## Why it exists

Commercial kitchens are now full of IP devices — temp probes, KDS displays, smart ovens — sitting
on the same flat network as the point-of-sale. That flat network is the whole problem: pop the
cheapest sensor and you can reach the register. This tool encodes the **zero-trust invariant** as
something you can lint in CI: *a lower-trust zone may never initiate a flow into a higher-trust
one* unless you explicitly mark it as an audited exception.

Trust tiers (most→least sensitive): `admin` > `pos` > `boh` > `iot`.

## Usage

```bash
# lint an inventory (exit 1 if the zero-trust invariant is violated — drop it in CI)
python -m microseg.cli lint examples/kitchen.json

# generate the nftables ruleset (refuses if lint fails — fail closed)
python -m microseg.cli generate examples/kitchen.json > microseg.nft
```

Catching the classic mistake:

```jsonc
// add this flow and `lint` fails:
{ "src_zone": "iot", "dst_zone": "pos", "port": 443 }
// ERROR uptier-flow  flow iot->pos:443 lets a lower-trust zone reach a higher-trust one —
//                    a compromised iot device could pivot into pos. ...
```

## Safety

This tool **only prints** a ruleset. It never touches your firewall. Review the output, test it
in a lab, and apply it deliberately. Applying network policy you didn't read is how kitchens go
dark mid-service.

## Roadmap

- [ ] YAML inventories (alongside JSON)
- [ ] IPv6 + per-device rules
- [ ] `diff` mode: what changes vs. the currently-loaded ruleset
- [ ] SARIF output + the shared Technika11y CI gate
- [ ] Pairing with the Kitchen IoT Firmware Auditor (OPS-09) for device-risk-weighted policy

## License

[Apache-2.0](LICENSE). See [`SECURITY.md`](SECURITY.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md).
