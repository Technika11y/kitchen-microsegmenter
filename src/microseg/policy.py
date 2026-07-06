"""The policy linter — pure functions, so the zero-trust invariant is unit-testable
without touching a firewall."""
from .model import TIERS


def _tier(policy, zone):
    label = policy.zones.get(zone)
    return TIERS.get(label) if label else None


def lint(policy):
    """Return a list of findings: {rule, severity, message}."""
    findings = []
    zone_names = set(policy.zones)

    # zones must use a known trust tier
    for zone, label in policy.zones.items():
        if label not in TIERS:
            findings.append(_f("unknown-tier", "error",
                f'zone "{zone}" has unknown trust tier "{label}" '
                f'(expected one of {sorted(TIERS)})'))

    # every device must live in a declared zone
    for d in policy.devices:
        if d.zone not in zone_names:
            findings.append(_f("device-orphan-zone", "error",
                f'device "{d.id}" is in undeclared zone "{d.zone}"'))

    # devices need unique IPs (a shared IP defeats per-address segmentation) and unique ids
    seen_ips = {}
    seen_ids = set()
    for d in policy.devices:
        if d.ip in seen_ips:
            findings.append(_f("duplicate-device-ip", "error",
                f'devices "{seen_ips[d.ip]}" and "{d.id}" share IP {d.ip} — '
                f'segmentation rules cannot tell them apart'))
        else:
            seen_ips[d.ip] = d.id
        if d.id in seen_ids:
            findings.append(_f("duplicate-device-id", "warn", f'duplicate device id "{d.id}"'))
        seen_ids.add(d.id)

    # the core zero-trust invariant
    for fl in policy.flows:
        for z in (fl.src_zone, fl.dst_zone):
            if z not in zone_names:
                findings.append(_f("flow-unknown-zone", "error",
                    f'flow references undeclared zone "{z}"'))
        st, dt = _tier(policy, fl.src_zone), _tier(policy, fl.dst_zone)
        if st is not None and dt is not None and st < dt and not fl.audited_exception:
            findings.append(_f("uptier-flow", "error",
                f'flow {fl.src_zone}->{fl.dst_zone}:{fl.port} lets a lower-trust zone reach a '
                f'higher-trust one — a compromised {fl.src_zone} device could pivot into '
                f'{fl.dst_zone}. Remove it, or set audited_exception=true with justification.'))

    return findings


def has_errors(findings):
    return any(x["severity"] == "error" for x in findings)


def _f(rule, severity, message):
    return {"rule": rule, "severity": severity, "message": message}
