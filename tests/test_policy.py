import unittest

from microseg.model import Policy
from microseg.policy import lint, has_errors

BASE = {
    "zones": {"iot": "iot", "pos": "pos"},
    "devices": [
        {"id": "temp-probe-1", "ip": "10.0.9.11", "zone": "iot"},
        {"id": "register-1", "ip": "10.0.1.5", "zone": "pos"},
    ],
    "flows": [],
}


def with_flows(flows):
    data = dict(BASE)
    data["flows"] = flows
    return Policy.from_dict(data)


class PolicyTests(unittest.TestCase):
    def test_clean_policy_has_no_errors(self):
        self.assertFalse(has_errors(lint(Policy.from_dict(BASE))))

    def test_flags_iot_to_pos_pivot(self):
        findings = lint(with_flows([{"src_zone": "iot", "dst_zone": "pos", "port": 443}]))
        self.assertTrue(any(f["rule"] == "uptier-flow" for f in findings))

    def test_audited_exception_suppresses_uptier(self):
        findings = lint(with_flows(
            [{"src_zone": "iot", "dst_zone": "pos", "port": 443, "audited_exception": True}]))
        self.assertFalse(any(f["rule"] == "uptier-flow" for f in findings))

    def test_downtier_flow_is_allowed(self):
        findings = lint(with_flows([{"src_zone": "pos", "dst_zone": "iot", "port": 1883}]))
        self.assertFalse(any(f["rule"] == "uptier-flow" for f in findings))

    def test_orphan_device_zone(self):
        data = dict(BASE)
        data["devices"] = BASE["devices"] + [{"id": "x", "ip": "10.0.0.9", "zone": "ghost"}]
        findings = lint(Policy.from_dict(data))
        self.assertTrue(any(f["rule"] == "device-orphan-zone" for f in findings))


if __name__ == "__main__":
    unittest.main()
