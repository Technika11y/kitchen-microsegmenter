import unittest

from microseg.model import Policy
from microseg.nftables import generate

DATA = {
    "zones": {"iot": "iot", "pos": "pos"},
    "devices": [
        {"id": "probe", "ip": "10.0.9.11", "zone": "iot"},
        {"id": "reg", "ip": "10.0.1.5", "zone": "pos"},
    ],
    "flows": [{"src_zone": "pos", "dst_zone": "iot", "port": 1883, "proto": "tcp"}],
}


class NftablesTests(unittest.TestCase):
    def setUp(self):
        self.out = generate(Policy.from_dict(DATA))

    def test_default_drop(self):
        self.assertIn("policy drop;", self.out)

    def test_zone_sets_present(self):
        self.assertIn("set zone_iot", self.out)
        self.assertIn("set zone_pos", self.out)

    def test_sanctioned_flow_rule(self):
        self.assertIn(
            "ip saddr @zone_pos ip daddr @zone_iot tcp dport 1883 accept", self.out)


if __name__ == "__main__":
    unittest.main()
