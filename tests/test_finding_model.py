import unittest

from models.data_models import Finding


class TestFindingModel(unittest.TestCase):
    def test_to_dict_fills_recommendation_from_action(self):
        f = Finding(
            id="X",
            category="test",
            severity="HIGH",
            description="d",
            action="do this",
        )
        d = f.to_dict()
        self.assertEqual(d["action"], "do this")
        self.assertEqual(d["recommendation"], "do this")

    def test_from_dict_roundtrip(self):
        raw = {
            "id": "DNS-CLASS-LONG-LABEL",
            "category": "dns-class",
            "severity": "HIGH",
            "description": "x",
            "tags": "dns-class,tunneling",
            "action": "block",
        }
        f = Finding.from_dict(raw)
        self.assertEqual(f.id, "DNS-CLASS-LONG-LABEL")
        self.assertIn("dns-class", f.tags)
        self.assertIn("tunneling", f.tags)


if __name__ == "__main__":
    unittest.main()
