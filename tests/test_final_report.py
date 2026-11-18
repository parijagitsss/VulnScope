import importlib.util
from pathlib import Path
import tempfile
import unittest
import json

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('build_final_report', ROOT / 'tools' / 'build_final_report.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReportTests(unittest.TestCase):
    def test_escaping(self):
        html = module.build_html([{'id': 'VS-1', 'title': '<script>alert(1)</script>', 'status': 'Pending'}], [], [], 'test date')
        self.assertNotIn('<script>alert(1)</script>', html)
        self.assertIn('&lt;script&gt;', html)

    def test_read_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'findings.json'
            path.write_text(json.dumps({'findings':[{'id':'VS-001'}]}), encoding='utf-8')
            self.assertEqual(module.read_findings(path)[0]['id'], 'VS-001')

    def test_nmap_xml(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'sample.xml'
            path.write_text('<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="5000"><state state="open"/><service name="http" product="Werkzeug"/></port></ports></host></nmaprun>', encoding='utf-8')
            found = module.nmap_services(path)
            self.assertEqual(found[0]['port'], '5000')

    def test_zap_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'zap.json'
            path.write_text(json.dumps({'site':[{'alerts':[{'name':'Missing header','riskdesc':'Low (Medium)'}]}]}),encoding='utf-8')
            alerts = module.zap_alerts(path)
            self.assertEqual(len(alerts), 1)
            self.assertEqual(alerts[0]['status'], 'Unverified automated alert')


if __name__ == '__main__':
    unittest.main()
