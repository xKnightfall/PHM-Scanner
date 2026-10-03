import tempfile, zipfile
from pathlib import Path
import unittest
from phm.core.target_resolution import resolve_target
from phm.core.investigator import InvestigationRunner

PNG=b'\x89PNG\r\n\x1a\n'+b'fake'
class RecursiveArchitectureTests(unittest.TestCase):
 def make_zip(self,path,members):
  with zipfile.ZipFile(path,'w') as z:
   for name,data in members.items(): z.writestr(name,data)
 def test_canonical_resolution(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)
   image=p/'x.bin'; image.write_bytes(PNG)
   self.assertEqual(resolve_target(image).plugins,['file_analysis','image_analysis'])
   z=p/'x.zip'; self.make_zip(z,{'a.txt':b'hello'})
   self.assertEqual(resolve_target(z).plugins,['file_analysis','archive_analysis'])
 def test_nested_archive_is_requeued(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d); inner=p/'inner.zip'; self.make_zip(inner,{'hello.txt':b'hello'})
   outer=p/'outer.zip'; self.make_zip(outer,{'inner.zip':inner.read_bytes()})
   report=InvestigationRunner(max_nodes=5,max_depth=3).run(str(outer))
   values=[n['value'] for n in report.metadata['nodes']]
   self.assertGreaterEqual(len(values),3)
   self.assertTrue(any(v.endswith('inner.zip') for v in values))
   self.assertTrue(any(v.endswith('hello.txt') for v in values))
 def test_extracted_image_uses_image_analyzer(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d); z=p/'outer.zip'; self.make_zip(z,{'mystery.bin':PNG})
   report=InvestigationRunner(max_nodes=4).run(str(z))
   self.assertTrue(any(r.plugin=='image_analysis' and r.target.endswith('mystery.bin') for r in report.results))
 def test_traversal_names_stay_in_workspace(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d); z=p/'outer.zip'; self.make_zip(z,{'../../escape.txt':b'x','/absolute.txt':b'y','C:\\escape.txt':b'z'})
   report=InvestigationRunner(max_nodes=5).run(str(z))
   for r in report.results:
    for item in r.raw.get('extracted',[]): self.assertIn('phm-investigation-',item['path'])
 def test_ipv4_not_phone(self):
  from phm.core.artifacts import extract_artifacts
  types=[a.type.value for a in extract_artifacts('8.8.8.8')]
  self.assertIn('ip',types); self.assertNotIn('phone',types)
 def test_decimal_not_phone(self):
  from phm.core.artifacts import extract_artifacts
  self.assertNotIn('phone',[a.type.value for a in extract_artifacts('0.1793125')])
 def test_extracted_workspace_path_is_not_a_domain_pivot(self):
  from phm.core.artifacts import extract_artifacts
  values=extract_artifacts('/tmp/phm-investigation-x/artifacts/ee25264acba19d70/mystery.bin')
  self.assertFalse(any(a.type.value=='domain' for a in values))
 def test_domain_validation_rejects_file_like_artifacts(self):
  from phm.core.artifacts import extract_artifacts
  for value in ('mystery.binpk','mystery.binpng','25.robots.txt','robots.txt','security.txt','sitemap.xml','/workspace/file.txt','random.file/path'):
   self.assertFalse(any(a.type.value=='domain' for a in extract_artifacts(value)), value)
 def test_domain_validation_preserves_labels_containing_file_words(self):
  from phm.core.artifacts import extract_artifacts
  for value in ('example.com','sub.example.com','binary.example.com','github.example.com','zip.example.com','png.example.com','jpg.example.com'):
   self.assertIn('domain',[a.type.value for a in extract_artifacts(value)], value)
 def test_extracted_png_recursion_has_single_image_analysis(self):
  with tempfile.TemporaryDirectory() as d:
   p=Path(d)/'outer.zip'; self.make_zip(p,{'mystery.bin':PNG})
   report=InvestigationRunner(max_nodes=4,max_seconds=3).run(str(p))
   image_targets=[r.target for r in report.results if r.plugin=='image_analysis']
   self.assertEqual(len(image_targets),1)
   self.assertNotIn('mystery.binpk', [n['value'] for n in report.metadata['nodes']])
