"""Safe, bounded archive inspection and recursive local extraction."""
from __future__ import annotations
import io, zipfile
from pathlib import Path
from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry

@registry.register
class ArchiveAnalysisPlugin(BasePlugin):
 name='archive_analysis'; category=Category.FILE; module='file'; capability='archive_recursive_triage'; consumes=('archive',); produces=('file','string'); description='Inspect local ZIP archives and bounded member contents.'; passive=True; local_first=True; network_required=False; external_tool_required=False
 def detect(self,target):
  p=Path(target.value)
  try:
   return Detection(p.is_file() and zipfile.is_zipfile(p),.98,'local ZIP archive')
  except OSError:return Detection(False,0,'not a readable archive')
 def collect(self,target):
  p=Path(target.value); result={'path':str(p),'entries':[],'extracted':[]}
  with zipfile.ZipFile(p) as z:
   for info in z.infolist()[:100]:
    item={'name':info.filename,'size':info.file_size,'encrypted':bool(info.flag_bits&1)}; result['entries'].append(item)
    if not item['encrypted'] and not info.is_dir() and info.file_size<=2_000_000:
     data=z.read(info); result['extracted'].append({'name':info.filename,'size':len(data),'text':data.decode('utf-8','replace')[:10000]})
  return result
 def analyze(self,target,raw):
  ev=[Evidence(source='archive.entries',value=raw['entries'])]
  for item in raw['extracted']: ev.append(Evidence(source='archive.member',value={'name':item['name'],'text':item['text']}))
  findings=[Finding(title='Archive contents inspected',description=f"Inspected {len(raw['entries'])} archive entries and extracted {len(raw['extracted'])} safe text-sized members for further analysis.",category=self.category,plugin=self.name,confidence=.95,severity=Severity.INFO,evidence=ev,metadata={'recursive_members':raw['extracted']})]
  for member in raw['extracted']:
   findings.append(Finding(title=f"Extracted archive member: {member['name']}",description="This extracted member has been promoted into the investigation evidence and is eligible for artifact and crypto correlation.",category=self.category,plugin=self.name,confidence=.9,severity=Severity.INFO,evidence=[Evidence(source='archive.extracted_text',value=member['text'])],metadata={'recursive':True,'member_name':member['name']}))
  return findings
 def report(self,target,raw,findings,errors=None): return self._result(target,raw,findings,errors)
