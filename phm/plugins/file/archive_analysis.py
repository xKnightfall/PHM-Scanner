"""Safe, bounded ZIP inspection and workspace materialization."""
from __future__ import annotations
import hashlib, os, zipfile
from pathlib import Path
from phm.core.models import Category, Detection, Evidence, Finding, Severity
from phm.core.plugin import BasePlugin
from phm.core.registry import registry

@registry.register
class ArchiveAnalysisPlugin(BasePlugin):
 name='archive_analysis'; category=Category.FILE; module='file'; capability='archive_recursive_triage'; consumes=('archive',); produces=('file','string'); description='Inspect ZIP archives and bounded member contents.'; passive=True; local_first=True; network_required=False; external_tool_required=False
 def detect(self,target):
  p=Path(target.value)
  try:return Detection(p.is_file() and zipfile.is_zipfile(p),.98,'local ZIP archive')
  except OSError:return Detection(False,0,'not a readable archive')
 def collect(self,target):
  p=Path(target.value); root=Path(target.options.get('workspace','')) / 'artifacts'; result={'path':str(p),'entries':[],'extracted':[],'errors':[],'extracted_bytes':0}
  try:
   with zipfile.ZipFile(p) as z:
    for info in z.infolist()[:100]:
     item={'name':info.filename,'size':info.file_size,'encrypted':bool(info.flag_bits&1)}; result['entries'].append(item)
     if item['encrypted'] or info.is_dir() or info.file_size>2_000_000 or result['extracted_bytes']+info.file_size>10_000_000: continue
     try:
      data=z.read(info); digest=hashlib.sha256(data).hexdigest()[:16]; safe=Path(info.filename).name or 'member'; directory=root/digest; directory.mkdir(parents=True,exist_ok=True); out=directory/safe; out.write_bytes(data)
      result['extracted_bytes']+=len(data); result['extracted'].append({'name':info.filename,'path':str(out),'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'text':data.decode('utf-8','replace')[:10000]})
     except Exception as exc: result['errors'].append({'name':info.filename,'error':str(exc)})
  except Exception as exc: result['errors'].append({'archive':str(exc)})
  return result
 def analyze(self,target,raw):
  ev=[Evidence(source='archive.entries',value=raw['entries'])]
  for item in raw['extracted']: ev.append(Evidence(source='archive.member',value={'name':item['name'],'path':item['path'],'sha256':item['sha256']}))
  findings=[Finding(title='Archive contents inspected',description=f"Inspected {len(raw['entries'])} archive entries and materialized {len(raw['extracted'])} bounded members.",category=self.category,plugin=self.name,confidence=.95,severity=Severity.INFO,evidence=ev,metadata={'recursive_members':raw['extracted'],'extraction_errors':raw['errors']})]
  for member in raw['extracted']: findings.append(Finding(title=f"Extracted archive member: {member['name']}",description='Materialized as a safe local investigation target.',category=self.category,plugin=self.name,confidence=.9,severity=Severity.INFO,evidence=[Evidence(source='archive.extracted_path',value=member['path'])],metadata={'recursive':True,'member':member}))
  return findings
 def report(self,target,raw,findings,errors=None): return self._result(target,raw,findings,errors)
