"""Image-specific triage entry point."""
from pathlib import Path
from phm.analysis.file.native import analyze_file
from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry
from phm.plugins.file.file_analysis import FileAnalysisPlugin
@registry.register
class ImageAnalysisPlugin(FileAnalysisPlugin):
 name='image_analysis'; category=Category.FILE; module='file'; capability='image_steganography_triage'; description='Image chunks, trailing data, and bit-plane candidates.'
 def detect(self,target):
  p=Path(target.value)
  if not p.is_file(): return Detection(False,0,'not a local image')
  try:
   raw=analyze_file(p,max_strings=10); ok=bool(raw.get('signatures') and raw['signatures'][0].get('artifact_type')=='image')
   return Detection(ok,.97 if ok else 0,'image signature')
  except OSError:return Detection(False,0,'unreadable image')
 def collect(self,target): return analyze_file(target.value,max_strings=int(target.options.get('max_strings',200)))
 def analyze(self,target,raw):
  findings=[]
  info=raw.get('image_info',{})
  if info.get('trailing_data',0)>0:
   findings.append(self._finding('Trailing data after image end',f"{info['trailing_data']} bytes follow the PNG IEND chunk and may contain an appended artifact.",target,[Evidence(source='image.trailing_data',value=info['trailing_data'])],Severity.MEDIUM))
  if info.get('text_chunks'):
   findings.append(self._finding('PNG text chunks found','PNG metadata text chunks are available for inspection.',target,[Evidence(source='image.text_chunks',value=info['text_chunks'])],Severity.INFO))
  candidates=[x for x in info.get('bit_plane_candidates',[]) if x.get('printable_ratio',0)>=.6]
  if candidates: findings.append(self._finding('Bit-plane data candidate','One or more image bit planes contain an unusually printable byte stream.',target,[Evidence(source='image.bit_plane_candidates',value=candidates)],Severity.LOW))
  return findings or [self._finding('Image-specific triage','No image-specific hidden-data indicators were identified.',target,[],Severity.INFO)]
 def _finding(self,title,description,target,evidence,severity):
  return Finding(title=title,description=description,category=self.category,plugin=self.name,confidence=.9,severity=severity,evidence=evidence,metadata={'specialized':'image'})
