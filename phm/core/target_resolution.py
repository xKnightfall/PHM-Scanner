"""Canonical target resolution shared by direct and recursive analysis."""
from __future__ import annotations
from pathlib import Path
from dataclasses import dataclass
import ipaddress, urllib.parse
from phm.core.autodetect import plan_analysis
from phm.core.models import Category
from phm.analysis.file.native import detect_signatures

@dataclass(frozen=True)
class TargetResolution:
 value: str; target_type: str; category: Category; plugins: list[str]|None; use_crypto_engine: bool; local_file: bool; specialized: str|None; confidence: float=0.0; reason: str=""; alternatives: list[dict]=None

def resolve_target(value: str | Path) -> TargetResolution:
 value=str(value)
 plan=plan_analysis(value)
 plugins=plan.plugins
 specialized=None
 path=Path(value)
 if path.is_file():
  suffix=path.suffix.lower()
  try:
   signature=detect_signatures(path.read_bytes()[:64])
   detected=signature[0]['name'] if signature else ''
  except OSError: detected=''
  if suffix in {'.png','.jpg','.jpeg','.gif','.webp'} or detected in {'PNG image','JPEG image','GIF image'}:
   specialized='image'; plugins=['file_analysis','image_analysis']
  elif suffix in {'.zip','.jar','.gz','.bz2','.xz','.7z','.rar'}:
   specialized='archive'; plugins=['file_analysis','archive_analysis']
  else: specialized='file'; plugins=['file_analysis']
  return TargetResolution(value,'file',Category.FILE,plugins,False,True,specialized,plan.confidence,plan.reason,plan.alternatives)
 if plan.target_type == 'url':
  host=urllib.parse.urlsplit(value).hostname or ''
  try: local=host.lower() == 'localhost' or ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback or ipaddress.ip_address(host).is_link_local
  except ValueError: local=False
  if local: plugins=['technology_fingerprint']
 elif plan.target_type == 'ip_address':
  try:
   if ipaddress.ip_address(value).is_private or ipaddress.ip_address(value).is_loopback or ipaddress.ip_address(value).is_link_local: plugins=[]
  except ValueError: pass
 return TargetResolution(value,plan.target_type,plan.category,plugins,plan.use_crypto_engine,False,specialized,plan.confidence,plan.reason,plan.alternatives)
