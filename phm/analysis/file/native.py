"""Native local file triage primitives."""
from __future__ import annotations
import hashlib, math, re, struct, io, zipfile, tarfile
from pathlib import Path
from typing import Any
from phm.core.artifacts import extract_artifacts
from phm.sources.github.adapter import scan_text_for_secrets

SIGS=[("PNG image","image",b'\x89PNG\r\n\x1a\n','image/png',('png',)),("JPEG image","image",b'\xff\xd8\xff','image/jpeg',('jpg','jpeg')),('GIF image','image',b'GIF8','image/gif',('gif',)),('PDF document','document',b'%PDF-','application/pdf',('pdf',)),('ZIP archive','archive',b'PK\x03\x04','application/zip',('zip','jar','docx','xlsx','pptx')),('Empty ZIP archive','archive',b'PK\x05\x06','application/zip',('zip',)),('Gzip archive','archive',b'\x1f\x8b\x08','application/gzip',('gz',)),('ELF binary','binary',b'\x7fELF','application/x-elf',('elf','so')),('DOS/PE executable','binary',b'MZ','application/vnd.microsoft.portable-executable',('exe','dll','sys')),('SQLite database','document',b'SQLite format 3\x00','application/vnd.sqlite3',('sqlite','db'))]
PAT=re.compile(r'(?i)(password|passwd|secret|token|key|credential|config|backup|dump|wallet|id_rsa|\.env)')
SUSP=re.compile(r'(?i)(powershell|cmd\.exe|/bin/sh|curl\s|wget\s|eval\(|base64\s+-d|virtualalloc|writeprocessmemory)')
def _sig(s,o): return {'name':s[0],'artifact_type':s[1],'offset':o,'magic_hex':s[2].hex(),'mime':s[3],'extensions':list(s[4])}
def detect_signatures(data): return [_sig(s,0) for s in SIGS if data.startswith(s[2])]
def detect_embedded_signatures(data,limit=40):
 out=[]
 for s in SIGS:
  pos=data.find(s[2],1)
  while pos>=0 and len(out)<limit: out.append(_sig(s,pos)); pos=data.find(s[2],pos+1)
 return sorted(out,key=lambda x:x['offset'])
def extension_matches(path, signatures):
 if not signatures or not path.suffix:return None
 return path.suffix.lower().lstrip('.') in signatures[0]['extensions']
def file_hashes(data): return {'md5':hashlib.md5(data).hexdigest(),'sha1':hashlib.sha1(data).hexdigest(),'sha256':hashlib.sha256(data).hexdigest()}
def shannon_entropy(data):
 if not data:return 0.0
 counts=[data.count(bytes([i])) for i in range(256)]; n=len(data)
 return round(-sum((c/n)*math.log2(c/n) for c in counts if c),4)
def extract_strings(data,min_length=4,max_strings=300):
 out=[]; seen=set()
 def add(x):
  x=x.strip('\x00')
  if len(x)>=min_length and x not in seen: seen.add(x); out.append(x)
  return len(out)>=max_strings
 for endian in ('ascii','utf-16-le','utf-16-be'):
  text=data.decode(endian,errors='ignore') if endian=='ascii' else data.decode(endian,errors='ignore')
  for x in re.findall(r'[\x20-\x7e\t]{%d,}'%min_length,text):
   if add(x): return out
 return out[:max_strings]
def _bit_plane(data, bit, limit=4096):
 bits=[]
 for byte in data[:limit*8]: bits.append(str((byte >> bit) & 1))
 raw=bytes(int(''.join(bits[i:i+8]),2) for i in range(0,len(bits)-7,8))
 return raw

def image_triage(data, signatures):
 if not signatures or signatures[0]['artifact_type']!='image': return {}
 result={}
 if data.startswith(b'\x89PNG'):
  chunks=[]; pos=8; iend_end=None
  while pos+12<=len(data):
   n=struct.unpack('>I',data[pos:pos+4])[0]; typ=data[pos+4:pos+8]; end=pos+12+n
   if end>len(data): break
   chunks.append({'type':typ.decode('latin1'),'length':n})
   pos=end
   if typ==b'IEND': iend_end=pos; break
  result={'format':'PNG','chunks':chunks,'trailing_data':len(data)-(iend_end or len(data)),'text_chunks':[c['type'] for c in chunks if c['type'] in ('tEXt','zTXt','iTXt')]}
 # These are candidates, not proof: PNG decompression/filter reconstruction is intentionally separate.
 result['bit_plane_candidates']=[{'plane':bit,'printable_ratio':round(sum(32<=b<127 or b in (9,10,13) for b in _bit_plane(data,bit))/max(1,len(_bit_plane(data,bit))),3)} for bit in range(8)]
 return result
def archive_triage(data,signatures,path):
 if not signatures or signatures[0]['artifact_type']!='archive': return {}
 out={'format':signatures[0]['name'],'entries':[],'encrypted':False}
 try:
  with zipfile.ZipFile(io.BytesIO(data)) as z:
   out['entries']=[{'name':i.filename,'size':i.file_size,'compressed_size':i.compress_size} for i in z.infolist()[:200]]
   out['encrypted']=any(i.flag_bits & 1 for i in z.infolist())
 except (zipfile.BadZipFile, OSError): pass
 return out
def analyze_file(path,max_strings=300):
 p=Path(path); data=p.read_bytes(); sig=detect_signatures(data); strings=extract_strings(data,max_strings=max_strings); joined='\n'.join(strings)
 decoded_candidates=[]
 try:
  from phm.crypto_engine import SmartCryptoEngine
  for value in strings[:40]:
   if len(value)>=8:
    crypto=SmartCryptoEngine(max_depth=4,beam_width=4).run(value)
    decoded_candidates.append(crypto.results[0].raw.get('best',{}) if crypto.results else {})
 except Exception: pass
 arts=extract_artifacts(joined); iocs={}
 for a in arts: iocs.setdefault(a.type.value,[]).append(a.value)
 return {'path':str(p),'name':p.name,'size':len(data),'hashes':file_hashes(data),'entropy':shannon_entropy(data),'signatures':sig,'extension':p.suffix.lower().lstrip('.'),'extension_matches_signature':extension_matches(p,sig),'strings':strings,'decoded_candidates':decoded_candidates[:20],'iocs':iocs,'embedded_signatures':detect_embedded_signatures(data),'embedded_archives':[x for x in detect_embedded_signatures(data) if x['artifact_type']=='archive'],'embedded_executables':[x for x in detect_embedded_signatures(data) if x['artifact_type']=='binary'],'image_info':image_triage(data,sig),'archive_info':archive_triage(data,sig,p),'potential_secrets':scan_text_for_secrets(joined,str(p),max_findings=25),'language_hints':[],'interesting_filename':bool(PAT.search(p.name)),'suspicious_patterns':[{'pattern':m.group(0),'string':s[:180]} for s in strings if (m:=SUSP.search(s))],'binary_info':{}}
