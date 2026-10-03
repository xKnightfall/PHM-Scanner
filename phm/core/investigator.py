"""Bounded, passive clue-to-pivot investigation runner."""
from __future__ import annotations
import heapq, time, tempfile
from dataclasses import dataclass
from phm.core.target_resolution import resolve_target
from phm.core.models import Category, InvestigationReport
from phm.core.orchestrator import InvestigationOrchestrator
from phm.core.artifacts import artifacts_from_report
from phm.core.correlation import build_relationship_graph
from phm.core.summary import build_summary
from phm.core.recommendations import build_next_steps

PIVOT_TYPES={'domain','url','ip','email','username','github_repository','github_repo','coordinate','file','image','archive','document'}
WEIGHTS={'github_repository':10,'domain':9,'email':8,'username':8,'url':7,'file':7,'image':7,'archive':7,'ip':5,'coordinate':4,'document':4}

@dataclass
class Lead:
 value:str; source:str; relationship:str; evidence:object; depth:int; analyzer:str='autodetect'
class InvestigationRunner:
 def __init__(self,max_nodes=12,max_depth=4,max_seconds=60,max_workers=4):
  self.max_nodes=max(1,min(max_nodes,100)); self.max_depth=max(0,min(max_depth,20)); self.max_seconds=max(1,min(max_seconds,900)); self.max_workers=max_workers
 def run(self,clue,options=None):
  started=time.monotonic(); queue=[]; sequence=0
  heapq.heappush(queue,(-100,sequence,Lead(clue,'START','starting clue',None,0))); seen=set(); results=[]; nodes=[]; pivots=[]; options=dict(options or {})
  options.setdefault('workspace', tempfile.mkdtemp(prefix='phm-investigation-'))
  weights = WEIGHTS
  while queue and len(nodes)<self.max_nodes and time.monotonic()-started<self.max_seconds:
   _,_,lead=heapq.heappop(queue); value=lead.value.strip(); key=value.casefold()
   if not value or key in seen or lead.depth>self.max_depth: continue
   seen.add(key); resolution=resolve_target(value); nodes.append({'value':value,'type':resolution.target_type,'depth':lead.depth,'source':lead.source,'relationship':lead.relationship})
   if lead.depth: pivots.append({'source':lead.source,'entity':value,'relationship':lead.relationship,'analyzer':resolution.target_type,'evidence':lead.evidence})
   if resolution.use_crypto_engine:
    from phm.crypto_engine import SmartCryptoEngine
    report=SmartCryptoEngine().run(value)
   else:
    report=InvestigationOrchestrator().run(resolution.category,value,plugin_names=resolution.plugins,options=options,max_workers=self.max_workers)
   results.extend(report.results)
   # Materialized local members are first-class leads; they re-enter the same queue.
   for result in report.results:
    for member in result.raw.get('extracted', []) if isinstance(result.raw, dict) else []:
     candidate=str(member.get('path',''))
     if candidate and lead.depth < self.max_depth and candidate.casefold() not in seen:
      sequence+=1; heapq.heappush(queue,(-12,sequence,Lead(candidate,value,f'{value} → archive member {member.get("name")}',member,lead.depth+1)))
   for artifact in artifacts_from_report(report):
    typ=str(artifact.get('type','')); candidate=str(artifact.get('value','')).strip()
    if typ not in PIVOT_TYPES or not candidate or candidate.casefold() in seen or lead.depth>=self.max_depth: continue
    score=weights.get(typ,1); sequence+=1
    child=Lead(candidate,value,f"{value} → {typ}",{'artifact_id':artifact.get('id'),'source_plugin':artifact.get('source_plugin'),'source_evidence':artifact.get('source_evidence')},lead.depth+1)
    heapq.heappush(queue,(-score,sequence,child))
  final=InvestigationReport(target=clue,category=Category.TECHNICAL,results=results,metadata={'investigation':True,'nodes':nodes,'pivots':pivots,'node_count':len(nodes),'max_nodes':self.max_nodes,'max_depth':self.max_depth,'elapsed_seconds':round(time.monotonic()-started,3),'stopped_reason':'time_limit' if time.monotonic()-started>=self.max_seconds else ('node_limit' if len(nodes)>=self.max_nodes else 'no_useful_leads')})
  final.metadata['artifacts']=artifacts_from_report(final); final.metadata['relationship_graph']=build_relationship_graph(final); final.metadata['summary']=build_summary(final); final.metadata['next_steps']=build_next_steps(final)
  return final
