"""Bounded, passive clue-to-pivot investigation runner."""
from __future__ import annotations
from collections import deque
from phm.core.autodetect import plan_analysis
from phm.core.models import Category, InvestigationReport
from phm.core.orchestrator import InvestigationOrchestrator
from phm.core.artifacts import artifacts_from_report
from phm.core.correlation import build_relationship_graph
from phm.core.summary import build_summary
from phm.core.recommendations import build_next_steps

PIVOT_TYPES={'domain','url','ip','email','username','github_repository','coordinate','file','image','archive','document'}
class InvestigationRunner:
 def __init__(self,max_nodes=12,max_workers=4): self.max_nodes=max(1,min(max_nodes,50)); self.max_workers=max_workers
 def run(self,clue,options=None):
  queue=deque([clue]); seen=set(); results=[]; nodes=[]; options=options or {}
  while queue and len(nodes)<self.max_nodes:
   value=queue.popleft().strip(); key=value.casefold()
   if not value or key in seen: continue
   seen.add(key); plan=plan_analysis(value); nodes.append({'value':value,'type':plan.target_type})
   selected=plan.plugins
   report=InvestigationOrchestrator().run(plan.category,value,plugin_names=selected,options=options,max_workers=self.max_workers) if not plan.use_crypto_engine else __import__('phm.crypto_engine',fromlist=['SmartCryptoEngine']).SmartCryptoEngine().run(value)
   results.extend(report.results)
   for artifact in artifacts_from_report(report):
    if artifact.get('type') in PIVOT_TYPES and str(artifact.get('value','')).casefold() not in seen and len(queue)<self.max_nodes*3:
     queue.append(str(artifact.get('value')))
  final=InvestigationReport(target=clue,category=Category.TECHNICAL,results=results,metadata={'investigation':True,'nodes':nodes,'node_count':len(nodes),'max_nodes':self.max_nodes})
  final.metadata['artifacts']=artifacts_from_report(final); final.metadata['relationship_graph']=build_relationship_graph(final); final.metadata['summary']=build_summary(final); final.metadata['next_steps']=build_next_steps(final)
  return final
