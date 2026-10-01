#!/usr/bin/env python3
"""Synthetic tests for Analyze.py and NmapImport.py.
No PowerShell is executed and no network target is contacted.
"""
import copy, csv, hashlib, importlib.util, json, subprocess, sys, tempfile, unittest
from pathlib import Path

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('analyzer',HERE/'Analyze.py'); a=importlib.util.module_from_spec(spec); spec.loader.exec_module(a)
_pcs=importlib.util.spec_from_file_location('patchcheck',HERE.parent/'Extensions'/'PatchCheck.py')
pc=importlib.util.module_from_spec(_pcs); _pcs.loader.exec_module(pc)
_scs=importlib.util.spec_from_file_location('softwarecheck',HERE.parent/'Extensions'/'SoftwareCheck.py')
sc=importlib.util.module_from_spec(_scs); _scs.loader.exec_module(sc)


def source(identity,data=None,status='Collected'):
    data=[] if data is None else data
    return {'id':identity,'status':status,'data':data,'note':'SYNTHETIC','error':None,'returned_count':len(data),'retained_count':len(data)}


def base_rule(**kw):
    r={'id':'T1','title':'Synthetic','source':'smbserver','field':'RequireSecuritySignature','type':'bool','expected':True}
    r.update(kw);return r

class RuleTests(unittest.TestCase):
    def eval(self,data,status='Collected',**kw):
        return a.evaluate_rule(base_rule(**kw),{'smbserver':source('smbserver',data,status)},'A','S','Host.A.json','0'*64,'2026-09-20T00:00:00+00:00')
    def test_pass(self): self.assertEqual(self.eval([{'RequireSecuritySignature':True}])['result'],'Pass')
    def test_fail(self): self.assertEqual(self.eval([{'RequireSecuritySignature':False}])['result'],'Fail')
    def test_missing(self): self.assertEqual(self.eval([{}])['result'],'Unknown')
    def test_error(self): self.assertEqual(self.eval([],status='Error')['result'],'Error')
    def test_unsupported(self): self.assertEqual(self.eval([],status='Unsupported')['result'],'Not tested')
    def test_partial(self): self.assertEqual(self.eval([{'RequireSecuritySignature':True}],status='Partial')['result'],'Unknown')
    def test_na(self): self.assertEqual(self.eval([],status='NotApplicable')['result'],'Not applicable')
    def test_duplicate(self): self.assertEqual(self.eval([{'RequireSecuritySignature':True}]*2)['result'],'Unknown')
    def test_enum(self): self.assertEqual(self.eval([{'RequireSecuritySignature':'True'}],type='enum_bool')['result'],'Pass')
    def test_int_not_bool(self): self.assertEqual(self.eval([{'RequireSecuritySignature':True}],type='int',expected=1)['result'],'Unknown')
    def test_gate_disabled(self): self.assertEqual(self.eval([{'Enabled':0}],field='X',type='int',expected=1,gate={'field':'Enabled','enabled':1,'disabled':0})['result'],'Not applicable')
    def test_gate_ambiguous(self): self.assertEqual(self.eval([{'Enabled':2}],field='X',type='int',expected=1,gate={'field':'Enabled','enabled':1,'disabled':0})['result'],'Unknown')
    def test_no_severity(self): self.assertEqual(self.eval([{'RequireSecuritySignature':False}])['severity'],'Not assigned')
    def test_rules_load(self):
        # A count assertion breaks every time a rule is added and proves nothing.
        # What matters is that the shipped profile loads, validates, and that no
        # rule id repeats.
        doc=a.load_rules(HERE/'Rules.json')
        ids=[r['id'] for r in doc['rules']]
        self.assertGreaterEqual(len(ids),9)
        self.assertEqual(len(ids),len(set(ids)))
        self.assertTrue(all(r.get('source') in a.SOURCE_IDS for r in doc['rules']))

    # -- absent values are only interpreted when the rule says what they mean --
    def test_absent_without_declaration_is_unknown(self):
        self.assertEqual(self.eval([{'RequireSecuritySignature':None}])['result'],'Unknown')
    def test_absent_declared_fail(self):
        r=self.eval([{'RequireSecuritySignature':None}],
                    absent_means={'result':'Fail','interpretation':'Default applies and it is unsafe.'})
        self.assertEqual(r['result'],'Fail')
        self.assertIn('Default applies',r['technical_interpretation'])
    def test_absent_declared_pass(self):
        self.assertEqual(self.eval([{'RequireSecuritySignature':None}],
                         absent_means={'result':'Pass','interpretation':'Safe modern default.'})['result'],'Pass')

    # -- accepted-value set --
    def test_int_any_match(self):
        self.assertEqual(self.eval([{'RequireSecuritySignature':2}],type='int_any',expected=[1,2])['result'],'Pass')
    def test_int_any_no_match(self):
        self.assertEqual(self.eval([{'RequireSecuritySignature':0}],type='int_any',expected=[1,2])['result'],'Fail')

    # -- thresholds, including numeric text such as net accounts output --
    def test_numeric_max_pass(self):
        self.assertEqual(self.eval([{'RequireSecuritySignature':4}],type='numeric_max',expected=4)['result'],'Pass')
    def test_numeric_max_fail(self):
        self.assertEqual(self.eval([{'RequireSecuritySignature':10}],type='numeric_max',expected=4)['result'],'Fail')
    def test_numeric_min_text(self):
        self.assertEqual(self.eval([{'RequireSecuritySignature':'14'}],type='numeric_min',expected=14)['result'],'Pass')
    def test_numeric_min_text_fail(self):
        self.assertEqual(self.eval([{'RequireSecuritySignature':'0'}],type='numeric_min',expected=14)['result'],'Fail')
    def test_numeric_between_rejects_zero(self):
        # A lockout threshold of 0 disables lockout entirely and must not pass a
        # rule whose acceptable range starts at 1.
        self.assertEqual(self.eval([{'RequireSecuritySignature':'0'}],type='numeric_between',expected=[1,5])['result'],'Fail')
    def test_numeric_between_pass(self):
        self.assertEqual(self.eval([{'RequireSecuritySignature':'5'}],type='numeric_between',expected=[1,5])['result'],'Pass')
    def test_numeric_rejects_non_numeric(self):
        self.assertEqual(self.eval([{'RequireSecuritySignature':'None'}],type='numeric_max',expected=4)['result'],'Unknown')
    def test_numeric_rejects_bool(self):
        # True must never be read as 1 in a threshold comparison.
        self.assertEqual(self.eval([{'RequireSecuritySignature':True}],type='numeric_max',expected=4)['result'],'Unknown')

class BatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.scope={'schema_version':'1.0','engagement_id':'SYNTHETIC','approved_for_lab':True,'targets':[
            {'asset_id':'A','site_id':'LAB','computer_name':'A','enabled':True},{'asset_id':'B','site_id':'LAB','computer_name':'B','enabled':True}]}
        self.write('Scope.json',self.scope)
        self.batch={'schema_version':'1.0','tool_version':'0.6','evidence_kind':'CollectionBatch','batch_id':'B1','engagement_id':'SYNTHETIC',
                    'scope_sha256':a.sha256(self.root/'Scope.json'),'collector_sha256':'0'*64,'completed_utc':'2026-09-20T00:00:02+00:00','targets':[]}
        self.raw={'schema_version':'1.0','tool_version':'0.6','evidence_kind':'WindowsCollection','asset_id':'A','site_id':'LAB','engagement_id':'SYNTHETIC',
                  'scope_sha256':self.batch['scope_sha256'],'collector_sha256':'0'*64,'collection_status':'Complete',
                  'started_utc':'2026-09-20T00:00:00.1234567Z','completed_utc':'2026-09-20T00:00:01.7654321Z',
                  'host':{'computer_name':'A','domain_role':2,'is_domain_controller':False},
                  'sources':[source(i) for i in sorted(a.SOURCE_IDS)]}
        self.rules={'schema_version':'1.0','profile_id':'SYN','rules':[base_rule()]}
        self.save()
    def tearDown(self): self.tmp.cleanup()
    def write(self,name,obj): (self.root/name).write_text(json.dumps(obj),encoding='utf-8')
    def save(self):
        self.write('Host.A.json',self.raw)
        self.batch['targets']=[{'asset_id':'A','site_id':'LAB','computer_name':'A','status':'Complete','evidence_file':'Host.A.json','evidence_sha256':a.sha256(self.root/'Host.A.json')},
                               {'asset_id':'B','site_id':'LAB','computer_name':'B','status':'NotAttempted','error':None}]
        self.write('Batch.json',self.batch)
    def analyze_fixture(self): return a.analyze_batch(self.root,self.rules)
    def test_missing_asset_visible(self): self.assertEqual(self.analyze_fixture()[0][1]['status'],'NotAttempted')
    def test_wrong_version_rejected(self): self.raw['tool_version']='9';self.save();self.assertEqual(self.analyze_fixture()[0][0]['status'],'EvidenceRejected')
    def test_wrong_host_rejected(self): self.raw['host']['computer_name']='X';self.save();self.assertEqual(self.analyze_fixture()[0][0]['status'],'EvidenceRejected')
    def test_digest_rejected(self): self.batch['targets'][0]['evidence_sha256']='1'*64;self.write('Batch.json',self.batch);self.assertEqual(self.analyze_fixture()[0][0]['status'],'EvidenceRejected')
    def test_duplicate_source(self): self.raw['sources'].append(copy.deepcopy(self.raw['sources'][0]));self.save();self.assertEqual(self.analyze_fixture()[0][0]['status'],'EvidenceRejected')
    def test_unknown_source(self): self.raw['sources'].append(source('BAD'));self.save();self.assertEqual(self.analyze_fixture()[0][0]['status'],'EvidenceRejected')
    def test_truncated_source_partial(self): self.raw['sources'][0]['status']='Partial';self.save();self.assertEqual(self.analyze_fixture()[0][0]['status'],'Partial')
    def test_missing_required_source_partial(self):
        # Removing a CORE source must downgrade the batch. Popping the last entry
        # relied on alphabetical order and silently stopped testing anything once
        # optional sources were added, so name the source explicitly.
        self.raw['sources']=[s for s in self.raw['sources'] if s['id']!='firewall']
        self.save();self.assertEqual(self.analyze_fixture()[0][0]['status'],'Partial')
    def test_missing_optional_source_still_complete(self):
        # An optional source that a host cannot produce must not rewrite history by
        # marking previously complete evidence as Partial.
        self.raw['sources']=[s for s in self.raw['sources'] if s['id']!='wdigest']
        self.save();self.assertEqual(self.analyze_fixture()[0][0]['status'],'Complete')
    def test_directory_na_accepted_off_domain(self):
        for s in self.raw['sources']:
            if s['id'] in a.DIRECTORY_SOURCE_IDS: s['status']='NotApplicable'
        self.save();self.assertEqual(self.analyze_fixture()[0][0]['status'],'Complete')
    def test_bad_time(self): self.raw['started_utc']='bad';self.save();self.assertEqual(self.analyze_fixture()[0][0]['status'],'EvidenceRejected')
    def test_end_before_start(self): self.raw['completed_utc']='2026-09-19T00:00:00+00:00';self.save();self.assertEqual(self.analyze_fixture()[0][0]['status'],'EvidenceRejected')
    def test_dc_local_sam_rejected(self): self.raw['host'].update(domain_role=5,is_domain_controller=True);self.save();self.assertEqual(self.analyze_fixture()[0][0]['status'],'EvidenceRejected')
    def test_dc_na_accepted(self):
        self.raw['host'].update(domain_role=5,is_domain_controller=True)
        for s in self.raw['sources']:
            if s['id'] in ('localadmins','localguest'):s.update(status='NotApplicable',data=[],returned_count=0,retained_count=0)
        self.save();self.assertEqual(self.analyze_fixture()[0][0]['status'],'Complete')
    def test_duplicate_json_keys(self):
        (self.root/'D.json').write_text('{"a":1,"a":2}')
        with self.assertRaises(ValueError):a.read_json(self.root/'D.json')
    def test_csv_guard(self):
        for v in ('=1','+1','-1','@x','  =2','\t=3'): self.assertTrue(a.csv_safe(v).startswith("'"))
    def test_rule_test_created(self): self.assertEqual(self.analyze_fixture()[1][0]['phase'],'host_configuration')
    def test_evidence_hash_on_test(self): self.assertEqual(len(self.analyze_fixture()[1][0]['evidence_sha256']),64)
    def test_unfinished_batch_visible(self): self.batch['completed_utc']=None;self.write('Batch.json',self.batch);self.assertFalse(self.analyze_fixture()[2]['batch_completed'])

class ExtraEvidence(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()
    def write(self,name,obj): p=self.root/name;p.write_text(json.dumps(obj),encoding='utf-8');return p
    def test_network_expected_reachable(self):
        p=self.write('n.json',{'schema_version':'1.0','tool_version':'0.6','evidence_kind':'NetworkObservations','engagement_id':'E','started_utc':'2026-09-20T00:00:00+00:00','completed_utc':'2026-09-20T00:00:01+00:00','source_asset_id':'S','source_site_id':'LAB','source_context':'VP','results':[{'test_id':'N1','target_ip':'10.0.0.2','port':445,'expected':'Reachable','connected':True,'local_endpoint':'10.0.0.1:1','elapsed_ms':1,'error':None,'timestamp_utc':'2026-09-20T00:00:01+00:00'}]})
        self.assertEqual(a.import_network(p,'E')[0][0]['result'],'Pass')
    def test_network_unexpected_reachable(self):
        p=self.write('n.json',{'schema_version':'1.0','tool_version':'0.6','evidence_kind':'NetworkObservations','engagement_id':'E','started_utc':'2026-09-20T00:00:00+00:00','completed_utc':'2026-09-20T00:00:01+00:00','source_asset_id':'S','source_context':'VP','results':[{'test_id':'N1','target_ip':'10.0.0.2','port':445,'expected':'Blocked','connected':True,'timestamp_utc':'2026-09-20T00:00:01+00:00'}]})
        self.assertEqual(a.import_network(p,'E')[0][0]['result'],'Fail')
    def test_network_no_connect_inconclusive(self):
        p=self.write('n.json',{'schema_version':'1.0','tool_version':'0.6','evidence_kind':'NetworkObservations','engagement_id':'E','started_utc':'2026-09-20T00:00:00+00:00','completed_utc':'2026-09-20T00:00:01+00:00','source_asset_id':'S','source_context':'VP','results':[{'test_id':'N1','target_ip':'10.0.0.2','port':445,'expected':'Blocked','connected':False,'error':'timeout','timestamp_utc':'2026-09-20T00:00:01+00:00'}]})
        self.assertEqual(a.import_network(p,'E')[0][0]['result'],'Inconclusive')
    def test_update_candidates(self):
        p=self.write('u.json',{'schema_version':'1.0','tool_version':'0.6','evidence_kind':'WuaOfflineUpdateApplicability','engagement_id':'E','site_id':'LAB','asset_id':'W11','computer_name':'W11','completed_utc':'2026-09-20T00:00:00+00:00','cab_sha256':'0'*64,'updates':[{'Title':'Synthetic KB','KBArticleIDs':['1'],'MsrcSeverity':'Important','UpdateID':'x','RevisionNumber':1}]})
        tests,_=a.import_updates(p,'E');self.assertEqual(tests[1]['result'],'Candidate')
    def test_nmap_observation(self):
        p=self.write('m.json',{'schema_version':'1.0','tool_version':'0.6','evidence_kind':'NmapObservations','engagement_id':'E','source_asset_id':'S','source_position':'VP','observations':[{'address':'10.0.0.2','protocol':'tcp','port':445,'state':'open'}]})
        self.assertEqual(a.import_nmap(p,'E')[0][0]['result'],'Observation')
    def test_manual_validation_merge(self):
        evidence=self.root/'shot.txt'; evidence.write_text('synthetic independent check',encoding='utf-8')
        digest=hashlib.sha256(evidence.read_bytes()).hexdigest()
        p=self.root/'Manual.csv'
        p.write_text('test_id,verification_status,verification_method,verification_observed,evidence_file,evidence_sha256,reviewer,notes\n'
                     f'T,Verified,Independent command,Enabled,shot.txt,{digest},Reviewer,Matched\n',encoding='utf-8')
        tests=[a.make_test(test_id='T',phase='host_configuration',category='x',objective='o',method='m')]
        artifacts=a.merge_manual(p,tests)
        self.assertEqual(tests[0]['manual_validation']['status'],'Verified')
        self.assertEqual(tests[0]['manual_validation']['evidence_sha256'],digest)
        self.assertEqual(artifacts[0]['records'],1)
        self.assertTrue(any(x.get('kind')=='ManualEvidence' for x in artifacts))
    def test_manual_validation_bad_hash_rejected(self):
        evidence=self.root/'shot.txt'; evidence.write_text('synthetic independent check',encoding='utf-8')
        p=self.root/'Manual.csv'
        p.write_text('test_id,verification_status,verification_method,verification_observed,evidence_file,evidence_sha256,reviewer,notes\n'
                     f'T,Verified,Independent command,Enabled,shot.txt,{"0"*64},Reviewer,Matched\n',encoding='utf-8')
        tests=[a.make_test(test_id='T',phase='host_configuration',category='x',objective='o',method='m')]
        with self.assertRaises(ValueError): a.merge_manual(p,tests)
    def test_hardeningkitty_normalized_import(self):
        p=self.write('hk.json',{'schema_version':'1.0','tool_version':'0.6','evidence_kind':'HardeningKittyAudit','engagement_id':'E','asset_id':'A','site_id':'LAB','profile':'SYN','normalized_utc':'2026-09-20T00:00:00+00:00','results':[{'id':'101','category':'Synthetic','name':'Synthetic setting','source_severity':'High','observed':'0','recommended':'1','test_result':'Failed'}]})
        tests,_=a.import_hardeningkitty(p,'E')
        self.assertEqual(tests[0]['result'],'Fail'); self.assertEqual(tests[0]['severity'],'Not assigned')

class NmapImport(unittest.TestCase):
    def test_importer(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);xml=root/'n.xml';out=root/'n.json'
            xml.write_text('<?xml version="1.0"?><nmaprun version="7.99" args="nmap -sT"><host><status state="up"/><address addr="10.0.0.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds" product="Microsoft Windows"/><script id="ignored" output="x"/></port></ports></host><runstats><finished timestr="x"/></runstats></nmaprun>')
            completed=subprocess.run([sys.executable,str(HERE.parent/'Extensions'/'NmapImport.py'),'--input',str(xml),'--output',str(out),'--engagement','E','--source-id','S','--source-position','VP'],capture_output=True,text=True)
            self.assertEqual(completed.returncode,0,completed.stderr)
            d=json.loads(out.read_text());self.assertEqual(len(d['observations']),1);self.assertEqual(d['ignored_nse_script_results'],1)

class PlanningAndImporterTests(unittest.TestCase):
    def test_plan_valid_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); inv=root/'AssetInventory.csv'; out=root/'plan'
            fields=['asset_id','site','zone','hostname','fqdn','ip','os','role','domain','management_platform','execution_method','evidence_return','credential_profile','in_scope','criticality','owner','notes']
            with inv.open('w',encoding='utf-8-sig',newline='') as f:
                w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerow({'asset_id':'A','site':'LAB','zone':'USER','hostname':'PC1','fqdn':'pc1.example.local','ip':'10.0.0.10','os':'Windows 11','role':'Workstation','domain':'example.local','management_platform':'ConfigMgr','execution_method':'ExistingManagement','evidence_return':'ManagementPlatform','credential_profile':'CLIENT-MGMT','in_scope':'true','criticality':'Normal','owner':'IT','notes':''})
            c=subprocess.run([sys.executable,str(HERE/'Plan.py'),'--inventory',str(inv),'--output',str(out),'--engagement','E'],capture_output=True,text=True)
            self.assertEqual(c.returncode,0,c.stderr); d=json.loads((out/'ExecutionPlan.json').read_text()); self.assertEqual(d['assets_in_scope'],1); self.assertEqual(d['unresolved_assets'],[])
    def test_plan_unresolved_inventory(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); inv=root/'AssetInventory.csv'; out=root/'plan'
            fields=['asset_id','site','zone','hostname','fqdn','ip','os','role','domain','management_platform','execution_method','evidence_return','credential_profile','in_scope','criticality','owner','notes']
            with inv.open('w',encoding='utf-8-sig',newline='') as f:
                w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerow({'asset_id':'A','site':'LAB','zone':'USER','hostname':'PC1','fqdn':'','ip':'10.0.0.10','os':'Windows 11','role':'Workstation','domain':'','management_platform':'','execution_method':'','evidence_return':'','credential_profile':'','in_scope':'true','criticality':'Normal','owner':'IT','notes':''})
            c=subprocess.run([sys.executable,str(HERE/'Plan.py'),'--inventory',str(inv),'--output',str(out),'--engagement','E'],capture_output=True,text=True)
            self.assertEqual(c.returncode,3); d=json.loads((out/'ExecutionPlan.json').read_text()); self.assertEqual(d['unresolved_assets'],['A'])
    def test_hardeningkitty_csv_importer(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/'hk.csv'; out=root/'hk.json'
            source.write_text('ID,Category,Name,Severity,Result,Recommended,TestResult,SeverityFinding\n101,Test,Setting,High,0,1,Failed,High\n',encoding='utf-8')
            c=subprocess.run([sys.executable,str(HERE.parent/'Extensions'/'HardeningKittyImport.py'),'--input',str(source),'--output',str(out),'--engagement','E','--asset-id','A','--site-id','LAB','--profile','SYN'],capture_output=True,text=True)
            self.assertEqual(c.returncode,0,c.stderr); d=json.loads(out.read_text()); self.assertEqual(d['results'][0]['test_result'],'Failed')
    def test_cim_importer(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/'cim.json'; out=root/'cim-normalized.json'
            source.write_text(json.dumps({'schema_version':'1.0','tool_version':'0.6','evidence_kind':'AgentlessCimSubset','computer_name':'SERVER1','authentication':'Kerberos','use_ssl':False,'timestamp_utc':'2026-09-20T00:00:00+00:00','sources':[{'id':'identity','status':'Collected','data':[{'Caption':'Windows'}],'error':None,'limitation':'subset'},{'id':'local_accounts','status':'NotImplemented','data':[],'error':None,'limitation':'not implemented'}]}),encoding='utf-8')
            c=subprocess.run([sys.executable,str(HERE.parent/'Extensions'/'CimImport.py'),'--input',str(source),'--output',str(out),'--engagement','E','--asset-id','A','--site-id','LAB','--source-position','MGMT'],capture_output=True,text=True)
            self.assertEqual(c.returncode,0,c.stderr); d=json.loads(out.read_text()); self.assertEqual(d['evidence_kind'],'CimObservations'); self.assertEqual(len(d['observations']),2)
            tests,_=a.import_cim(out,'E'); self.assertEqual(tests[0]['result'],'Observation'); self.assertEqual(tests[1]['result'],'Not tested')



# Product matching decides which vendor data is applied to a host. A wrong match
# produces confident findings for software the host does not run, so each of the
# five platforms we support is pinned, along with the cases that must NOT match.
PRODUCTS = {
    "20438": "Windows 11 Version 25H2 for x64-based Systems",
    "20439": "Windows 11 Version 24H2 for x64-based Systems",
    "20440": "Windows 11 Version 24H2 for ARM64-based Systems",
    "19041": "Windows 10 Version 22H2 for x64-based Systems",
    "11923": "Windows Server 2022",
    "11924": "Windows Server 2022 (Server Core installation)",
    "11571": "Windows Server 2019",
    "10816": "Windows Server 2016",
    "21759": "Microsoft SQL Server 2022 for x64-based Systems (CU 26)",
    "12039": "Microsoft Exchange Server 2016 Cumulative Update 23",
    "11961": "Microsoft SharePoint Server Subscription Edition",
    "12079-20438": "Microsoft .NET Framework 3.5 on Windows 11 Version 25H2 for x64-based Systems",
}


class ProductMatchTests(unittest.TestCase):
    def first(self, caption, release, arch, install=None):
        m = pc.match_product(PRODUCTS, caption, release, arch, install)
        return m[0][1] if m else None

    def test_win11_client(self):
        self.assertEqual(self.first("Microsoft Windows 11 Home", "25H2", "64-bit", "Client"),
                         "Windows 11 Version 25H2 for x64-based Systems")
    def test_win11_arm(self):
        self.assertEqual(self.first("Microsoft Windows 11 Pro", "24H2", "ARM64", "Client"),
                         "Windows 11 Version 24H2 for ARM64-based Systems")
    def test_win10_client(self):
        self.assertEqual(self.first("Microsoft Windows 10 Pro", "22H2", "64-bit", "Client"),
                         "Windows 10 Version 22H2 for x64-based Systems")
    def test_server_2022(self):
        self.assertEqual(self.first("Microsoft Windows Server 2022 Standard Evaluation", None, "64-bit", "Server"),
                         "Windows Server 2022")
    def test_server_2019(self):
        self.assertEqual(self.first("Microsoft Windows Server 2019 Datacenter", None, "64-bit", "Server"),
                         "Windows Server 2019")
    def test_server_2016(self):
        self.assertEqual(self.first("Microsoft Windows Server 2016 Standard", None, "64-bit", "Server"),
                         "Windows Server 2016")
    def test_server_core_is_a_different_product(self):
        self.assertEqual(self.first("Microsoft Windows Server 2022 Datacenter", None, "64-bit", "Server Core"),
                         "Windows Server 2022 (Server Core installation)")

    # --- the cases that must never match ---
    def test_windows_server_is_not_sql_server(self):
        # "Microsoft SQL Server 2022" contains "server 2022". Matching it would
        # report SQL Server vulnerabilities against a Windows host.
        self.assertNotIn("SQL", self.first("Microsoft Windows Server 2022 Standard", None, "64-bit", "Server") or "")
    def test_exchange_and_sharepoint_excluded(self):
        for caption in ("Microsoft Windows Server 2016 Standard",):
            got = self.first(caption, None, "64-bit", "Server") or ""
            self.assertNotIn("Exchange", got)
            self.assertNotIn("SharePoint", got)
    def test_unknown_client_release_does_not_guess(self):
        # Without a readable release there is no way to know which product applies.
        self.assertIsNone(self.first("Microsoft Windows 10 Enterprise", None, "64-bit", "Client"))
    def test_non_windows_os_no_match(self):
        self.assertIsNone(self.first("Ubuntu 22.04", None, "64-bit", None))
    def test_component_products_excluded(self):
        # Sub-component products carry a compound id and are not the OS itself.
        got = self.first("Microsoft Windows 11 Home", "25H2", "64-bit", "Client")
        self.assertNotIn(".NET Framework", got)

    # --- build comparison ---
    def test_build_tuple_rejects_text(self):
        self.assertIsNone(pc._build_tuple("10.0.26200.abc"))
    def test_build_tuple_parses(self):
        self.assertEqual(pc._build_tuple("10.0.26200.9457"), (10, 0, 26200, 9457))
    def test_build_tuple_none(self):
        self.assertIsNone(pc._build_tuple(None))


class SoftwareCheckTests(unittest.TestCase):
    def _assess(self, inv):
        return {i['name']: i['risk_type'] for i in sc.assess(inv, set())}
    def item(self, name, version, publisher=None):
        return {'Name':name,'Version':version,'Publisher':publisher}
    def test_parse_version(self):
        self.assertEqual(sc.parse_version('120.0.6099.109'),(120,0,6099,109))
        self.assertEqual(sc.parse_version('1.1.1w'),(1,1,1))
        self.assertIsNone(sc.parse_version('unknown'))
        self.assertIsNone(sc.parse_version(''))
    def test_eol_any_flash(self):
        self.assertEqual(self._assess([self.item('Adobe Flash Player 32 ActiveX','32.0.0.465')]).get('Adobe Flash Player 32 ActiveX'),'EndOfLife')
    def test_eol_python2(self):
        self.assertEqual(self._assess([self.item('Python 2.7.18','2.7.18150')]).get('Python 2.7.18'),'EndOfLife')
    def test_python3_not_flagged(self):
        self.assertNotIn('Python 3.12.1 (64-bit)', self._assess([self.item('Python 3.12.1 (64-bit)','3.12.1150.0')]))
    def test_java8_eol(self):
        self.assertEqual(self._assess([self.item('Java 8 Update 331','8.0.3310.9')]).get('Java 8 Update 331'),'EndOfLife')
    def test_java17_not_flagged(self):
        self.assertNotIn('Java(TM) SE Development Kit 17.0.2', self._assess([self.item('Java(TM) SE Development Kit 17.0.2','17.0.2')]))
    def test_openssl_1x_eol(self):
        self.assertEqual(self._assess([self.item('OpenSSL 1.1.1w','1.1.1')]).get('OpenSSL 1.1.1w'),'EndOfLife')
    def test_node16_eol(self):
        self.assertEqual(self._assess([self.item('Node.js','16.20.2')]).get('Node.js'),'EndOfLife')
    def test_chrome_below_floor(self):
        self.assertEqual(self._assess([self.item('Google Chrome','90.0.4430.212','Google LLC')]).get('Google Chrome'),'BelowVersionFloor')
    def test_chrome_current_not_flagged(self):
        self.assertNotIn('Google Chrome', self._assess([self.item('Google Chrome','141.0.7000.0','Google LLC')]))
    def test_winrar_below_floor(self):
        self.assertEqual(self._assess([self.item('WinRAR 6.11 (64-bit)','6.11.0')]).get('WinRAR 6.11 (64-bit)'),'BelowVersionFloor')
    def test_publisher_hint_guards_floor(self):
        self.assertNotIn('Google Chrome Wrapper', self._assess([self.item('Google Chrome Wrapper','1.0','Acme Inc')]))
    def test_version_unreadable_not_passed(self):
        self.assertEqual(self._assess([self.item('7-Zip','unknown')]).get('7-Zip'),'VersionUnreadable')
    def test_kb_excluded(self):
        self.assertEqual(self._assess([self.item('Security Update for Windows (KB5001234)','1')]),{})
    def test_vcredist_excluded(self):
        self.assertEqual(self._assess([self.item('Microsoft Visual C++ 2019 X64 Additional Runtime','14.29.30139')]),{})
    def test_kev_tokens_from_cache(self):
        d=tempfile.mkdtemp()
        with open(Path(d)/'cisa_kev.json','w') as fh:
            json.dump({'vulnerabilities':[{'product':'Acrobat Reader','vendorProject':'Adobe'}]}, fh)
        toks=sc._kev_products(d)
        self.assertIn('acrobat', toks)
        self.assertNotIn('adobe', toks)
    def test_missing_inventory_is_unknown(self):
        # assess of empty inventory yields no items; the module reports Unknown at the batch level
        self.assertEqual(self._assess([]),{})


class WirelessImportTests(unittest.TestCase):
    def _w(self, obj):
        f = Path(tempfile.mkdtemp()) / 'ev.json'
        f.write_text(json.dumps(obj), encoding='utf-8')
        return f
    def test_air_classification_to_results(self):
        doc = {'schema_version':'1.0','tool_version':a.VERSION,'evidence_kind':'WirelessAirObservations','engagement_id':'E',
               'observations':[
                   {'essid':'CORP','classification':'RogueOrEvilTwin','open':False,'corporate_essid':True,'wps_enabled':False},
                   {'essid':'CORP','classification':'AuthorizedAP','open':True,'corporate_essid':True,'wps_enabled':False},
                   {'essid':'CORP','classification':'AuthorizedAP','open':False,'corporate_essid':True,'wps_enabled':True},
                   {'essid':'','classification':'Hidden','open':False,'corporate_essid':False,'wps_enabled':False},
                   {'essid':'Cafe','classification':'External','open':False,'corporate_essid':False,'wps_enabled':False}]}
        tests,_ = a.import_wireless_air(self._w(doc),'E')
        self.assertEqual([t['result'] for t in tests], ['Fail','Fail','Fail','Observation','Observation'])
    def test_air_engagement_mismatch_raises(self):
        doc={'schema_version':'1.0','tool_version':a.VERSION,'evidence_kind':'WirelessAirObservations','engagement_id':'X','observations':[]}
        with self.assertRaises(ValueError): a.import_wireless_air(self._w(doc),'E')
    def test_controller_findings(self):
        doc={'schema_version':'1.0','tool_version':a.VERSION,'evidence_kind':'WirelessControllerConfig','engagement_id':'E',
             'controller':{'rogue_detection_enabled':False,'wips_enabled':True},'corporate_vlans':[10],
             'wlans':[
                 {'ssid':'C','purpose':'corporate','security':'wpa2-psk','pmf':'optional','vlan':10,'client_isolation':None},
                 {'ssid':'G','purpose':'guest','security':'open','pmf':'disabled','vlan':10,'client_isolation':False},
                 {'ssid':'S','purpose':'corporate','security':'wpa2-enterprise','pmf':'required','vlan':20,'client_isolation':None}]}
        tests,_=a.import_wireless_controller(self._w(doc),'E')
        by={t['test_id']:t['result'] for t in tests}
        self.assertEqual(by['CTRL.rogue_detection'],'Fail')
        self.assertEqual(by['CTRL.wips'],'Pass')
        self.assertEqual(by['CTRL.1.auth'],'Fail')
        self.assertEqual(by['CTRL.2.open'],'Fail')
        self.assertEqual(by['CTRL.2.isolation'],'Fail')
        self.assertEqual(by['CTRL.2.vlan'],'Fail')
        self.assertEqual(by['CTRL.3.auth'],'Pass')
        self.assertEqual(by['CTRL.3.pmf'],'Pass')
    def test_greenbone_candidate_vs_observation(self):
        doc={'schema_version':'1.0','tool_version':a.VERSION,'evidence_kind':'GreenboneObservations','engagement_id':'E',
             'observations':[
                 {'host':'h1','port':'443/tcp','name':'High vuln','threat':'High','actionable':True},
                 {'host':'h2','port':'445/tcp','name':'Med vuln','threat':'Medium','actionable':True},
                 {'host':'h3','port':'general/tcp','name':'Info','threat':'Log','actionable':False}]}
        tests,_=a.import_greenbone(self._w(doc),'E')
        self.assertEqual(tests[0]['test_id'],'VULN.SCAN')   # scan-level completeness row leads the list
        self.assertEqual([t['result'] for t in tests if t['test_id']!='VULN.SCAN'],['Candidate','Candidate','Observation'])
    def test_greenbone_engagement_mismatch_raises(self):
        doc={'schema_version':'1.0','tool_version':a.VERSION,'evidence_kind':'GreenboneObservations','engagement_id':'X','observations':[]}
        with self.assertRaises(ValueError): a.import_greenbone(self._w(doc),'E')

class Build20260928Tests(unittest.TestCase):
    """Regression tests for the defects found in the September 2026 lab rounds."""
    def test_server_core_prefers_base_product_over_edition_variant(self):
        names=dict(PRODUCTS); names['12244']='Windows Server 2022, 23H2 Edition (Server Core)'
        m=pc.match_product(names,'Microsoft Windows Server 2022 Standard Evaluation','21H2','64-bit','Server Core')
        self.assertEqual(m[0][0],'11924')
    def test_msrc_release_window_is_chronological(self):
        rel=[{'ID':'2026-Apr'},{'ID':'2025-Sep'},{'ID':'2026-Jan'},{'ID':'2026-Sep'}]
        self.assertEqual([r['ID'] for r in sorted(rel,key=pc._release_date)],['2025-Sep','2026-Jan','2026-Apr','2026-Sep'])
    def test_network_expected_blocked_with_live_host_passes(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'n.json'
            p.write_text(json.dumps({'schema_version':'1.0','tool_version':'0.6','evidence_kind':'NetworkObservations','engagement_id':'E','started_utc':'2026-09-20T00:00:00+00:00','completed_utc':'2026-09-20T00:00:01+00:00','source_asset_id':'S','source_context':'VP','results':[{'test_id':'N1','target_ip':'10.0.0.2','port':445,'expected':'Blocked','connected':False,'host_alive':True,'outcome':'ExpectedBlocked','error':'timeout','timestamp_utc':'2026-09-20T00:00:01+00:00'}]}),encoding='utf-8')
            self.assertEqual(a.import_network(p,'E')[0][0]['result'],'Pass')
    def test_network_expected_blocked_dead_host_stays_inconclusive(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'n.json'
            p.write_text(json.dumps({'schema_version':'1.0','tool_version':'0.6','evidence_kind':'NetworkObservations','engagement_id':'E','started_utc':'2026-09-20T00:00:00+00:00','completed_utc':'2026-09-20T00:00:01+00:00','source_asset_id':'S','source_context':'VP','results':[{'test_id':'N1','target_ip':'10.0.0.2','port':445,'expected':'Blocked','connected':False,'host_alive':False,'outcome':'Inconclusive','error':'timeout','timestamp_utc':'2026-09-20T00:00:01+00:00'}]}),encoding='utf-8')
            self.assertEqual(a.import_network(p,'E')[0][0]['result'],'Inconclusive')
    def test_hardeningkitty_csv_with_extra_columns_is_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); source=root/'hk.csv'; out=root/'hk.json'
            source.write_text('ID,Category,Name,Severity,Result,Recommended,TestResult,SeverityFinding,DefaultValue,Filter\n101,Test,Setting,High,0,1,Failed,High,0,\n',encoding='utf-8')
            c=subprocess.run([sys.executable,str(HERE.parent/'Extensions'/'HardeningKittyImport.py'),'--input',str(source),'--output',str(out),'--engagement','E','--asset-id','A','--site-id','LAB','--profile','SYN'],capture_output=True,text=True)
            self.assertEqual(c.returncode,0,c.stderr)
    def test_gate_rule_not_applicable_when_feature_off(self):
        rule={'id':'PRN01','title':'x','source':'pointandprint','field':'RestrictDriverInstallationToAdministrators','type':'int','expected':1,'gate':{'field':'SpoolerRunning','enabled':1,'disabled':0}}
        res=a.evaluate_rule(rule,{'pointandprint':source('pointandprint',[{'SpoolerRunning':0,'RestrictDriverInstallationToAdministrators':None}])},'A','S','Host.A.json','0'*64,'2026-09-20T00:00:00+00:00')
        self.assertEqual(res['result'],'Not applicable')


# ---------------------------------------------------------------------------
# Build 2026-10-01: Greenbone report validation and scan completeness, wireless
# controller/air classification defects, multi-batch metadata, ToFindings
# review queue. Synthetic fixtures only; no network, no PowerShell.
# ---------------------------------------------------------------------------
_EXT=HERE.parent/'Extensions'
_wai_spec=importlib.util.spec_from_file_location('wirelessairimport',_EXT/'WirelessAirImport.py')
wai=importlib.util.module_from_spec(_wai_spec); _wai_spec.loader.exec_module(wai)
_gbi_spec=importlib.util.spec_from_file_location('greenboneimport',_EXT/'GreenboneImport.py')
gbi=importlib.util.module_from_spec(_gbi_spec); _gbi_spec.loader.exec_module(gbi)
_tf_spec=importlib.util.spec_from_file_location('tofindings',_EXT/'ToFindings.py')
tf=importlib.util.module_from_spec(_tf_spec); _tf_spec.loader.exec_module(tf)

_GVM_HEAD=('<?xml version="1.0"?><report id="r1"><report id="r1"><scan_run_status>{status}</scan_run_status>'
           '<task id="t1"><name>Lab scan</name><status>{status}</status><progress>{progress}</progress></task>'
           '<scan_start>2026-10-01T08:00:00Z</scan_start><scan_end>{end}</scan_end>'
           '<hosts><count>3</count></hosts><result_count><full>5</full><filtered>2</filtered></result_count>'
           '<filters><term>apply_overrides=0 min_qod=70</term></filters><results>')
_GVM_TAIL='</results></report></report>'
_GVM_RESULT=('<result id="{rid}"><name>{name}</name><host>10.0.0.{n}<asset asset_id="x"/></host><port>445/tcp</port>'
             '<nvt oid="1.3.6.1.4.1.25623.1.0.{n}"><cvss_base>7.5</cvss_base><refs><ref type="cve" id="CVE-2026-000{n}"/></refs></nvt>'
             '<threat>{threat}</threat><severity>7.5</severity><qod><value>{qod}</value></qod></result>')

def _gvm_xml(status='Done',progress='100',end='2026-10-01T09:00:00Z',results=None):
    results=results if results is not None else [dict(rid='a',name='SMB Vuln',n=1,threat='High',qod='80')]
    body=''.join(_GVM_RESULT.format(**r) for r in results)
    return _GVM_HEAD.format(status=status,progress=progress,end=end)+body+_GVM_TAIL

_AIRODUMP_HEADER=('BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, '
                  '# beacons, # IV, LAN IP, ID-length, ESSID, Key\r\n')
def _airodump_row(bssid,essid,privacy='WPA2',idlen=None):
    idlen=len(essid) if idlen is None else idlen
    return (f'{bssid}, 2026-10-01 08:00:00, 2026-10-01 08:05:00,  6,  54, {privacy}, CCMP, PSK, -40,  100,  0,'
            f'   0.  0.  0.  0,  {idlen}, {essid}, \r\n')
def _airodump_csv(rows):
    return ('\r\n'+_AIRODUMP_HEADER+''.join(rows)+'\r\n'
            'Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs\r\n')


class Build20261001Tests(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()
    def _json(self,name,obj):
        p=self.root/name; p.write_text(json.dumps(obj),encoding='utf-8'); return p
    def _run(self,script,*argv):
        return subprocess.run([sys.executable,str(_EXT/script)]+[str(x) for x in argv],capture_output=True,text=True)
    def _greenbone(self,xml_text,name='r.xml'):
        src=self.root/name; src.write_text(xml_text,encoding='utf-8'); out=self.root/(name+'.json')
        c=self._run('GreenboneImport.py','--input',src,'--output',out,'--engagement','E','--source-position','VP')
        return c,out

    # -- GreenboneImport: defect 1, unrelated XML must not import as zero results --
    def test_greenbone_unrelated_xml_rejected(self):
        c,out=self._greenbone('<?xml version="1.0"?><nmaprun><host><result>x</result></host></nmaprun>')
        self.assertEqual(c.returncode,2,c.stdout)
        self.assertIn('Not a Greenbone/GVM report',c.stderr)
        self.assertFalse(out.exists(),'no output may be written for a rejected document')
    def test_greenbone_report_without_results_or_count_rejected(self):
        c,out=self._greenbone('<?xml version="1.0"?><report id="r1"><task><name>x</name></task></report>')
        self.assertEqual(c.returncode,2); self.assertFalse(out.exists())
    def test_greenbone_get_reports_response_wrapper_accepted(self):
        xml='<?xml version="1.0"?><get_reports_response status="200">'+_gvm_xml()+'</get_reports_response>'
        xml=xml.replace('<?xml version="1.0"?><report','<report',1)
        c,out=self._greenbone(xml)
        self.assertEqual(c.returncode,0,c.stderr); d=json.loads(out.read_text(encoding='utf-8'))
        self.assertEqual(d['result_count'],1)

    # -- defect 2: scan completeness recorded; Running export flagged --
    def test_greenbone_done_scan_records_status_fields(self):
        c,out=self._greenbone(_gvm_xml())
        self.assertEqual(c.returncode,0,c.stderr); d=json.loads(out.read_text(encoding='utf-8'))
        self.assertTrue(d['scan_complete'])
        self.assertEqual(d['scan_run_status'],'Done'); self.assertEqual(d['progress'],'100')
        self.assertEqual(d['task_name'],'Lab scan'); self.assertEqual(d['hosts_count'],'3')
        self.assertEqual(d['result_count_full'],'5'); self.assertEqual(d['result_count_filtered'],'2')
        self.assertEqual(d['filter_text'],'apply_overrides=0 min_qod=70')
        self.assertEqual(d['scan_start'],'2026-10-01T08:00:00Z'); self.assertEqual(d['scan_end'],'2026-10-01T09:00:00Z')
        self.assertFalse(any('before the task completed' in l for l in d['limitations']))
    def test_greenbone_running_scan_sets_scan_complete_false(self):
        c,out=self._greenbone(_gvm_xml(status='Running',progress='42',end=''))
        self.assertEqual(c.returncode,0,c.stderr); d=json.loads(out.read_text(encoding='utf-8'))
        self.assertFalse(d['scan_complete']); self.assertEqual(d['scan_run_status'],'Running')
        self.assertIsNone(d['scan_end'])
        self.assertTrue(any(l=='scan export taken before the task completed; status Running at 42 percent' for l in d['limitations']),d['limitations'])

    # -- defect 3: qod recorded; critical threat is actionable --
    def test_greenbone_qod_recorded_and_critical_actionable(self):
        rows=[dict(rid='a',name='One',n=1,threat='Critical',qod='97'),dict(rid='b',name='Two',n=2,threat='Log',qod='30')]
        c,out=self._greenbone(_gvm_xml(results=rows))
        self.assertEqual(c.returncode,0,c.stderr); d=json.loads(out.read_text(encoding='utf-8'))
        self.assertEqual(d['observations'][0]['qod'],'97'); self.assertTrue(d['observations'][0]['actionable'])
        self.assertEqual(d['observations'][1]['qod'],'30'); self.assertFalse(d['observations'][1]['actionable'])
        self.assertEqual(d['observations'][0]['cves'],['CVE-2026-0001'])

    # -- defect 4: credentialed indicator heuristic --
    def test_greenbone_credentialed_indicator(self):
        self.assertIsNone(gbi.credentialed_indicator(['SMB Vuln','Apache detection']))
        self.assertTrue(gbi.credentialed_indicator(['SMB Log-In Possible','SMB Vuln']))
        self.assertTrue(gbi.credentialed_indicator(['SSH Login Successful For Authenticated Checks']))
        self.assertFalse(gbi.credentialed_indicator(['SSH Login Failed For Authenticated Checks']))
        self.assertFalse(gbi.credentialed_indicator(['SMB Vuln','Could not log in to host']))
        c,out=self._greenbone(_gvm_xml(results=[dict(rid='a',name='Nothing',n=1,threat='Log',qod='80')]))
        d=json.loads(out.read_text(encoding='utf-8')); self.assertIsNone(d['credentialed_indicator'])
        self.assertIn('Heuristic',d['credentialed_indicator_note'])

    # -- defect 5: guest VLAN separation cannot pass when no corporate VLAN is known --
    def test_controller_importer_records_corporate_vlans_known(self):
        intake={'engagement_id':'E','site_id':'LAB','controller':{'rogue_detection_enabled':True,'wips_enabled':True},
                'wlans':[{'ssid':'C','purpose':'corporate','security':'wpa2-enterprise','pmf':'required','vlan':None},
                         {'ssid':'G','purpose':'guest','security':'open','pmf':'disabled','vlan':30,'client_isolation':True}]}
        src=self._json('intake.json',intake); out=self.root/'ctrl.json'
        c=self._run('WirelessControllerImport.py','--input',src,'--output',out,'--engagement','E')
        self.assertEqual(c.returncode,0,c.stderr); d=json.loads(out.read_text(encoding='utf-8'))
        self.assertFalse(d['corporate_vlans_known']); self.assertEqual(d['corporate_vlans'],[])
        tests,_=a.import_wireless_controller(out,'E'); by={t['test_id']:t for t in tests}
        self.assertEqual(by['CTRL.2.vlan']['result'],'Unknown')
        self.assertEqual(by['CTRL.2.vlan']['technical_interpretation'],'no corporate VLAN is recorded, so separation cannot be determined')
        intake['wlans'][0]['vlan']=10; src=self._json('intake2.json',intake); out2=self.root/'ctrl2.json'
        self.assertEqual(self._run('WirelessControllerImport.py','--input',src,'--output',out2,'--engagement','E').returncode,0)
        self.assertTrue(json.loads(out2.read_text(encoding='utf-8'))['corporate_vlans_known'])
        by={t['test_id']:t['result'] for t in a.import_wireless_controller(out2,'E')[0]}
        self.assertEqual(by['CTRL.2.vlan'],'Pass')
    def test_controller_guest_vlan_unknown_when_corporate_unknown_in_analyze(self):
        # Evidence predating the flag: an empty corporate list must not produce Pass either.
        doc={'schema_version':'1.0','tool_version':a.VERSION,'evidence_kind':'WirelessControllerConfig','engagement_id':'E',
             'controller':{'rogue_detection_enabled':True,'wips_enabled':True},'corporate_vlans':[],
             'wlans':[{'ssid':'G','purpose':'guest','security':'wpa2-enterprise','pmf':'required','vlan':30,'client_isolation':True}]}
        by={t['test_id']:t for t in a.import_wireless_controller(self._json('c.json',doc),'E')[0]}
        self.assertEqual(by['CTRL.1.vlan']['result'],'Unknown')
        self.assertNotIn('CTRL.1.guestsec',by)

    # -- defect 6: guest WLAN on a shared key is recorded as an observation --
    def test_controller_guest_psk_observation(self):
        doc={'schema_version':'1.0','tool_version':a.VERSION,'evidence_kind':'WirelessControllerConfig','engagement_id':'E',
             'controller':{'rogue_detection_enabled':True,'wips_enabled':True},'corporate_vlans':[10],'corporate_vlans_known':True,
             'wlans':[{'ssid':'G1','purpose':'guest','security':'wpa2-psk','pmf':'required','vlan':30,'client_isolation':True},
                      {'ssid':'G2','purpose':'guest','security':'wep','pmf':'disabled','vlan':31,'client_isolation':True},
                      {'ssid':'G3','purpose':'guest','security':'open','pmf':'disabled','vlan':32,'client_isolation':True},
                      {'ssid':'C','purpose':'corporate','security':'wpa2-psk','pmf':'required','vlan':10,'client_isolation':None}]}
        by={t['test_id']:t for t in a.import_wireless_controller(self._json('c.json',doc),'E')[0]}
        self.assertEqual(by['CTRL.1.guestsec']['result'],'Observation'); self.assertIn('shared key',by['CTRL.1.guestsec']['objective'])
        self.assertEqual(by['CTRL.1.guestsec']['severity'],'Not assigned')
        self.assertEqual(by['CTRL.2.guestsec']['result'],'Observation')
        self.assertNotIn('CTRL.3.guestsec',by); self.assertNotIn('CTRL.4.guestsec',by)

    # -- defect 7: WPS unknown without wash; null never fails --
    def test_air_wps_null_without_wash_and_no_wps_fail(self):
        csv_text=_airodump_csv([_airodump_row('AA:BB:CC:DD:EE:01','CORP')])
        src=self.root/'air.csv'; src.write_bytes(csv_text.encode('utf-8'))   # bytes: keep airodump's CRLF intact on Windows
        allow=self._json('allow.json',{'corporate_essids':['CORP'],'authorized_bssids':['AA:BB:CC:DD:EE:01']})
        out=self.root/'air.json'
        c=self._run('WirelessAirImport.py','--input',src,'--authorized',allow,'--output',out,'--engagement','E','--source-position','VP')
        self.assertEqual(c.returncode,0,c.stderr); d=json.loads(out.read_text(encoding='utf-8'))
        self.assertIsNone(d['wps_source']); self.assertIsNone(d['observations'][0]['wps_enabled'])
        self.assertEqual(d['observations'][0]['classification'],'AuthorizedAP')
        self.assertTrue(any('wash' in l for l in d['limitations']))
        tests,_=a.import_wireless_air(out,'E')
        self.assertEqual(tests[0]['result'],'Observation'); self.assertNotIn('WPS',tests[0]['objective'])
        # with wash supplied, state is known and a listed BSSID fails
        wash=self.root/'wash.txt'; wash.write_text('BSSID               Ch  dBm  WPS  Lck  Vendor    ESSID\nAA:BB:CC:DD:EE:01    6  -40  2.0  No   Acme      CORP\n',encoding='utf-8')
        out2=self.root/'air2.json'
        c=self._run('WirelessAirImport.py','--input',src,'--authorized',allow,'--wash',wash,'--output',out2,'--engagement','E','--source-position','VP')
        self.assertEqual(c.returncode,0,c.stderr); d2=json.loads(out2.read_text(encoding='utf-8'))
        self.assertEqual(d2['wps_source'],'wash'); self.assertTrue(d2['observations'][0]['wps_enabled'])
        self.assertEqual(a.import_wireless_air(out2,'E')[0][0]['result'],'Fail')
    def test_air_analyze_null_wps_never_fails(self):
        doc={'schema_version':'1.0','tool_version':a.VERSION,'evidence_kind':'WirelessAirObservations','engagement_id':'E',
             'observations':[{'essid':'CORP','classification':'AuthorizedAP','open':False,'corporate_essid':True,'wps_enabled':None}]}
        self.assertEqual(a.import_wireless_air(self._json('w.json',doc),'E')[0][0]['result'],'Observation')

    # -- defect 8: csv parsing keeps an ESSID that contains a comma in one column --
    def test_air_essid_with_comma_parsed(self):
        rows=wai.parse_airodump(_airodump_csv([
            _airodump_row('AA:BB:CC:DD:EE:01','Cafe, Upstairs'),
            _airodump_row('AA:BB:CC:DD:EE:02','"Quoted, Name"',idlen=12),
            _airodump_row('AA:BB:CC:DD:EE:03','Plain')]))
        self.assertEqual(len(rows),3)
        self.assertEqual(rows[0]['ESSID'],'Cafe, Upstairs'); self.assertEqual(rows[0]['Privacy'],'WPA2'); self.assertEqual(rows[0]['Key'],'')
        self.assertEqual(rows[1]['ESSID'],'Quoted, Name'); self.assertEqual(rows[1]['channel'],'6')
        self.assertEqual(rows[2]['ESSID'],'Plain'); self.assertEqual(rows[2]['Power'],'-40')

    # -- defect 9: hidden SSIDs include NUL-only and NUL-prefixed names --
    def test_air_hidden_essid_rules(self):
        self.assertTrue(wai.is_hidden_essid('')); self.assertTrue(wai.is_hidden_essid('\x00\x00\x00'))
        self.assertTrue(wai.is_hidden_essid('\x00abc')); self.assertFalse(wai.is_hidden_essid('CORP'))
        rows=wai.parse_airodump(_airodump_csv([_airodump_row('AA:BB:CC:DD:EE:01','\x00\x00\x00\x00',idlen=4)]))
        self.assertEqual(rows[0]['ESSID'],'\x00\x00\x00\x00')
        src=self.root/'air.csv'; src.write_bytes(_airodump_csv([_airodump_row('AA:BB:CC:DD:EE:01','\x00\x00\x00\x00',idlen=4)]).encode('utf-8'))
        allow=self._json('allow.json',{'corporate_essids':['CORP'],'authorized_bssids':[]}); out=self.root/'air.json'
        c=self._run('WirelessAirImport.py','--input',src,'--authorized',allow,'--output',out,'--engagement','E','--source-position','VP')
        self.assertEqual(c.returncode,0,c.stderr); d=json.loads(out.read_text(encoding='utf-8'))
        self.assertTrue(d['observations'][0]['hidden']); self.assertEqual(d['observations'][0]['classification'],'Hidden'); self.assertEqual(d['observations'][0]['essid'],'')

    # -- defect 10: look-alike ESSID classified and failed; exact rogue keeps allowlist caveat --
    def test_air_lookalike_essid_classified_and_fails(self):
        self.assertEqual(wai.normalise_essid('Corp-WiFi_Guest '),'corpwifiguest')
        src=self.root/'air.csv'
        src.write_bytes(_airodump_csv([_airodump_row('AA:BB:CC:DD:EE:01','Corp WiFi'),_airodump_row('AA:BB:CC:DD:EE:02','corp_wifi'),
                                       _airodump_row('AA:BB:CC:DD:EE:03','Corp WiFi'),_airodump_row('AA:BB:CC:DD:EE:04','Cafe')]).encode('utf-8'))
        allow=self._json('allow.json',{'corporate_essids':['Corp WiFi'],'authorized_bssids':['AA:BB:CC:DD:EE:01']}); out=self.root/'air.json'
        c=self._run('WirelessAirImport.py','--input',src,'--authorized',allow,'--output',out,'--engagement','E','--source-position','VP')
        self.assertEqual(c.returncode,0,c.stderr); d=json.loads(out.read_text(encoding='utf-8'))
        cls=[o['classification'] for o in d['observations']]
        self.assertEqual(cls,['AuthorizedAP','LookalikeEssid','RogueOrEvilTwin','External'])
        self.assertEqual(d['observations'][1]['lookalike_of'],'Corp WiFi'); self.assertFalse(d['observations'][1]['corporate_essid'])
        self.assertIsNone(d['observations'][0]['lookalike_of'])
        tests,_=a.import_wireless_air(out,'E')
        self.assertEqual([t['result'] for t in tests],['Observation','Fail','Fail','Observation'])
        self.assertEqual(tests[1]['objective'],"Access point broadcasting a look-alike of corporate ESSID 'corp_wifi'")
        self.assertIn('allowlist must be complete and current',tests[2]['technical_interpretation'])

    # -- defect 11: multi-batch metadata counts distinct enabled assets over all batches --
    def _batch_dir(self,name,batch_id,targets,evidence_for=()):
        d=self.root/name; d.mkdir()
        scope={'schema_version':'1.0','engagement_id':'SYNTHETIC','approved_for_lab':True,
               'targets':[{'asset_id':t,'site_id':'LAB','computer_name':t,'enabled':en} for t,en in targets]}
        (d/'Scope.json').write_text(json.dumps(scope),encoding='utf-8')
        batch={'schema_version':'1.0','tool_version':'0.6','evidence_kind':'CollectionBatch','batch_id':batch_id,'engagement_id':'SYNTHETIC',
               'scope_sha256':a.sha256(d/'Scope.json'),'collector_sha256':'0'*64,'completed_utc':'2026-10-01T00:00:02+00:00','targets':[]}
        for t,en in targets:
            if t in evidence_for:
                raw={'schema_version':'1.0','tool_version':'0.6','evidence_kind':'WindowsCollection','asset_id':t,'site_id':'LAB','engagement_id':'SYNTHETIC',
                     'scope_sha256':batch['scope_sha256'],'collector_sha256':'0'*64,'collection_status':'Complete',
                     'started_utc':'2026-10-01T00:00:00Z','completed_utc':'2026-10-01T00:00:01Z',
                     'host':{'computer_name':t,'domain_role':2,'is_domain_controller':False},
                     'sources':[source(i,status=('Error' if (t=='C' and i=='wdigest') else 'Collected')) for i in sorted(a.SOURCE_IDS)]}
                (d/f'Host.{t}.json').write_text(json.dumps(raw),encoding='utf-8')
                batch['targets'].append({'asset_id':t,'site_id':'LAB','computer_name':t,'status':'Complete','evidence_file':f'Host.{t}.json','evidence_sha256':a.sha256(d/f'Host.{t}.json')})
            elif en:
                batch['targets'].append({'asset_id':t,'site_id':'LAB','computer_name':t,'status':'NotAttempted','error':None})
        (d/'Batch.json').write_text(json.dumps(batch),encoding='utf-8')
        return d
    def test_multi_batch_enabled_assets_is_distinct_union(self):
        rules={'schema_version':'1.0','profile_id':'SYN','rules':[base_rule()]}
        b1=self._batch_dir('b1','B1',[('A',True),('B',True)],evidence_for=('A',))
        b2=self._batch_dir('b2','B2',[('B',True),('C',True),('D',False)],evidence_for=('C',))
        _,_,m1,_=a.analyze_batch(b1,rules); self.assertEqual(m1['enabled_assets'],2)
        assets,tests,meta,_=a.merge_batches([b1,b2],rules)
        self.assertEqual(meta['enabled_assets'],3)              # A, B, C once each; D is disabled
        self.assertEqual(meta['batch_ids'],['B1','B2']); self.assertEqual(meta['batches'],2); self.assertEqual(meta['batch_id'],'B1,B2')
        self.assertEqual(sorted(x['asset_id'] for x in assets),['A','B','C','D'])
        total=len(a.SOURCE_IDS)
        self.assertEqual(meta['sources_collected_max'],total); self.assertEqual(meta['sources_collected_min'],total-1)
        self.assertEqual(sorted(t['asset_id'] for t in tests),['A','C'])
    def test_single_batch_meta_has_batch_fields_and_source_coverage(self):
        rules={'schema_version':'1.0','profile_id':'SYN','rules':[base_rule()]}
        b1=self._batch_dir('b1','B1',[('A',True),('B',True)])
        _,_,meta,_=a.merge_batches([b1],rules)
        self.assertEqual(meta['enabled_assets'],2); self.assertEqual(meta['batch_ids'],['B1']); self.assertEqual(meta['batches'],1)
        self.assertEqual(meta['batch_id'],'B1'); self.assertIsNone(meta['sources_collected_min']); self.assertIsNone(meta['sources_collected_max'])

    # -- defects 12 and 13: ToFindings review queue, review gaps, non-host assets and control refs --
    def _tests_csv(self,rows):
        d=self.root/'derived'; d.mkdir(exist_ok=True)
        fields=['test_id','phase','category','site_id','asset_id','source_position','objective','method','control_refs','expected','observed','result',
                'technical_interpretation','severity','validation','evidence_file','evidence_pointer','evidence_sha256','timestamp_utc','limitations','reference','manual_validation']
        with (d/'Tests.csv').open('w',encoding='utf-8-sig',newline='') as f:
            w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); w.writeheader()
            for r in rows: w.writerow({k:r.get(k,'') for k in fields})
        return d
    def test_tofindings_review_queue_and_gaps(self):
        rows=[
            {'test_id':'HOST.A.SMB01','category':'smbserver','asset_id':'A','site_id':'LAB','objective':'SMBv1','observed':'True','expected':'False','result':'Fail','control_refs':'Not mapped','evidence_file':'Host.A.json','evidence_sha256':'1'*64},
            {'test_id':'HOST.A.SMB02','category':'smbserver','asset_id':'A','site_id':'LAB','objective':'Signing','observed':'','result':'Unknown','evidence_file':'Host.A.json','evidence_sha256':'1'*64},
            {'test_id':'HOST.A.RDP01','category':'rdp','asset_id':'A','site_id':'LAB','objective':'NLA','observed':'','result':'Error','evidence_file':'Host.A.json','evidence_sha256':'1'*64},
            {'test_id':'HOST.B.SMB02','category':'smbserver','asset_id':'B','site_id':'LAB','objective':'Signing','observed':'','result':'Not tested','evidence_file':'Host.B.json','evidence_sha256':'2'*64},
            {'test_id':'HOST.B.SMB01','category':'smbserver','asset_id':'B','site_id':'LAB','objective':'SMBv1','observed':'False','result':'Pass','evidence_file':'Host.B.json','evidence_sha256':'2'*64},
            {'test_id':'VULN.00001','category':'network_vulnerability','asset_id':'','site_id':'LAB','source_position':'VP','objective':'SMB vuln on 10.0.0.1:445','observed':'{"x":1}','result':'Candidate','control_refs':'NIST SP 800-53 Rev 5 RA-5','evidence_file':'gb.json','evidence_sha256':'3'*64},
            {'test_id':'VULN.00002','category':'network_vulnerability','asset_id':'','site_id':'LAB','source_position':'VP','objective':'Info','observed':'o'*300,'result':'Observation','evidence_file':'gb.json','evidence_sha256':'3'*64},
            {'test_id':'NET.N1','category':'segmentation_reachability','asset_id':'','site_id':'LAB','source_position':'VP','objective':'Reach','observed':'{}','result':'Inconclusive','evidence_file':'n.json','evidence_sha256':'4'*64},
            {'test_id':'AIR.00001','category':'wireless_air','asset_id':'','site_id':'','source_position':'3rd floor','objective':'AP seen','observed':'{}','result':'Observation','evidence_file':'air.json','evidence_sha256':'5'*64},
            {'test_id':'CTRL.1.open','category':'wireless_controller','asset_id':'','site_id':'HQ','source_position':'export','objective':"WLAN 'G' is not an open network",'observed':'{"ssid":"G"}','result':'Fail','control_refs':'NIST SP 800-53 Rev 5 AC-18','evidence_file':'ctrl.json','evidence_sha256':'6'*64},
        ]
        derived=self._tests_csv(rows); out=self.root/'out'
        c=self._run('ToFindings.py','--derived',derived,'--output',out,'--engagement-id','E')
        self.assertEqual(c.returncode,0,c.stderr)
        self.assertIn('Review queue     : 6',c.stdout); self.assertIn('Coverage gaps    : 3',c.stdout)
        d=json.loads((out/'findings.json').read_text(encoding='utf-8'))
        q={e['test_id']:e for e in d['review_queue']}
        self.assertEqual(set(q),{'HOST.A.SMB02','HOST.A.RDP01','HOST.B.SMB02','VULN.00001','VULN.00002','NET.N1'})
        self.assertEqual(d['counts']['review_queue'],6); self.assertEqual(d['counts']['coverage_gaps'],3); self.assertEqual(d['counts']['findings'],2)
        self.assertEqual(q['VULN.00001']['result'],'Candidate'); self.assertEqual(q['VULN.00001']['asset_id'],'LAB')
        self.assertEqual(q['VULN.00001']['evidence_sha256'],'3'*64); self.assertEqual(q['VULN.00001']['category'],'network_vulnerability')
        self.assertLessEqual(len(q['VULN.00002']['observed']),160); self.assertTrue(q['VULN.00002']['observed'].endswith('...'))
        self.assertNotIn('AIR.00001',q)                                   # plain observation outside the scanner category
        gaps={(g['title'],tuple(g['affected_assets'])):g for g in d['coverage_gaps']}
        ga=gaps[('Tests without a determination for this asset',('A',))]; gb=gaps[('Tests without a determination for this asset',('B',))]
        self.assertIn('1 Unknown, 1 Error, 0 Not tested',ga['description']); self.assertIn('0 Unknown, 0 Error, 1 Not tested',gb['description'])
        self.assertEqual(ga['kind'],'CoverageGap'); self.assertEqual(ga['status'],'Not tested')
        gc=gaps[('Candidate results awaiting analyst disposition',())]; self.assertIn('1 Candidate rows in category network_vulnerability',gc['description'])
        self.assertEqual(len({g['id'] for g in d['coverage_gaps']}),3)
        # defect 13: the controller finding is anchored to its site and carries its control reference
        by_rule={f['source_rule']:f for f in d['findings']}
        self.assertEqual(by_rule['open']['affected_assets'],['HQ']); self.assertEqual(by_rule['open']['affected_asset_count'],1)
        self.assertEqual(by_rule['open']['control_refs'],'NIST SP 800-53 Rev 5 AC-18')
        self.assertEqual(by_rule['SMB01']['affected_assets'],['A']); self.assertEqual(by_rule['SMB01']['control_refs'],'Not mapped')
    def test_tofindings_review_queue_empty_when_all_decided(self):
        rows=[{'test_id':'HOST.A.SMB01','category':'smbserver','asset_id':'A','site_id':'LAB','objective':'SMBv1','observed':'False','result':'Pass','evidence_file':'Host.A.json','evidence_sha256':'1'*64}]
        self.assertEqual(tf._review_queue(rows),[]); self.assertEqual(tf._review_gaps(rows,1),[])
    def test_tofindings_non_host_fallback_to_source_position(self):
        rows=[{'test_id':'AIR.00002','category':'wireless_air','asset_id':'','site_id':'','source_position':'3rd floor','objective':'Rogue AP','observed':'{}','result':'Fail','control_refs':'NIST SP 800-53 Rev 5 AC-18','evidence_file':'air.json','evidence_sha256':'5'*64}]
        f=tf._config_findings(rows)[0]
        self.assertEqual(f['affected_assets'],['3rd floor']); self.assertEqual(f['control_refs'],'NIST SP 800-53 Rev 5 AC-18')


# ---------------------------------------------------------------------------
# Build 2026-10-01: PatchCheck.py (defects 1 to 10) and SoftwareCheck.py
# (defects 11 to 14). Synthetic MSRC and host fixtures only; the end-to-end
# runs use --offline against a seeded cache so nothing reaches the network.
# ---------------------------------------------------------------------------
def msrc_doc(products, vulns):
    return {'ProductTree':{'FullProductName':[{'ProductID':k,'Value':v} for k,v in products.items()]},'Vulnerability':vulns}

def vuln(cve, fixes, scores=None):
    """fixes = [(product_id, fixed_build)]; scores = list of CVSSScoreSets entries."""
    return {'CVE':cve,'Title':{'Value':cve},
            'CVSSScoreSets':scores if scores is not None else [{'BaseScore':7.8,'Vector':'V','ProductID':[p for p,_ in fixes]}],
            'Remediations':[{'ProductID':[p],'FixedBuild':fb,'Description':{'Value':'5031356'},'URL':'u','RestartRequired':{'Value':'Yes'}} for p,fb in fixes]}

def host_doc(asset, caption, full_build, release='21H2', arch='64-bit', install='Server'):
    return {'asset_id':asset,'host':{'computer_name':asset,'os_caption':caption,'display_version':release,'architecture':arch,'full_build':full_build},
            'sources':[{'id':'patchlevel','status':'Collected','data':[{'InstallationType':install}]}]}

SERVER_2022 = {'11923':'Windows Server 2022','12244':'Windows Server 2022, 23H2 Edition'}


def sealed_batch(root, hosts, extra_targets=(), tamper=False, ledger=True, scope=True):
    """Write a sealed raw batch (Scope.json + Batch.json) holding the given host
    documents. extra_targets = [(asset_id, enabled, ledger_status_or_None)] adds
    scoped targets without a Host file: a ledger_status of None means no ledger
    entry at all. tamper breaks the first host's recorded digest; ledger=False
    omits Batch.json; scope=False omits Scope.json."""
    root=Path(root)
    targets=[{'asset_id':h['asset_id'],'site_id':'LAB','computer_name':h['asset_id'],'enabled':True} for h in hosts]
    targets+=[{'asset_id':t,'site_id':'LAB','computer_name':t,'enabled':en} for t,en,_ in extra_targets]
    scope_doc={'schema_version':'1.0','engagement_id':'SYNTHETIC','approved_for_lab':True,'targets':targets}
    if scope: (root/'Scope.json').write_text(json.dumps(scope_doc),encoding='utf-8')
    entries=[]
    for h in hosts:
        name='Host.%s.json'%h['asset_id']; (root/name).write_text(json.dumps(h),encoding='utf-8')
        entries.append({'asset_id':h['asset_id'],'site_id':'LAB','computer_name':h['asset_id'],'status':'Complete','evidence_file':name,'evidence_sha256':a.sha256(root/name)})
    for t,en,status in extra_targets:
        if status is not None and en:
            entries.append({'asset_id':t,'site_id':'LAB','computer_name':t,'status':status,'error':'SYNTHETIC: WinRM timeout' if status in ('NotAttempted','Error') else None})
    if tamper: entries[0]['evidence_sha256']='1'*64
    batch={'schema_version':'1.0','tool_version':'0.6','evidence_kind':'CollectionBatch','batch_id':'B1','engagement_id':'SYNTHETIC',
           'scope_sha256':a.sha256(root/'Scope.json') if scope else '0'*64,'collector_sha256':'0'*64,'completed_utc':'2026-10-01T00:00:02+00:00','targets':entries}
    if ledger: (root/'Batch.json').write_text(json.dumps(batch),encoding='utf-8')
    return root


class Build20261001PatchCheckTests(unittest.TestCase):
    """Defects 1 to 10 of the 1 October 2026 review of PatchCheck.py."""
    H2022 = host_doc('A','Microsoft Windows Server 2022 Standard','10.0.20348.1000')

    def assess(self, host, docs, kev_ids=set(), kev_available=True):
        return pc.assess_host(host, docs, kev_ids, kev_available, 'B')

    # 2. same-branch rule
    def test_other_branch_fixedbuild_is_ignored(self):
        doc = msrc_doc(SERVER_2022, [vuln('CVE-1',[('11923','10.0.25398.9999')])])
        self.assertEqual(pc.missing_for_host(doc,'11923',(10,0,20348,1000)),[])
        self.assertEqual(pc.branch_remediations(doc,'11923',(10,0,20348,1000)),(0,1))
    def test_only_other_branch_fixes_yields_unknown_not_clean(self):
        doc = msrc_doc(SERVER_2022, [vuln('CVE-1',[('11923','10.0.25398.9999')])])
        r = self.assess(self.H2022, [('2026-Sep',doc)])
        self.assertEqual(r['status'],'Unknown')
        self.assertEqual(r['product_matched']['product_id'],'11923')
        self.assertTrue(any('different servicing branch' in l for l in r['limitations']))
    def test_same_branch_fix_still_found_next_to_other_branch(self):
        doc = msrc_doc(SERVER_2022, [vuln('CVE-1',[('11923','10.0.25398.9999')]), vuln('CVE-2',[('11923','10.0.20348.2000')])])
        r = self.assess(self.H2022, [('2026-Sep',doc)])
        self.assertEqual(r['status'],'MissingUpdates')
        self.assertEqual([f['cve'] for f in r['missing_updates']],['CVE-2'])

    # 4. Server 2012 R2 compares on (CurrentBuild, UBR) only
    def test_server_2012_r2_lower_ubr_is_missing(self):
        doc = msrc_doc({'10483':'Windows Server 2012 R2'}, [vuln('CVE-1',[('10483','6.3.9600.22500')])])
        self.assertEqual([f['cve'] for f in pc.missing_for_host(doc,'10483',(10,0,9600,22470))],['CVE-1'])
    def test_server_2012_r2_higher_ubr_is_present(self):
        doc = msrc_doc({'10483':'Windows Server 2012 R2'}, [vuln('CVE-1',[('10483','6.3.9600.22400')])])
        self.assertEqual(pc.missing_for_host(doc,'10483',(10,0,9600,22470)),[])
        self.assertEqual(pc.branch_remediations(doc,'10483',(10,0,9600,22470)),(1,0))
    def test_server_2012_r2_end_to_end(self):
        host = host_doc('R2','Microsoft Windows Server 2012 R2 Standard','10.0.9600.22470',release=None)
        doc = msrc_doc({'10483':'Windows Server 2012 R2','10378':'Windows Server 2012'}, [vuln('CVE-1',[('10483','6.3.9600.22500'),('10378','6.2.9200.25000')])])
        r = self.assess(host,[('2026-Sep',doc)])
        self.assertEqual(r['product_matched']['product_id'],'10483')
        self.assertEqual(r['status'],'MissingUpdates')
        self.assertEqual(r['missing_updates'][0]['fixed_build'],'6.3.9600.22500')

    # 3. server match uses display_version
    def test_edition_only_candidate_is_not_selected(self):
        m = pc.match_product({'12244':'Windows Server 2022, 23H2 Edition'},'Microsoft Windows Server 2022 Standard','21H2','64-bit','Server')
        self.assertEqual(m,[])
    def test_edition_matching_display_version_is_preferred(self):
        m = pc.match_product(SERVER_2022,'Microsoft Windows Server 2022 Datacenter','23H2','64-bit','Server')
        self.assertEqual(m[0][0],'12244')
    def test_edition_not_matching_display_version_falls_to_base(self):
        m = pc.match_product(SERVER_2022,'Microsoft Windows Server 2022 Datacenter','21H2','64-bit','Server')
        self.assertEqual([p for p,_ in m],['11923'])
    def test_r2_caption_prefers_r2_product_and_plain_caption_excludes_it(self):
        names={'10483':'Windows Server 2012 R2','10378':'Windows Server 2012'}
        self.assertEqual(pc.match_product(names,'Microsoft Windows Server 2012 R2 Standard',None,'64-bit','Server')[0][0],'10483')
        self.assertEqual([p for p,_ in pc.match_product(names,'Microsoft Windows Server 2012 Standard',None,'64-bit','Server')],['10378'])
    def test_unidentifiable_server_product_is_unknown(self):
        doc = msrc_doc({'12244':'Windows Server 2022, 23H2 Edition'}, [vuln('CVE-1',[('12244','10.0.25398.9999')])])
        r = self.assess(self.H2022,[('2026-Sep',doc)])
        self.assertEqual(r['status'],'Unknown'); self.assertIsNone(r['product_matched'])
        self.assertTrue(any('not be identified unambiguously' in l for l in r['limitations']))

    # 5. product-specific CVSS
    def test_cvss_from_product_specific_set(self):
        scores=[{'BaseScore':5.5,'Vector':'OTHER','ProductID':['99999']},{'BaseScore':9.8,'Vector':'MINE','ProductID':['11923']}]
        doc = msrc_doc(SERVER_2022,[vuln('CVE-1',[('11923','10.0.20348.2000')],scores)])
        f = pc.missing_for_host(doc,'11923',(10,0,20348,1000))[0]
        self.assertEqual((f['cvss_base_score'],f['cvss_vector'],f['cvss_source']),(9.8,'MINE','product'))
    def test_cvss_first_set_only_when_no_set_names_a_product(self):
        scores=[{'BaseScore':6.1,'Vector':'FIRST'},{'BaseScore':8.8,'Vector':'SECOND'}]
        doc = msrc_doc(SERVER_2022,[vuln('CVE-1',[('11923','10.0.20348.2000')],scores)])
        f = pc.missing_for_host(doc,'11923',(10,0,20348,1000))[0]
        self.assertEqual((f['cvss_base_score'],f['cvss_source']),(6.1,'first_set'))
    def test_cvss_none_when_sets_name_other_products_only(self):
        scores=[{'BaseScore':5.5,'Vector':'OTHER','ProductID':['99999']}]
        doc = msrc_doc(SERVER_2022,[vuln('CVE-1',[('11923','10.0.20348.2000')],scores)])
        f = pc.missing_for_host(doc,'11923',(10,0,20348,1000))[0]
        self.assertEqual((f['cvss_base_score'],f['cvss_source']),(None,'none'))

    # 6. architecture spellings
    def test_architecture_64_bit_capital_b(self):
        m = pc.match_product(PRODUCTS,'Microsoft Windows 11 Home','25H2','64-Bit','Client')
        self.assertEqual(m[0][1],'Windows 11 Version 25H2 for x64-based Systems')
    def test_architecture_aliases(self):
        for text,want in (('64 bits','x64'),('x64','x64'),('AMD64','x64'),('32-Bit','32-bit'),('x86','32-bit'),('arm64','ARM64'),('AArch64','ARM64'),('64-bit','x64')):
            self.assertEqual(pc.normalise_arch(text),want,text)
        self.assertEqual(pc.normalise_arch('Itanium'),'Itanium')
        self.assertEqual(pc.match_product(PRODUCTS,'Microsoft Windows 11 Pro','24H2','arm 64','Client')[0][0],'20440')

    # 7. KEV unavailable gives null
    def test_kev_unavailable_gives_null_not_false(self):
        doc = msrc_doc(SERVER_2022,[vuln('CVE-1',[('11923','10.0.20348.2000')])])
        r = self.assess(self.H2022,[('2026-Sep',doc)],kev_ids=None,kev_available=False)
        self.assertIsNone(r['missing_updates'][0]['known_exploited'])
        self.assertEqual(r['counts']['known_exploited'],0)
        self.assertTrue(any('known_exploited is null' in l for l in r['limitations']))
    def test_kev_available_gives_bool(self):
        doc = msrc_doc(SERVER_2022,[vuln('CVE-1',[('11923','10.0.20348.2000')]),vuln('CVE-2',[('11923','10.0.20348.2000')])])
        r = self.assess(self.H2022,[('2026-Sep',doc)],kev_ids={'CVE-1'})
        got={f['cve']:f['known_exploited'] for f in r['missing_updates']}
        self.assertEqual(got,{'CVE-1':True,'CVE-2':False}); self.assertEqual(r['counts']['known_exploited'],1)

    # 8. cache freshness
    def test_cache_sidecar_written_and_stale_offline_flagged(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'msrc_index.json'; p.write_text('{"value": []}',encoding='utf-8')
            data,origin,fetched,stale=pc._cached(td,'msrc_index.json','http://invalid.test/',offline=True)
            self.assertEqual((origin,stale),('cache',False)); self.assertTrue((Path(td)/'msrc_index.json.meta.json').is_file())
            (Path(td)/'msrc_index.json.meta.json').write_text(json.dumps({'fetched_utc':'2026-07-01T00:00:00+00:00'}),encoding='utf-8')
            data,origin,fetched,stale=pc._cached(td,'msrc_index.json','http://invalid.test/',offline=True)
            self.assertTrue(stale); self.assertEqual(fetched.isoformat(),'2026-07-01T00:00:00+00:00')
    def test_stale_cache_is_refetched_when_online(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'msrc_index.json'; p.write_text('{"value": []}',encoding='utf-8')
            (Path(td)/'msrc_index.json.meta.json').write_text(json.dumps({'fetched_utc':'2026-07-01T00:00:00+00:00'}),encoding='utf-8')
            calls=[]; original=pc._fetch
            pc._fetch=lambda url: (calls.append(url) or {'value':[{'ID':'2026-Sep'}]})
            try: data,origin,fetched,stale=pc._cached(td,'msrc_index.json','http://x/',offline=False)
            finally: pc._fetch=original
            self.assertEqual((origin,stale,len(calls)),('network',False,1)); self.assertEqual(data['value'][0]['ID'],'2026-Sep')
            self.assertLess(pc._age_days(fetched),1)

    # 9. fetch failures are caught, never a traceback
    def test_fetch_failure_raises_feed_unavailable(self):
        import urllib.error as ue
        original=pc._fetch
        def boom(url): raise ue.URLError('no route')
        pc._fetch=boom
        try:
            with tempfile.TemporaryDirectory() as td:
                with self.assertRaises(pc.FeedUnavailable) as cm: pc._cached(td,'msrc_index.json','http://x/',offline=False)
                self.assertEqual(cm.exception.name,'msrc_index.json'); self.assertIn('URLError',cm.exception.reason)
        finally: pc._fetch=original
    def test_offline_without_cache_raises_feed_unavailable(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(pc.FeedUnavailable): pc._cached(td,'cisa_kev.json','http://x/',offline=True)

    # 10. integrity gate + 1. every host (end to end, offline, seeded cache)
    def _batch(self, td, hosts, tamper=None, ledger=True):
        return sealed_batch(td, hosts, tamper=bool(tamper), ledger=ledger)
    def _seed(self, td, doc):
        cache=Path(td)/'cache'; cache.mkdir()
        (cache/'msrc_index.json').write_text(json.dumps({'value':[{'ID':'2026-Sep'}]}),encoding='utf-8')
        (cache/'msrc_2026-Sep.json').write_text(json.dumps(doc),encoding='utf-8')
        (cache/'cisa_kev.json').write_text(json.dumps({'vulnerabilities':[{'cveID':'CVE-1'}]}),encoding='utf-8')
        return cache
    def _run(self, root, cache):
        out=root/'out'
        c=subprocess.run([sys.executable,str(HERE.parent/'Extensions'/'PatchCheck.py'),'--batch',str(root),'--output',str(out),'--cache',str(cache),'--offline'],capture_output=True,text=True)
        self.assertNotIn('Traceback',c.stderr)
        return c, json.loads((out/'MissingUpdates.json').read_text(encoding='utf-8'))
    def test_digest_mismatch_is_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=self._batch(td,[self.H2022],tamper=True); cache=self._seed(td,msrc_doc(SERVER_2022,[vuln('CVE-1',[('11923','10.0.20348.2000')])]))
            c,d=self._run(root,cache)
            self.assertEqual(c.returncode,2); self.assertEqual(d['hosts'][0]['status'],'EvidenceRejected'); self.assertEqual(d['status'],'EvidenceRejected')
            self.assertIn('digest mismatch',d['hosts'][0]['rejection_reason']); self.assertEqual(d['hosts'][0]['missing_updates'],[]); self.assertIsNone(d['hosts'][0]['product_matched'])
    def test_missing_ledger_entry_is_evidence_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root=self._batch(td,[self.H2022]); ledger=json.loads((root/'Batch.json').read_text()); ledger['targets']=[]; (root/'Batch.json').write_text(json.dumps(ledger),encoding='utf-8')
            v=pc.verify_hosts(str(root)); self.assertEqual(len(v),1); self.assertIn('no ledger entry',v[0][2])
    def test_missing_batch_json_rejects_every_host(self):
        with tempfile.TemporaryDirectory() as td:
            root=self._batch(td,[self.H2022],ledger=False)
            v=pc.verify_hosts(str(root)); self.assertIn('Batch.json is absent',v[0][2])
    def test_two_host_batch_yields_two_entries(self):
        h2=host_doc('B','Microsoft Windows Server 2022 Standard','10.0.20348.3000')
        with tempfile.TemporaryDirectory() as td:
            root=self._batch(td,[self.H2022,h2]); cache=self._seed(td,msrc_doc(SERVER_2022,[vuln('CVE-1',[('11923','10.0.20348.2000')])]))
            c,d=self._run(root,cache)
            self.assertEqual(c.returncode,1)
            self.assertEqual([(h['asset_id'],h['status']) for h in d['hosts']],[('A','MissingUpdates'),('B','NoMissingUpdates')])
            # first host mirrored at top level for existing consumers
            self.assertEqual(d['asset_id'],'A'); self.assertEqual(d['status'],'MissingUpdates'); self.assertEqual(len(d['missing_updates']),1)
            self.assertTrue(d['kev_available']); self.assertTrue(d['missing_updates'][0]['known_exploited'])
            self.assertIsNotNone(d['feed_fetched_utc']); self.assertEqual(d['feed_age_days'],0)
            self.assertIn('Host              : B',c.stdout)
    def test_feed_failure_writes_unknown_and_exits_2(self):
        with tempfile.TemporaryDirectory() as td:
            root=self._batch(td,[self.H2022]); cache=Path(td)/'cache'; cache.mkdir()   # empty cache + offline = unavailable
            c,d=self._run(root,cache)
            self.assertEqual(c.returncode,2); self.assertEqual(d['hosts'][0]['status'],'Unknown'); self.assertEqual(d['status'],'Unknown')
            self.assertTrue(any('msrc_index.json could not be fetched' in l for l in d['hosts'][0]['limitations']))
            self.assertIn('Vendor data unavailable',c.stdout); self.assertFalse(d['kev_available'])


class Build20261001SoftwareCheckTests(unittest.TestCase):
    """Defects 11 to 14 of the 1 October 2026 review of SoftwareCheck.py."""
    def doc(self, asset, status='Collected', data=None, present=True):
        d={'asset_id':asset,'host':{'computer_name':asset},'sources':[]}
        if present: d['sources'].append({'id':'software','status':status,'data':[] if data is None else data})
        return d
    def test_error_status_is_unknown(self):
        r=sc.assess_host(self.doc('A','Error',[{'Name':'Google Chrome','Version':'90.0','Publisher':'Google LLC'}]),set(),None,'B')
        self.assertEqual(r['status'],'Unknown'); self.assertEqual(r['items'],[])
        self.assertTrue(any('software inventory was not collected' in l for l in r['limitations']))
    def test_absent_source_is_unknown(self):
        r=sc.assess_host(self.doc('A',present=False),set(),None,'B')
        self.assertEqual(r['status'],'Unknown'); self.assertTrue(any('software inventory was not collected' in l for l in r['limitations']))
    def test_collected_empty_inventory_is_clean(self):
        r=sc.assess_host(self.doc('A'),set(),None,'B')
        self.assertEqual(r['status'],'NoRiskySoftwareFound'); self.assertEqual(r['counts']['inventory_size'],0)
    def test_partial_status_adds_limitation(self):
        r=sc.assess_host(self.doc('A','Partial',[]),set(),None,'B')
        self.assertEqual(r['status'],'NoRiskySoftwareFound'); self.assertTrue(any('partially collected' in l for l in r['limitations']))
    def test_quickbooks_and_thinkbook_not_excluded_kb_number_is(self):
        self.assertFalse(sc._excluded('quickbooks desktop pro 2023')); self.assertFalse(sc._excluded('lenovo thinkbook utility'))
        self.assertTrue(sc._excluded('security update for windows (kb5031356)')); self.assertTrue(sc._excluded('kb5031356'))
        self.assertFalse(sc._excluded('kb123'))   # too short to be a KB article
        self.assertTrue(sc._excluded('microsoft visual c++ 2019 x64 minimum runtime'))
        self.assertFalse(sc._excluded('hotfixer pro'))   # word boundary
        got={i['name']:i['risk_type'] for i in sc.assess([{'Name':'Lenovo ThinkBook Utility','Version':'1.0'},{'Name':'Update for Windows (KB5031356)','Version':'1'}],{'thinkbook'})}
        self.assertEqual(got,{'Lenovo ThinkBook Utility':'KevProductPresent'})
    def test_two_hosts_catalog_warning_and_unknown_top_level(self):
        with tempfile.TemporaryDirectory() as td:
            root=sealed_batch(td,[self.doc('A','Error'),self.doc('B','Collected',[{'Name':'WinRAR 6.11 (64-bit)','Version':'6.11.0'}])])
            out=root/'out'
            c=subprocess.run([sys.executable,str(HERE.parent/'Extensions'/'SoftwareCheck.py'),'--batch',str(root),'--output',str(out),'--no-kev'],capture_output=True,text=True)
            self.assertNotIn('Traceback',c.stderr); self.assertEqual(c.returncode,1)
            d=json.loads((out/'SoftwareRisk.json').read_text(encoding='utf-8'))
            self.assertEqual([(h['asset_id'],h['status']) for h in d['hosts']],[('A','Unknown'),('B','RiskySoftware')])
            self.assertEqual(d['status'],'Unknown'); self.assertEqual(d['asset_id'],'A')
            self.assertIn('curated snapshot',d['catalog_warning']); self.assertEqual(d['hosts'][1]['items'][0]['risk_type'],'BelowVersionFloor')


# ---------------------------------------------------------------------------
# Build 2026-10-01 RC2: shared input/coverage contract (C1), patch finding
# semantics (C3), importer completeness (C4), analyst dispositions and sealing
# (C5). Synthetic fixtures only; PatchCheck runs offline against a seeded cache.
# ---------------------------------------------------------------------------
_eg_spec=importlib.util.spec_from_file_location('evidencegate',HERE/'EvidenceGate.py')
eg=importlib.util.module_from_spec(_eg_spec); _eg_spec.loader.exec_module(eg)
_sd_spec=importlib.util.spec_from_file_location('sealderived',HERE/'SealDerived.py')
sd=importlib.util.module_from_spec(_sd_spec); _sd_spec.loader.exec_module(sd)


class Build20261001RC2Tests(unittest.TestCase):
    def setUp(self): self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()
    def _dir(self,name):
        d=self.root/name; d.mkdir(); return d
    def _json(self,name,obj):
        p=self.root/name; p.write_text(json.dumps(obj),encoding='utf-8'); return p
    def _run(self,script,*argv):
        return subprocess.run([sys.executable,str(HERE.parent/script)]+[str(x) for x in argv],capture_output=True,text=True)
    def _raw(self,asset,error_source=None):
        return {'schema_version':'1.0','tool_version':'0.6','evidence_kind':'WindowsCollection','asset_id':asset,'site_id':'LAB','engagement_id':'SYNTHETIC',
                'scope_sha256':'','collector_sha256':'0'*64,'collection_status':'Complete',
                'started_utc':'2026-10-01T00:00:00Z','completed_utc':'2026-10-01T00:00:01Z',
                'host':{'computer_name':asset,'domain_role':2,'is_domain_controller':False},
                'sources':[source(i,status=('Error' if i==error_source else 'Collected')) for i in sorted(a.SOURCE_IDS)]}
    def _analyze_batch(self,name,targets,evidence_for=(),error_source=None):
        """A sealed batch for Analyze: targets=[(asset, enabled, ledger_status)], Host files for evidence_for."""
        d=self._dir(name)
        scope={'schema_version':'1.0','engagement_id':'SYNTHETIC','approved_for_lab':True,
               'targets':[{'asset_id':t,'site_id':'LAB','computer_name':t,'enabled':en} for t,en,_ in targets]}
        (d/'Scope.json').write_text(json.dumps(scope),encoding='utf-8')
        batch={'schema_version':'1.0','tool_version':'0.6','evidence_kind':'CollectionBatch','batch_id':'B1','engagement_id':'SYNTHETIC',
               'scope_sha256':a.sha256(d/'Scope.json'),'collector_sha256':'0'*64,'completed_utc':'2026-10-01T00:00:02+00:00','targets':[]}
        for t,en,status in targets:
            if t in evidence_for:
                raw=self._raw(t,error_source if t==evidence_for[-1] else None); raw['scope_sha256']=batch['scope_sha256']
                (d/f'Host.{t}.json').write_text(json.dumps(raw),encoding='utf-8')
                batch['targets'].append({'asset_id':t,'site_id':'LAB','computer_name':t,'status':'Complete','evidence_file':f'Host.{t}.json','evidence_sha256':a.sha256(d/f'Host.{t}.json')})
            elif status is not None:
                batch['targets'].append({'asset_id':t,'site_id':'LAB','computer_name':t,'status':status,'error':'SYNTHETIC: WinRM timeout'})
        (d/'Batch.json').write_text(json.dumps(batch),encoding='utf-8')
        return d
    def _derived(self,batch_dir,rules=None,extra=()):
        rules=rules or {'schema_version':'1.0','profile_id':'SYN','rules':[base_rule()]}
        rr=self._json('rules.json',rules); out=self.root/('derived_'+batch_dir.name)
        c=self._run('Code/Analyze.py','--batch',batch_dir,'--rules',rr,'--output',out,*extra)
        self.assertTrue((out/'Coverage.csv').exists(),c.stderr); return out
    def _tests_csv(self,name,rows):
        d=self._dir(name)
        fields=['test_id','phase','category','site_id','asset_id','source_position','objective','method','control_refs','expected','observed','result',
                'technical_interpretation','severity','validation','evidence_file','evidence_pointer','evidence_sha256','timestamp_utc','limitations','reference','manual_validation']
        with (d/'Tests.csv').open('w',encoding='utf-8-sig',newline='') as f:
            w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore'); w.writeheader()
            for r in rows: w.writerow({k:r.get(k,'') for k in fields})
        return d
    def _seed(self,doc):
        cache=self._dir('cache')
        (cache/'msrc_index.json').write_text(json.dumps({'value':[{'ID':'2026-Sep'}]}),encoding='utf-8')
        (cache/'msrc_2026-Sep.json').write_text(json.dumps(doc),encoding='utf-8')
        (cache/'cisa_kev.json').write_text(json.dumps({'vulnerabilities':[{'cveID':'CVE-1'}]}),encoding='utf-8')
        return cache
    def _patch_block(self,**over):
        block={'asset_id':'A','computer_name':'A','os_caption':'SYNTHETIC Windows','observed_build':'10.0.20348.1','full_build':'10.0.20348.1',
               'counts':{'critical_9_plus':1,'high_7_plus':0},'kev_available':True,'feed_fetched_utc':'2026-09-30T06:00:00+00:00','limitations':[],
               'missing_updates':[{'cve':'CVE-2099-0001','kb':'1','fixed_build':'10.0.20348.2','cvss_base_score':9.8,'cvss_vector':'V','known_exploited':False},
                                  {'cve':'CVE-2099-0002','kb':'2','fixed_build':'10.0.20348.3','cvss_base_score':5.5,'cvss_vector':'V','known_exploited':False},
                                  {'cve':'CVE-2099-0003','kb':'3','fixed_build':'10.0.26100.9','cvss_base_score':7.5,'cvss_vector':'V','known_exploited':False}]}
        block.update(over); return block

    # -- 1. EvidenceGate.verify_batch is the shared contract --
    def test_gate_accounts_for_every_scoped_target(self):
        d=self._analyze_batch('b',[('A',True,None),('B',True,'NotAttempted'),('C',False,None),('D',True,None)],evidence_for=('A',))
        g=eg.verify_batch(d)
        self.assertEqual((g['engagement_id'],g['batch_id']),('SYNTHETIC','B1')); self.assertEqual(len(g['scope_sha256']),64)
        self.assertEqual([t['asset_id'] for t in g['targets']],['A','B','C','D']); self.assertEqual(set(g['ledger']),{'A','B'})
        by={h['asset_id']:h for h in g['hosts']}
        self.assertEqual((by['A']['status'],by['A']['digest_ok'],by['A']['evidence_file']),('Complete',True,'Host.A.json'))
        self.assertEqual((by['B']['status'],by['B']['digest_ok']),('NotAttempted',None)); self.assertIn('WinRM timeout',by['B']['reason'])
        self.assertEqual(by['C']['status'],'Excluded'); self.assertIn('approved scope',by['C']['reason'])
        self.assertEqual(by['D']['status'],'NotAttempted'); self.assertIn('No ledger entry',by['D']['reason'])
    def test_gate_digest_mismatch_is_rejected(self):
        d=self._analyze_batch('b',[('A',True,None)],evidence_for=('A',))
        ledger=json.loads((d/'Batch.json').read_text()); ledger['targets'][0]['evidence_sha256']='1'*64; (d/'Batch.json').write_text(json.dumps(ledger),encoding='utf-8')
        h=eg.verify_batch(d)['hosts'][0]
        self.assertEqual((h['status'],h['digest_ok']),('EvidenceRejected',False)); self.assertIn('digest mismatch',h['reason'])
    def test_gate_missing_batch_or_scope_raises(self):
        d=self._analyze_batch('b',[('A',True,None)],evidence_for=('A',))
        (d/'Batch.json').unlink()
        with self.assertRaises(ValueError) as cm: eg.verify_batch(d)
        self.assertIn('Batch.json is absent',str(cm.exception))
        d2=self._analyze_batch('b2',[('A',True,None)],evidence_for=('A',)); (d2/'Scope.json').unlink()
        with self.assertRaises(ValueError) as cm: eg.verify_batch(d2)
        self.assertIn('Scope.json is absent',str(cm.exception))
        with self.assertRaises(ValueError): eg.verify_batch(self.root/'nope')
    def test_gate_rejects_the_same_ledger_faults_as_analyze(self):
        d=self._analyze_batch('b',[('A',True,None)],evidence_for=('A',))
        ledger=json.loads((d/'Batch.json').read_text()); ledger['targets'][0]['site_id']='OTHER'; (d/'Batch.json').write_text(json.dumps(ledger),encoding='utf-8')
        with self.assertRaises(ValueError) as cm: eg.verify_batch(d)
        self.assertIn('identity mismatch',str(cm.exception))
        with self.assertRaises(ValueError): a.analyze_batch(d,{'schema_version':'1.0','profile_id':'SYN','rules':[base_rule()]})
    def test_analyze_patchcheck_softwarecheck_share_the_gate(self):
        # Each module imports EvidenceGate by path and routes its ledger handling through verify_batch.
        for module in (a,pc,sc):
            self.assertTrue(callable(module.EvidenceGate.verify_batch),module.__name__)
        d=self._analyze_batch('b',[('A',True,None),('B',True,'NotAttempted')],evidence_for=('A',))
        assets,_,meta,_=a.analyze_batch(d,{'schema_version':'1.0','profile_id':'SYN','rules':[base_rule()]})
        self.assertEqual([(x['asset_id'],x['status']) for x in assets],[('A','Complete'),('B','NotAttempted')])
        self.assertEqual(meta['enabled_assets'],2)
        original=a.EvidenceGate.verify_batch
        a.EvidenceGate.verify_batch=lambda batch_dir: (_ for _ in ()).throw(ValueError('gate stub'))
        try:
            with self.assertRaises(ValueError) as cm: a.analyze_batch(d,{'schema_version':'1.0','profile_id':'SYN','rules':[base_rule()]})
        finally: a.EvidenceGate.verify_batch=original
        self.assertEqual(str(cm.exception),'gate stub')
        statuses={h['asset_id']:h['status'] for h in pc.gate_hosts(str(d))}
        self.assertEqual(statuses,{'A':'Accepted','B':'NotAttempted'})
        self.assertEqual({h['asset_id']:h['status'] for h in sc.gate_hosts(str(d))},{'A':'Accepted','B':'NotAttempted'})

    # -- 2. PatchCheck and SoftwareCheck account for every enabled target --
    def test_patchcheck_writes_unattempted_and_excluded_targets(self):
        root=sealed_batch(self._dir('b'),[host_doc('A','Microsoft Windows Server 2022 Standard','10.0.20348.1000')],
                          extra_targets=[('B',True,'NotAttempted'),('C',False,None),('D',True,'Error')])
        cache=self._seed(msrc_doc(SERVER_2022,[vuln('CVE-1',[('11923','10.0.20348.2000')])]))
        out=self.root/'out'
        c=self._run('Extensions/PatchCheck.py','--batch',root,'--output',out,'--cache',cache,'--offline')
        self.assertNotIn('Traceback',c.stderr); self.assertEqual(c.returncode,1)
        d=json.loads((out/'MissingUpdates.json').read_text(encoding='utf-8'))
        self.assertEqual([(h['asset_id'],h['status']) for h in d['hosts']],[('A','MissingUpdates'),('B','NotAttempted'),('C','Excluded'),('D','NotAttempted')])
        self.assertIn('WinRM timeout',d['hosts'][1]['rejection_reason']); self.assertEqual(d['hosts'][3]['ledger_status'],'Error')
        self.assertTrue(any('NOT evidence that the host is patched' in l for l in d['hosts'][1]['limitations']))
        self.assertEqual(d['hosts'][1]['missing_updates'],[]); self.assertIn('Host              : B',c.stdout)
    def test_patchcheck_unattempted_only_exits_2(self):
        root=sealed_batch(self._dir('b'),[],extra_targets=[('B',True,'NotAttempted')])
        cache=self._seed(msrc_doc(SERVER_2022,[])); out=self.root/'out'
        c=self._run('Extensions/PatchCheck.py','--batch',root,'--output',out,'--cache',cache,'--offline')
        self.assertEqual(c.returncode,2,c.stderr); d=json.loads((out/'MissingUpdates.json').read_text(encoding='utf-8'))
        self.assertEqual([(h['asset_id'],h['status']) for h in d['hosts']],[('B','NotAttempted')]); self.assertEqual(d['status'],'NotAttempted')
    def test_patchcheck_refuses_folder_without_scope_and_digest_mismatch_stays_rejected(self):
        root=sealed_batch(self._dir('b'),[host_doc('A','Microsoft Windows Server 2022 Standard','10.0.20348.1000')],scope=False)
        cache=self._seed(msrc_doc(SERVER_2022,[]))
        c=self._run('Extensions/PatchCheck.py','--batch',root,'--output',self.root/'out','--cache',cache,'--offline')
        self.assertNotEqual(c.returncode,0); self.assertIn('Scope.json is absent',c.stderr); self.assertFalse((self.root/'out'/'MissingUpdates.json').exists())
        root2=sealed_batch(self._dir('b2'),[host_doc('A','Microsoft Windows Server 2022 Standard','10.0.20348.1000')],tamper=True)
        c=self._run('Extensions/PatchCheck.py','--batch',root2,'--output',self.root/'out2','--cache',cache,'--offline')
        self.assertEqual(c.returncode,2); d=json.loads((self.root/'out2'/'MissingUpdates.json').read_text(encoding='utf-8'))
        self.assertEqual(d['hosts'][0]['status'],'EvidenceRejected'); self.assertIn('digest mismatch',d['hosts'][0]['rejection_reason'])
    def test_unsealed_host_file_is_rejected_not_hidden_as_unattempted(self):
        root=sealed_batch(self._dir('b'),[host_doc('A','Microsoft Windows Server 2022 Standard','10.0.20348.1000')],extra_targets=[('B',True,'NotAttempted')])
        (root/'Host.B.json').write_text(json.dumps(host_doc('B','Microsoft Windows Server 2022 Standard','10.0.20348.1000')),encoding='utf-8')
        (root/'Host.Z.json').write_text(json.dumps(host_doc('Z','Microsoft Windows Server 2022 Standard','10.0.20348.1000')),encoding='utf-8')
        by={h['asset_id']:h for h in pc.gate_hosts(str(root))}
        self.assertEqual(by['B']['status'],'EvidenceRejected'); self.assertIn('no ledger entry',by['B']['reason']); self.assertIn('not sealed',by['B']['reason'])
        self.assertEqual(by['Z']['status'],'EvidenceRejected'); self.assertIn('not in the approved scope',by['Z']['reason'])
        self.assertEqual({h['asset_id']:h['status'] for h in sc.gate_hosts(str(root))}['B'],'EvidenceRejected')
    def test_softwarecheck_refuses_unsealed_folder_and_accounts_for_targets(self):
        unsealed=self._dir('raw'); (unsealed/'Host.A.json').write_text(json.dumps({'asset_id':'A','host':{'computer_name':'A'},'sources':[{'id':'software','status':'Collected','data':[]}]}),encoding='utf-8')
        c=self._run('Extensions/SoftwareCheck.py','--batch',unsealed,'--output',self.root/'sw','--no-kev')
        self.assertNotEqual(c.returncode,0); self.assertIn('Batch.json is absent',c.stderr); self.assertFalse((self.root/'sw'/'SoftwareRisk.json').exists())
        root=sealed_batch(self._dir('b'),[{'asset_id':'A','host':{'computer_name':'A'},'sources':[{'id':'software','status':'Collected','data':[]}]}],
                          extra_targets=[('B',True,'NotAttempted'),('C',False,None)])
        c=self._run('Extensions/SoftwareCheck.py','--batch',root,'--output',self.root/'sw2','--no-kev')
        self.assertEqual(c.returncode,2,c.stderr); d=json.loads((self.root/'sw2'/'SoftwareRisk.json').read_text(encoding='utf-8'))
        self.assertEqual([(h['asset_id'],h['status']) for h in d['hosts']],[('A','NoRiskySoftwareFound'),('B','NotAttempted'),('C','Excluded')])
        self.assertIn('WinRM timeout',d['hosts'][1]['rejection_reason']); self.assertTrue(any('NOT evidence' in l for l in d['hosts'][1]['limitations']))
        root3=sealed_batch(self._dir('b3'),[{'asset_id':'A','host':{'computer_name':'A'},'sources':[{'id':'software','status':'Collected','data':[]}]}],tamper=True)
        c=self._run('Extensions/SoftwareCheck.py','--batch',root3,'--output',self.root/'sw3','--no-kev')
        self.assertEqual(c.returncode,2); self.assertEqual(json.loads((self.root/'sw3'/'SoftwareRisk.json').read_text(encoding='utf-8'))['hosts'][0]['status'],'EvidenceRejected')

    # -- 3. ToFindings builds asset coverage gaps from Coverage.csv and Evidence.json --
    def test_tofindings_coverage_gaps_for_every_non_complete_asset(self):
        rules={'schema_version':'1.0','profile_id':'SYN','rules':[base_rule(),base_rule(id='T2',source='wdigest',field='UseLogonCredential',type='int',expected=0)]}
        batch=self._analyze_batch('b',[('A',True,None),('B',True,'NotAttempted'),('C',False,None),('D',True,None)],evidence_for=('A','D'),error_source='wdigest')
        derived=self._derived(batch,rules); out=self.root/'draft'
        c=self._run('Extensions/ToFindings.py','--derived',derived,'--output',out,'--engagement-id','SYNTHETIC')
        self.assertEqual(c.returncode,0,c.stderr); f=json.loads((out/'findings.json').read_text(encoding='utf-8'))
        cv={g['asset_id']:g for g in f['coverage_gaps'] if g['id'].startswith('GAP-CV-')}
        self.assertEqual(set(cv),{'B','C','D'})
        self.assertEqual(cv['B']['coverage_status'],'NotAttempted'); self.assertEqual(cv['B']['affected_assets'],['B']); self.assertIn('WinRM timeout',cv['B']['description'])
        self.assertEqual(cv['C']['coverage_status'],'Excluded'); self.assertIn('excluded',cv['C']['title'].lower())
        self.assertEqual(cv['D']['coverage_status'],'Partial'); total=len(a.SOURCE_IDS)
        self.assertEqual((cv['D']['sources_collected'],cv['D']['sources_total']),(total-1,total))
        self.assertIn('%d of %d sources usable'%(total-1,total),cv['D']['description']); self.assertIn('wdigest',cv['D']['description'])
        self.assertEqual(f['counts']['scoped_assets'],4); self.assertEqual(f['counts']['scoped_assets_complete'],1)
        self.assertEqual(len({g['id'] for g in f['coverage_gaps']}),len(f['coverage_gaps']))
    def test_tofindings_coverage_gap_reads_evidence_json_assets_too(self):
        d=self._tests_csv('derived',[{'test_id':'HOST.A.SMB01','category':'smbserver','asset_id':'A','site_id':'LAB','objective':'o','observed':'False','result':'Pass','evidence_file':'Host.A.json','evidence_sha256':'1'*64}])
        (d/'Coverage.csv').write_text('asset_id,site_id,computer_name,status,evidence,note\nA,LAB,A,Complete,Host.A.json,ok\n',encoding='utf-8-sig')
        (d/'Evidence.json').write_text(json.dumps({'coverage':[{'asset_id':'A','status':'Complete'},{'asset_id':'E','site_id':'LAB','computer_name':'E','status':'EvidenceRejected','note':'Evidence digest mismatch.'}]}),encoding='utf-8')
        out=self.root/'draft'; c=self._run('Extensions/ToFindings.py','--derived',d,'--output',out,'--engagement-id','E')
        self.assertEqual(c.returncode,0,c.stderr); f=json.loads((out/'findings.json').read_text(encoding='utf-8'))
        gaps=[g for g in f['coverage_gaps'] if g.get('asset_id')=='E']
        self.assertEqual(len(gaps),1); self.assertEqual(gaps[0]['coverage_status'],'EvidenceRejected'); self.assertIn('digest mismatch',gaps[0]['description'])

    # -- 4. an explicitly supplied missing --patch / --software path is never ignored --
    def test_tofindings_missing_explicit_inputs_recorded_and_exit_4(self):
        batch=self._analyze_batch('b',[('A',True,None)],evidence_for=('A',)); derived=self._derived(batch); out=self.root/'draft'
        c=self._run('Extensions/ToFindings.py','--derived',derived,'--patch',self.root/'missing.json','--software',self.root/'nope.json','--output',out,'--engagement-id','SYNTHETIC')
        self.assertEqual(c.returncode,4,c.stderr); self.assertIn('REQUIRED INPUT MISSING',c.stdout)
        f=json.loads((out/'findings.json').read_text(encoding='utf-8'))
        gaps={g['input_kind']:g for g in f['coverage_gaps'] if g['id'].startswith('GAP-IN-')}
        self.assertEqual(set(gaps),{'patch','software'})
        self.assertIn('missing.json',gaps['patch']['description']); self.assertIn('patch',gaps['patch']['description'].lower())
        self.assertIn('nope.json',gaps['software']['description']); self.assertEqual(f['counts']['required_input_failures'],2)
        c=self._run('Extensions/ToFindings.py','--derived',derived,'--output',self.root/'draft2','--engagement-id','SYNTHETIC')
        self.assertEqual(c.returncode,0,c.stderr)

    # -- 5. remediation names the highest same-branch fixed build, never the worst CVE's --
    def test_patch_remediation_targets_max_fixed_build_with_supersedence_caveat(self):
        f=tf._patch_finding(self._patch_block(),1)
        self.assertIn('10.0.20348.3',f['remediation']); self.assertIn('supersedence',f['remediation']); self.assertIn('vendor data of 2026-09-30',f['remediation'])
        self.assertNotIn('at least build',f['remediation']); self.assertNotIn('10.0.20348.2',f['remediation']); self.assertNotIn('26100',f['remediation'])
        self.assertEqual(f['remediation_target_build'],'10.0.20348.3'); self.assertEqual(f['severity'],'Critical')
        self.assertNotIn('Update packages required',json.dumps(f))
        self.assertEqual(f['kb_references']['label'],'KB references of the latest fixes in the evaluated window')
        self.assertEqual(f['kb_references']['items'],['KB2','KB1'])
    def test_patch_remediation_without_fixed_builds_is_analyst_required(self):
        block=self._patch_block()
        for u in block['missing_updates']: u['fixed_build']=None
        f=tf._patch_finding(block,1)
        self.assertEqual(f['remediation'],'ANALYST REQUIRED: remediation target not determined.'); self.assertIsNone(f['remediation_target_build'])
        self.assertEqual(f['kb_references']['items'],[])
    def test_patch_kb_references_capped_at_eight(self):
        block=self._patch_block(); block['missing_updates']=[{'cve':'CVE-%d'%i,'kb':str(i),'fixed_build':'10.0.20348.%d'%i,'cvss_base_score':5.0,'cvss_vector':'V','known_exploited':False} for i in range(2,14)]
        f=tf._patch_finding(block,1)
        self.assertEqual(len(f['kb_references']['items']),8); self.assertEqual(f['kb_references']['items'][0],'KB13')

    # -- 6. description wording and the truncated-window limitation --
    def test_patch_description_and_window_limitation(self):
        block=self._patch_block(limitations=['Only the 1 most recent Microsoft releases were evaluated.','WINDOW TOO NARROW. Outstanding updates were still being found in the oldest release evaluated (2026-Sep), so older releases will contain more. This count is a floor, not a total.'],window_truncated=True)
        f=tf._patch_finding(block,1)
        self.assertIn('3 CVEs are carried by the outstanding cumulative-update stream',f['description']); self.assertNotIn('security updates are outstanding',f['description'])
        self.assertTrue(f['window_truncated']); self.assertTrue(f['limitations'].startswith('WINDOW TOO NARROW')); self.assertIn('most recent Microsoft releases',f['limitations'])
        self.assertFalse(tf._patch_finding(self._patch_block(),1)['window_truncated'])

    # -- 7. KEV prose --
    def test_patch_kev_prose_unavailable_and_snapshot(self):
        text=tf._patch_finding(self._patch_block(kev_available=False),1)['exploitability'].lower()
        self.assertIn('unavailable',text); self.assertNotIn('currently appear',text)
        block=self._patch_block(); del block['kev_available']; block['missing_updates'][0]['known_exploited']=None
        f=tf._patch_finding(block,1); self.assertIn('not evaluated',f['exploitability'].lower()); self.assertFalse(f['kev_evaluated'])
        f=tf._patch_finding(self._patch_block(),1)
        self.assertIn('As of the catalogue snapshot of 2026-09-30',f['exploitability']); self.assertIn('no outstanding CVE appears',f['exploitability']); self.assertTrue(f['kev_evaluated'])
        block=self._patch_block(); block['missing_updates'][1]['known_exploited']=True
        f=tf._patch_finding(block,1); self.assertIn('as of the catalogue snapshot of 2026-09-30',f['exploitability'].lower()); self.assertIn('1 of the outstanding CVEs',f['exploitability']); self.assertIn('CVE-2099-0002',f['exploitability'])

    # -- 8. per-host evidence pointers --
    def test_patch_evidence_pointers_per_host(self):
        doc={'schema_version':'1.0','evidence_kind':'MissingUpdateAssessment','generated_utc':'2026-10-01T00:00:00+00:00','source_batch':'B1','status':'MissingUpdates',
             'kev_available':True,'feed_fetched_utc':'2026-09-30T06:00:00+00:00','hosts':[]}
        first=self._patch_block(); del first['feed_fetched_utc']; del first['kev_available']; first['status']='MissingUpdates'
        second=self._patch_block(asset_id='B',computer_name='B',full_build='10.0.20348.5',observed_build='10.0.20348.5',status='MissingUpdates'); del second['feed_fetched_utc']
        second['missing_updates']=[{'cve':'CVE-2099-0009','kb':'9','fixed_build':'10.0.20348.9','cvss_base_score':7.5,'cvss_vector':'V','known_exploited':False}]
        doc['hosts']=[first,second]
        for k,v in first.items(): doc.setdefault(k,v)
        patch=self._json('MissingUpdates.json',doc)
        d=self._tests_csv('derived',[{'test_id':'HOST.A.SMB01','category':'smbserver','asset_id':'A','site_id':'LAB','objective':'o','observed':'False','result':'Pass','evidence_file':'Host.A.json','evidence_sha256':'1'*64}])
        out=self.root/'draft'; c=self._run('Extensions/ToFindings.py','--derived',d,'--patch',patch,'--output',out,'--engagement-id','E')
        self.assertEqual(c.returncode,0,c.stderr); f=json.loads((out/'findings.json').read_text(encoding='utf-8'))
        by={x['id']:x for x in f['findings']}
        self.assertEqual([e['evidence_pointer'] for e in by['VULN-01']['evidence']],['hosts[0]','missing_updates'])
        self.assertEqual([e['evidence_pointer'] for e in by['VULN-02']['evidence']],['hosts[1]'])
        self.assertEqual(by['VULN-02']['evidence'][0]['full_build'],'10.0.20348.5'); self.assertEqual(by['VULN-02']['evidence'][0]['feed_fetched_utc'],'2026-09-30T06:00:00+00:00')
        self.assertIn('2026-09-30',by['VULN-01']['remediation']); self.assertIn('As of the catalogue snapshot of 2026-09-30',by['VULN-02']['exploitability'])

    # -- 9. Greenbone scan_complete is tri-state --
    def test_greenbone_completion_tri_state(self):
        self.assertEqual(gbi.completion_state({'scan_run_status':'Done','scan_end':'2026-10-01T09:00:00Z','progress':'100'})[0],True)
        self.assertIs(gbi.completion_state({'scan_run_status':'Done','scan_end':None,'progress':'100'})[0],None)
        for status in ('Running','Requested','Queued','Stopped','Interrupted'):
            self.assertIs(gbi.completion_state({'scan_run_status':status,'scan_end':None,'progress':'42'})[0],False,status)
        self.assertIs(gbi.completion_state({'scan_run_status':None,'scan_end':None,'progress':None})[0],None)
        self.assertIs(gbi.completion_state({'scan_run_status':'New','scan_end':None,'progress':None})[0],None)
        src=self.root/'r.xml'; src.write_text('<report id="r1"><results/></report>',encoding='utf-8'); out=self.root/'r.json'
        c=self._run('Extensions/GreenboneImport.py','--input',src,'--output',out,'--engagement','E','--source-position','VP')
        self.assertEqual(c.returncode,0,c.stderr); d=json.loads(out.read_text(encoding='utf-8'))
        self.assertIsNone(d['scan_complete']); self.assertIn('no scan_run_status',d['scan_completion_basis'])
        self.assertTrue(any('scan completion not established' in l for l in d['limitations']))
        src2=self.root/'r2.xml'; src2.write_text(_gvm_xml(status='Running',progress='42',end=''),encoding='utf-8'); out2=self.root/'r2.json'
        self._run('Extensions/GreenboneImport.py','--input',src2,'--output',out2,'--engagement','E','--source-position','VP')
        d2=json.loads(out2.read_text(encoding='utf-8')); self.assertIs(d2['scan_complete'],False); self.assertIn('Running',d2['scan_completion_basis'])
        src3=self.root/'r3.xml'; src3.write_text(_gvm_xml(),encoding='utf-8'); out3=self.root/'r3.json'
        self._run('Extensions/GreenboneImport.py','--input',src3,'--output',out3,'--engagement','E','--source-position','VP')
        self.assertIs(json.loads(out3.read_text(encoding='utf-8'))['scan_complete'],True)

    # -- 10. VULN.SCAN row and its coverage gap --
    def test_analyze_emits_scan_row_and_tofindings_gaps_it(self):
        base={'schema_version':'1.0','tool_version':a.VERSION,'evidence_kind':'GreenboneObservations','engagement_id':'E','source_position':'VP',
              'scan_run_status':'Running','progress':'42','scan_end':None,'hosts_count':'3','result_count_full':'5','result_count_filtered':'2',
              'filter_text':'min_qod=70','credentialed_indicator':None,'scan_completion_basis':'synthetic',
              'observations':[{'host':'h1','port':'445/tcp','name':'High vuln','threat':'High','actionable':True}]}
        expect={True:'Observation',False:'Inconclusive',None:'Not tested'}
        for value,result in expect.items():
            doc=dict(base); doc['scan_complete']=value
            tests,_=a.import_greenbone(self._json('g_%s.json'%result,doc),'E')
            scan=tests[0]; self.assertEqual(scan['test_id'],'VULN.SCAN'); self.assertEqual(scan['result'],result,value)
            self.assertEqual((scan['category'],scan['phase']),('network_vulnerability','active_network'))
            obs=scan['observed']
            self.assertEqual((obs['scan_run_status'],obs['progress'],obs['hosts_count'],obs['filter_text'],obs['credentialed_indicator'],obs['result_count']),('Running','42','3','min_qod=70',None,1))
            self.assertTrue(tf._needs_review(scan))
        rows=[{'test_id':'VULN.SCAN','category':'network_vulnerability','asset_id':'','site_id':'','source_position':'VP','objective':'Scanner export completeness','observed':'{}','result':'Inconclusive','evidence_file':'g.json','evidence_sha256':'3'*64}]
        d=self._tests_csv('derived',rows); out=self.root/'draft'
        c=self._run('Extensions/ToFindings.py','--derived',d,'--output',out,'--engagement-id','E'); self.assertEqual(c.returncode,0,c.stderr)
        f=json.loads((out/'findings.json').read_text(encoding='utf-8'))
        sc_gaps=[g for g in f['coverage_gaps'] if g['id'].startswith('GAP-SC-')]
        self.assertEqual(len(sc_gaps),1); self.assertEqual(sc_gaps[0]['title'],'Scanner export incomplete or completion not established'); self.assertEqual(sc_gaps[0]['affected_assets'],['VP'])
        self.assertIn('VULN.SCAN',{q['test_id'] for q in f['review_queue']})
        rows[0]['result']='Observation'; d2=self._tests_csv('derived2',rows); out2=self.root/'draft2'
        self._run('Extensions/ToFindings.py','--derived',d2,'--output',out2,'--engagement-id','E')
        self.assertEqual([g for g in json.loads((out2/'findings.json').read_text(encoding='utf-8'))['coverage_gaps'] if g['id'].startswith('GAP-SC-')],[])

    # -- 11. wireless controller unknown states --
    def test_controller_unknown_states_never_fail_and_notes_pass_through(self):
        intake={'engagement_id':'E','site_id':'LAB','controller':{'rogue_detection_enabled':None,'wips_enabled':'not_supported',
                'field_notes':{'wips_enabled':'Vendor has no WIPS feature on this model.'}},
                'wlans':[{'ssid':'G','purpose':'guest','security':'wpa2-psk','pmf':None,'vlan':30,'client_isolation':'unknown','field_notes':{'client_isolation':'Not shown in the export.'}},
                         {'ssid':'C','purpose':'corporate','security':'wpa2-enterprise','pmf':'not_supported','vlan':10,'client_isolation':True}]}
        src=self._json('intake.json',intake); out=self.root/'ctrl.json'
        c=self._run('Extensions/WirelessControllerImport.py','--input',src,'--output',out,'--engagement','E')
        self.assertEqual(c.returncode,0,c.stderr); d=json.loads(out.read_text(encoding='utf-8'))
        self.assertEqual((d['controller']['rogue_detection_enabled'],d['controller']['wips_enabled']),('unknown','not_supported'))
        self.assertEqual(d['controller']['field_notes']['wips_enabled'],'Vendor has no WIPS feature on this model.')
        self.assertEqual((d['wlans'][0]['pmf'],d['wlans'][0]['client_isolation'],d['wlans'][1]['pmf']),('unknown','unknown','not_supported'))
        self.assertTrue(any('Control state unknown or not supported' in l for l in d['limitations']))
        by={t['test_id']:t for t in a.import_wireless_controller(out,'E')[0]}
        for tid in ('CTRL.rogue_detection','CTRL.wips','CTRL.1.isolation','CTRL.1.pmf','CTRL.2.pmf'):
            self.assertEqual(by[tid]['result'],'Unknown',tid); self.assertIn('cannot be determined',by[tid]['technical_interpretation'])
        self.assertEqual(by['CTRL.wips']['observed']['source_note'],'Vendor has no WIPS feature on this model.')
        self.assertEqual(by['CTRL.1.isolation']['observed']['source_note'],'Not shown in the export.'); self.assertNotIn('source_note',by['CTRL.rogue_detection']['observed'])
        self.assertEqual(by['CTRL.2.auth']['result'],'Pass'); self.assertEqual(by['CTRL.1.vlan']['result'],'Pass')
        intake['controller']={'rogue_detection_enabled':True}   # wips missing entirely means unknown, not an error
        self.assertEqual(self._run('Extensions/WirelessControllerImport.py','--input',self._json('i2.json',intake),'--output',self.root/'c2.json','--engagement','E').returncode,0)
        self.assertEqual(json.loads((self.root/'c2.json').read_text(encoding='utf-8'))['controller']['wips_enabled'],'unknown')
        intake['controller']={'rogue_detection_enabled':'maybe','wips_enabled':True}
        c=self._run('Extensions/WirelessControllerImport.py','--input',self._json('i3.json',intake),'--output',self.root/'c3.json','--engagement','E')
        self.assertEqual(c.returncode,2); self.assertIn('rogue_detection_enabled',c.stderr)
    def test_analyze_controller_absent_fields_are_unknown(self):
        doc={'schema_version':'1.0','tool_version':a.VERSION,'evidence_kind':'WirelessControllerConfig','engagement_id':'E','controller':{},
             'corporate_vlans':[10],'corporate_vlans_known':True,'wlans':[{'ssid':'G','purpose':'guest','security':'wpa2-enterprise','vlan':30}]}
        by={t['test_id']:t['result'] for t in a.import_wireless_controller(self._json('c.json',doc),'E')[0]}
        self.assertEqual((by['CTRL.rogue_detection'],by['CTRL.wips'],by['CTRL.1.isolation'],by['CTRL.1.pmf']),('Unknown','Unknown','Unknown','Unknown'))

    # -- 12. wireless air band coverage --
    def _air_row(self,bssid,essid,channel):
        return (f'{bssid}, 2026-10-01 08:00:00, 2026-10-01 08:05:00, {channel},  54, WPA2, CCMP, PSK, -40,  100,  0,'
                f'   0.  0.  0.  0,  {len(essid)}, {essid}, \r\n')
    def test_air_band_from_channel(self):
        for channel,band in (('6','2.4 GHz'),('1','2.4 GHz'),('14','2.4 GHz'),('36','5 GHz'),('177','5 GHz'),('5 6g','6 GHz'),('233 6e','6 GHz'),('37 6g','6 GHz'),
                             ('15','unknown'),('178','unknown'),('233','unknown'),('-1','unknown'),('','unknown'),('abc','unknown')):
            self.assertEqual(wai.channel_band(channel),band,channel)
    def test_air_coverage_block_and_single_band_limitation(self):
        allow=self._json('allow.json',{'corporate_essids':['CORP'],'authorized_bssids':['AA:BB:CC:DD:EE:01']})
        src=self.root/'air.csv'; src.write_bytes(_airodump_csv([self._air_row('AA:BB:CC:DD:EE:01','CORP','6'),self._air_row('AA:BB:CC:DD:EE:02','Cafe','36')]).encode('utf-8'))
        out=self.root/'air.json'
        c=self._run('Extensions/WirelessAirImport.py','--input',src,'--authorized',allow,'--output',out,'--engagement','E','--source-position','VP')
        self.assertEqual(c.returncode,0,c.stderr); d=json.loads(out.read_text(encoding='utf-8'))
        self.assertEqual(d['coverage'],{'bands_observed':['2.4 GHz','5 GHz'],'unknown_band_count':0,'ap_count':2,'duration_hint':None})
        self.assertEqual([o['band'] for o in d['observations']],['2.4 GHz','5 GHz']); self.assertFalse(any('Only the' in l for l in d['limitations']))
        self.assertEqual(d['observations'][0]['classification'],'AuthorizedAP'); self.assertEqual(d['wps_source'],None)
        src2=self.root/'air2.csv'; src2.write_bytes(_airodump_csv([self._air_row('AA:BB:CC:DD:EE:01','CORP','6')]).encode('utf-8')); out2=self.root/'air2.json'
        self._run('Extensions/WirelessAirImport.py','--input',src2,'--authorized',allow,'--output',out2,'--engagement','E','--source-position','VP')
        d2=json.loads(out2.read_text(encoding='utf-8'))
        self.assertEqual(d2['coverage']['bands_observed'],['2.4 GHz']); self.assertTrue(any(l.startswith('Only the 2.4 GHz band') for l in d2['limitations']))
        self.assertEqual(a.import_wireless_air(out2,'E')[0][0]['result'],'Observation')

    # -- 13. analyst dispositions --
    def test_tofindings_dispositions_applied_and_validated(self):
        rows=[{'test_id':'HOST.A.SMB02','category':'smbserver','asset_id':'A','site_id':'LAB','objective':'Signing','observed':'','result':'Unknown','evidence_file':'Host.A.json','evidence_sha256':'1'*64},
              {'test_id':'VULN.00001','category':'network_vulnerability','asset_id':'','site_id':'LAB','source_position':'VP','objective':'SMB vuln','observed':'{}','result':'Candidate','evidence_file':'gb.json','evidence_sha256':'3'*64},
              {'test_id':'HOST.A.SMB01','category':'smbserver','asset_id':'A','site_id':'LAB','objective':'SMBv1','observed':'False','result':'Pass','evidence_file':'Host.A.json','evidence_sha256':'1'*64}]
        d=self._tests_csv('derived',rows)
        self.assertEqual((HERE.parent/'Templates'/'ReviewDispositions.csv').read_text(encoding='utf-8-sig').strip(),','.join(tf.DISPOSITION_FIELDS))
        evidence=self.root/'shot.txt'; evidence.write_text('independent check',encoding='utf-8'); digest=hashlib.sha256(evidence.read_bytes()).hexdigest()
        header=','.join(tf.DISPOSITION_FIELDS)+'\n'
        disp=self.root/'disp.csv'; disp.write_text(header+f'HOST.A.SMB02,ConfirmedFinding,Checked on host,Reviewer,2026-10-01T10:00:00Z,shot.txt,{digest}\n',encoding='utf-8')
        out=self.root/'draft'; c=self._run('Extensions/ToFindings.py','--derived',d,'--dispositions',disp,'--output',out,'--engagement-id','E')
        self.assertEqual(c.returncode,0,c.stderr); f=json.loads((out/'findings.json').read_text(encoding='utf-8'))
        q={e['test_id']:e for e in f['review_queue']}
        self.assertEqual(q['HOST.A.SMB02']['disposition']['disposition'],'ConfirmedFinding'); self.assertEqual(q['HOST.A.SMB02']['disposition']['evidence_sha256'],digest)
        self.assertEqual(q['HOST.A.SMB02']['disposition']['reviewer'],'Reviewer'); self.assertEqual(q['VULN.00001']['disposition'],{'disposition':'Pending'})
        self.assertEqual((f['counts']['dispositions_recorded'],f['counts']['pending']),(1,1)); self.assertIn('Dispositions     : 1 recorded, 1 review rows still Pending',c.stdout)
        c=self._run('Extensions/ToFindings.py','--derived',d,'--output',self.root/'draft0','--engagement-id','E')
        f0=json.loads((self.root/'draft0'/'findings.json').read_text(encoding='utf-8'))
        self.assertTrue(all(e['disposition']=={'disposition':'Pending'} for e in f0['review_queue'])); self.assertEqual((f0['counts']['dispositions_recorded'],f0['counts']['pending']),(0,2))
        bad=[('unknown',header+'HOST.X.NOPE,Pending,,,,,\n','unknown test_id'),
             ('disposition',header+'HOST.A.SMB02,Maybe,,,,,\n','Invalid disposition'),
             ('columns','test_id,disposition\nHOST.A.SMB02,Pending\n','do not match'),
             ('duplicate',header+'HOST.A.SMB02,Pending,,,,,\nHOST.A.SMB02,Pending,,,,,\n','Duplicate'),
             ('hash',header+f'HOST.A.SMB02,ConfirmedFinding,,,,shot.txt,{"0"*64}\n','SHA-256 mismatch')]
        for name,text,message in bad:
            p=self.root/f'{name}.csv'; p.write_text(text,encoding='utf-8')
            c=self._run('Extensions/ToFindings.py','--derived',d,'--dispositions',p,'--output',self.root/('bad_'+name),'--engagement-id','E')
            self.assertNotEqual(c.returncode,0,name); self.assertIn(message,c.stderr,name); self.assertFalse((self.root/('bad_'+name)/'findings.json').exists(),name)

    # -- 14. SealDerived --
    def test_seal_derived_covers_new_files_and_refuses_raw_batch(self):
        batch=self._analyze_batch('b',[('A',True,None)],evidence_for=('A',)); derived=self._derived(batch)
        c=self._run('Extensions/ToFindings.py','--derived',derived,'--output',derived,'--engagement-id','SYNTHETIC')
        self.assertEqual(c.returncode,0,c.stderr); self.assertIn('SealDerived.py',c.stdout)
        self.assertNotIn('findings.json',(derived/'Manifest.txt').read_text(encoding='utf-8'))
        v=self._run('Code/VerifyManifest.py',derived); self.assertEqual(v.returncode,1); self.assertIn('findings.json: UNMANIFESTED',v.stdout)
        c=self._run('Code/SealDerived.py',derived); self.assertEqual(c.returncode,0,c.stderr); self.assertIn('findings.json',c.stdout)
        manifest=(derived/'Manifest.txt').read_text(encoding='utf-8')
        self.assertIn('  findings.json',manifest); self.assertIn('  Tests.csv',manifest); self.assertNotIn('Manifest.txt',manifest)
        self.assertEqual(self._run('Code/VerifyManifest.py',derived).returncode,0)
        c=self._run('Code/SealDerived.py',batch); self.assertEqual(c.returncode,2); self.assertIn('Batch.json',c.stderr); self.assertFalse((batch/'Manifest.txt').exists())
        self.assertEqual(self._run('Code/SealDerived.py').returncode,2)
        with self.assertRaises(ValueError): sd.seal(self.root/'absent')


if __name__=='__main__': unittest.main()
