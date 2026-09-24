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
        self.assertEqual([t['result'] for t in tests],['Candidate','Candidate','Observation'])
    def test_greenbone_engagement_mismatch_raises(self):
        doc={'schema_version':'1.0','tool_version':a.VERSION,'evidence_kind':'GreenboneObservations','engagement_id':'X','observations':[]}
        with self.assertRaises(ValueError): a.import_greenbone(self._w(doc),'E')


if __name__=='__main__': unittest.main()
