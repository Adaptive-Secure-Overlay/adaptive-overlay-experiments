"""Two serial functional/time measurements on an externally disconnected EVE copy.

Existing components only. Per-node keys are generated on that node. Test issuer
exists only on the isolated EVE controller, never on endpoint or physical hosts.
"""
import base64,hashlib,json,os,re,signal,subprocess,sys,tarfile,time,traceback
from pathlib import Path
import guest_setup as v
import path_capture as pathcap
import router_read
import buffer_queues
from queue_stats import loss_deltas
pathcap.router_probe=router_read  # Use recorded credential, never the old empty-password adapter.
g=v.g; ROOT=v.ROOT; STATUS=ROOT/'LIVE-STATUS.json'; v.STATUS=STATUS

def atom(path,value):v.atom(path,value)
def remote_json(user,command,prefix='PUBLIC_JSON=',timeout=40):
    raw=g.ssh(user,command,timeout=timeout)
    found=re.search(re.escape(prefix)+r'(\{[^\r\n]*\})',raw)
    assert found,'Missing sanitized endpoint receipt'
    return json.loads(found[1])
def node(user,action,peer=None,job=None):return v.node(user,action,peer,job)
def identity_provision():
    # Extraction is local to this new controller directory. No persistent issuer
    # from the real stand is replaced or newly entrusted implicitly.
    code=ROOT/'issuer-code';code.mkdir(mode=0o700)
    with tarfile.open(ROOT/'candidate.tar.xz') as tf:
        for member in tf.getmembers():
            p=Path(member.name)
            assert member.isfile() and len(p.parts)>1 and p.parts[0]=='code' and '..' not in p.parts
            out=code/Path(*p.parts[1:]);out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(tf.extractfile(member).read())
    sys.path.insert(0,str(code))
    import trust_registry as trust
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    issuer_dir=ROOT/'test-issuer';issuer_dir.mkdir(mode=0o700)
    issuer=Ed25519PrivateKey.generate()
    private=issuer.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
    public=issuer.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    fd=os.open(issuer_dir/'issuer.key',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(private.hex().encode()+b'\n')
    root={'schema':trust.ROOT_SCHEMA,'signers':{'copy-test-issuer':{'algorithm':'Ed25519','public_key':base64.urlsafe_b64encode(public).rstrip(b'=').decode()}}}
    root_data=trust._canonical_json(root);(ROOT/'trust-root.json').write_bytes(root_data)
    entries=[];receipts={}
    for user in g.ENDPOINTS:
        helper_b64=base64.b64encode((ROOT/'node_diag.py').read_bytes()).decode()
        g.ssh(user,"/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14 - <<'PY'\nimport ast,base64,os\nfrom pathlib import Path\np=Path('"+str(ROOT/ 'node_diag.py')+"'); data=base64.b64decode('"+helper_b64+"');ast.parse(data.decode());fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o700)\nwith os.fdopen(fd,'wb') as f:f.write(data)\nPY",timeout=20)
        command=f"/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14 -B {ROOT}/code/mcc_e2e_admin.py keygen --node User{user} --directory {ROOT}/identity"
        raw=g.ssh(user,command,timeout=30)
        found=re.search(r'(\{"generated"[^\r\n]*\})',raw);assert found,'Node-local key generation failed'
        entry=json.loads(found[1]);assert entry['posix_permissions_verified'] and not entry['test_fixtures_only']
        receipt=remote_json(user,"/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14 - <<'PY'\nimport json,stat,os\nfrom pathlib import Path\nimport cryptography\nr=Path('"+str(ROOT)+"'); e=json.loads((r/'identity/public-entry.json').read_text());print('PUBLIC_JSON='+json.dumps({'entry':e,'cryptography':cryptography.__version__,'private_permissions':{n:oct(stat.S_IMODE((r/'identity'/n).stat().st_mode)) for n in ('signing.key','encryption.key')},'private_owner_is_process':all((r/'identity'/n).stat().st_uid==os.getuid() for n in ('signing.key','encryption.key'))}))\nPY")
        assert receipt['private_owner_is_process'] and set(receipt['private_permissions'].values())=={'0o600'}
        path=issuer_dir/f'User{user}-public.json';path.write_text(json.dumps(receipt['entry']));entries.append(str(path));receipts[str(user)]=receipt
    command=['/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14','-B',str(code/'mcc_e2e_admin.py'),'sign-registry','--entries',*entries,'--trust-root',str(ROOT/'trust-root.json'),'--issuer-key',str(issuer_dir/'issuer.key'),'--issuer-id','copy-test-issuer','--version','1','--output',str(ROOT/'registry.json')]
    result=subprocess.run(command,capture_output=True,text=True,timeout=30)
    assert result.returncode==0,'Test-only public registry signing failed'
    registry_data=(ROOT/'registry.json').read_bytes()
    for user in g.ENDPOINTS:
        values={n:base64.b64encode(data).decode() for n,data in [('trust-root.json',root_data),('registry.json',registry_data)]}
        cmd="/root/candidate-mcc-runtime3148-5002-restored-20261015/python/bin/python3.14 - <<'PY'\nimport base64,json,os,sys\nfrom pathlib import Path\nr=Path('"+str(ROOT)+"'); values="+repr(values)+"\nfor n,b in values.items():\n p=r/n;fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n with os.fdopen(fd,'wb') as f:f.write(base64.b64decode(b))\nsys.path.insert(0,str(r/'code'))\nimport trust_registry as t\nv=t.verify_registry_bytes((r/'registry.json').read_bytes(),r/'trust-root.json',['User6','User7','User8','User9','User10']);print('PUBLIC_JSON='+json.dumps({'verified':True,'version':v.version,'nodes':len(v.nodes)}))\nPY"
        receipt=remote_json(user,cmd);assert receipt=={'verified':True,'version':1,'nodes':5}
        receipts[str(user)]['registry']=receipt
    atom(ROOT/'KEY-ADMISSION.json',{'passed':True,'test_issuer_only_for_this_copy':True,'root_sha256':hashlib.sha256(root_data).hexdigest(),'private_keys_transferred':False,'nodes':receipts})
