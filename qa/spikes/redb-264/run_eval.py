import os,subprocess,tempfile,time,signal,pathlib,json,hashlib,argparse
parser=argparse.ArgumentParser(description='Scratch-only redb transactional backend qualification')
parser.add_argument('--binary',required=True,type=pathlib.Path)
parser.add_argument('--artifacts',required=True,type=pathlib.Path)
args=parser.parse_args()
binary=str(args.binary.resolve(strict=True))
out=args.artifacts.resolve()
if out.exists() and any(out.iterdir()):
    parser.error('artifacts directory must be new or empty; stale barriers invalidate results')
out.mkdir(parents=True,exist_ok=True)
rows=[]
def run(*args):
 p=subprocess.run([binary,*map(str,args)],capture_output=True,text=True,timeout=20)
 return p.returncode,p.stdout.strip(),p.stderr.strip()
for i in range(10):
 for point in ('before-commit','after-commit'):
  database=out/f'{i:02d}-{point}.redb'
  barrier=out/f'{i:02d}-{point}.ready'
  database.unlink(missing_ok=True)
  assert run('init',database)[0]==0
  p=subprocess.Popen([binary,'promote',str(database),'','r1_candidate','idem1','fingerprint1',point,str(barrier)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  t=time.monotonic()
  while not barrier.exists() and p.poll() is None and time.monotonic()-t<10:time.sleep(.01)
  assert barrier.exists() and p.poll() is None,('barrier missing',point,p.poll())
  assert barrier.read_text()==point
  p.kill(); outbytes,errbytes=p.communicate(timeout=5)
  assert p.returncode==-signal.SIGKILL
  code,status,_=run('check',database)
  expected='head=;seq=0;receipts=0;idempotency=0' if point=='before-commit' else 'head=r1_candidate;seq=1;receipts=1;idempotency=1'
  assert code==0 and expected==status,(point,status)
  if point=='after-commit':
   rc,replay,_=run('promote',database,'','r1_candidate','idem1','fingerprint1')
   assert rc==0 and replay.startswith('IDEMPOTENT:') and expected in replay
   rc,conflict,_=run('promote',database,'','r1_candidate','idem1','changed')
   assert rc==2 and conflict=='E_IDEMPOTENCY_CONFLICT'
  else:
   rc,retry,_=run('promote',database,'','r1_candidate','idem1','fingerprint1')
   assert rc==0 and retry.startswith('PROMOTED:')
  rows.append(dict(iteration=i,point=point,signal='SIGKILL',observed_status=status,passed=True))
for n in (2,20,100):
 db=out/f'race-{n}.redb'
 db.unlink(missing_ok=True)
 rc,output,error=run('race',db,n)
 assert rc==0,(n,rc,output,error)
 assert f'race={n};wins=1;head_conflicts={n-1}' in output,output
 assert ';seq=1;receipts=1;idempotency=1' in output
 rows.append(dict(race=n,output=output,passed=True))
manifest=dict(protocol='openscion.redb.backend-eval.v1',redb='2.6.4',rust='1.85.1',kill_tests=20,races=[2,20,100],results=rows)
raw=json.dumps(manifest,sort_keys=True,indent=2)+'\n'
path=out/'summary.json'
path.write_text(raw)
print('REDB_EVAL_PASS',len(rows),'SIGKILL_CASES',20,'RACE_WORKERS',([2,20,100]))
print('SUMMARY_SHA256',hashlib.sha256(path.read_bytes()).hexdigest())
print('LOCK_SHA256',hashlib.sha256((pathlib.Path(__file__).parent/'Cargo.lock').read_bytes()).hexdigest())
print('REPRESENTATIVE',rows[0],rows[1],rows[-1])
