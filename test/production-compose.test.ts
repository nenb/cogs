import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { lstat, mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { performance } from "node:perf_hooks";
import test from "node:test";
import type { StreamFn } from "@earendil-works/pi-agent-core";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai";
import type { AssistantMessage } from "@earendil-works/pi-ai/compat";
import { SessionManager } from "@earendil-works/pi-coding-agent";
import {
  capabilityRemovalScenario,
  PROBE_GENERATION_SECONDS,
  PROBE_SUITE_SECONDS,
  productFailureDiagnostic,
  requireProbeSuiteWindow,
  syntheticPkiArgv,
  withProductCustody,
} from "../dev/product-test/runner.ts";
import {
  type ContainerSpec,
  type CustodyPort,
  containerArguments,
  SANDBOX_CAPABILITIES,
  SANDBOX_CAPABILITY_MASK,
  sandboxCapabilities,
} from "../dev/product-test/snapshot-owner.ts";
import { type ApiServer, type ApiServerOptions, createApiServer, type JsonValue } from "../src/api/server.ts";
import { type ModelApiKeySource, type OpenBaoIdentityPort, OpenBaoModelApiKeyStore } from "../src/auth/model-auth.ts";
import type { CogsEnvoyRuntimeConfig } from "../src/egress/envoy-runtime-config.ts";
import type { CogsExtAuthzServer } from "../src/egress/ext-authz-server.ts";
import { canonicalPresetPolicyRevision } from "../src/egress/preset-revision.ts";
import { lowerLaunchEgressRoutePlan } from "../src/egress/route-policy.ts";
import {
  aggregateCogsEgressRoutePlanRevision,
  type CogsEgressRuntimeManager,
  type CogsEgressRuntimeManagerOptions,
  startCogsEgressRuntimeManager,
} from "../src/egress/runtime-manager.ts";
import {
  beginRegisteredClose,
  closeContext,
  createCloseOwner,
  joinCloseWork,
  registerCloseOwner,
} from "../src/launch/close.ts";
import { type LaunchConfig, validateLaunchConfig } from "../src/launch/config.ts";
import { LaunchLifecycle, type LaunchLifecycleOptions } from "../src/launch/lifecycle.ts";
import { type ProductionMainPort, runProductionMain } from "../src/main.ts";
import {
  type AuthenticatedCogsPiSessionOptions,
  type CogsPiSessionPorts,
  createAuthenticatedCogsPiSession,
} from "../src/pi/session.ts";
import {
  ProductionWorkerError,
  type ProductionWorkerRuntime,
  type ProductionWorkerSeams,
  startProductionWorker,
} from "../src/runtime/compose.ts";
import type { RuntimeConfig } from "../src/runtime/config.ts";
import type { CogsPrivateSkillStore } from "../src/skills/local-private-store.ts";
import type { CogsSharedSkillOciResolver } from "../src/skills/oci-layout.ts";
import type { CogsExecPort, SshConnectionManager, SshConnectionManagerOptions } from "../src/ssh/connection.ts";
import { type CogsWorkerTelemetrySink, createCogsWorkerTelemetrySink } from "../src/telemetry/worker-telemetry.ts";

test("protected workflow separates profile jobs and preserves probe-only no-pass inventory", async () => {
  const workflow = await readFile(".github/workflows/insecure-container.yml", "utf8");
  for (const profile of ["profile: empty", "profile: nonempty"])
    assert.equal(workflow.split(profile).length - 1, 2, `missing independent ${profile} jobs`);
  assert.match(workflow, /mode: --protected-linux/u);
  assert.match(workflow, /mode: --capability-probes/u);
  assert.match(workflow, /authority: candidate-pass/u);
  assert.match(workflow, /authority: probe-only/u);
  assert.match(workflow, /cogs\.product-probe-inventory\/v1/u);
  assert.match(workflow, /cogs\.product-failure-receipt\/v1/u);
  assert.match(workflow, /probe capability coverage or retired generation mismatch/u);
  assert.match(workflow, /build_receipt_sha256/u);
  assert.match(workflow, /capability_coverage/u);
  assert.match(workflow, /AUTHORITY'\]!='probe-only'/u);
  assert.match(workflow, /matrix\.authority == 'candidate-pass'/u);
});

test("probe suites reserve eight sequential 600-second generations and cleanup", async () => {
  const workflow = await readFile(".github/workflows/insecure-container.yml", "utf8");
  assert.match(workflow, /timeout_minutes: 100/u);
  assert.match(workflow, /lifetime_ms=5340000/u);
  assert.match(workflow, /eight independent\n {10}# 600-second effects/u);
  assert.equal(PROBE_GENERATION_SECONDS, 600);
  assert.equal(PROBE_SUITE_SECONDS, 5280);
  // A fake clock crosses the old five-minute expiry boundary while every
  // sequential generation still has its independent 600-second reservation.
  let now = 0;
  const restrictions = { seconds: 600, expires: PROBE_SUITE_SECONDS * 1000 + 1 } as never;
  for (let generation = 0; generation < 8; generation++) {
    requireProbeSuiteWindow(restrictions, now, generation);
    now += 660_000;
  }
  assert.ok(now > 300_000);
  assert.throws(() => requireProbeSuiteWindow(restrictions, now, 7));
});

test("product helper identity is unreaped through final signals and directory modes defeat ambient umask", () => {
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      String.raw`
import importlib.util,os,signal,tempfile,time,types
from contextlib import ExitStack
from unittest.mock import patch
s=importlib.util.spec_from_file_location('custody','dev/product-test/host-custody.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
with tempfile.TemporaryDirectory() as root:
 parent=os.open(root,os.O_RDONLY|os.O_DIRECTORY);previous=os.umask(0o077)
 try:
  for mode in (0o555,0o755,0o750):
   fd=m.directory(parent,str(mode),mode)
   assert os.fstat(fd).st_mode&0o777==mode
   os.close(fd)
   with patch.object(m.os,'fchmod',side_effect=AssertionError('reopen mutated mode')):
    os.close(m.directory(parent,str(mode)))
  closed=[];close=os.close
  with patch.object(m.os,'fchmod'),patch.object(m.os,'close',side_effect=lambda fd:(closed.append(fd),close(fd))):
   try: m.directory(parent,'chmod-ineffective',0o755)
   except RuntimeError: pass
   else: raise AssertionError('mode verification missing')
  assert len(closed)==1
 finally: os.umask(previous);os.close(parent)
class Stream:
 def fileno(self): return 20
 def close(self):
  if mode=='finalize-close': raise OSError('descriptor close refused')
class Poll:
 def __enter__(self): self.entries={};return self
 def __exit__(self,*a): pass
 def register(self,stream,event,target): self.entries[stream]=types.SimpleNamespace(fd=20,data=target,fileobj=stream)
 def unregister(self,stream): del self.entries[stream]
 def get_map(self): return self.entries
 def select(self,*a): return [(key,1) for key in self.entries.values()]
for mode in ('success','nonzero','nonzero-measurement','early-exit','timeout','overflow','restop-pid','restop-code','restop-signal','finalize-close'):
 events=[];reaped=False
 class Process:
  pid=12345;stdout=Stream();stderr=Stream()
  def wait(self,**kw):
   global reaped
   assert events[-2:]==['killpg','cgroup.kill'],events
   reaped=True;events.append('reap-and-reuse');return 0
 def waitid(kind,fd,flags):
  assert kind==3 and fd==77 and flags&os.WNOWAIT and flags&os.WNOHANG and not reaped
  events.append('observe')
  if mode=='timeout': return None
  stopped=flags&os.WSTOPPED and mode!='early-exit'
  bad=mode.removeprefix('restop-') if events.count('observe')==2 else ''
  return types.SimpleNamespace(si_pid=1 if bad=='pid' else 12345,si_code=os.CLD_STOPPED if stopped and bad!='code' else os.CLD_EXITED,si_status=signal.SIGTERM if bad=='signal' else signal.SIGSTOP if stopped else 7 if mode.startswith('nonzero') else 0)
 def killpg(pid,sig):
  assert pid==12345 and sig==signal.SIGKILL and not reaped,'numeric PGID was reused by an unrelated group'
  events.append('killpg')
 with tempfile.TemporaryDirectory() as root:
  owner=m.Custody.__new__(m.Custody);owner.generation='a'*32;owner.records=set();owner.failed=False;owner.failure_stage='operation'
  owner.fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);owner.control=m.directory(owner.fd,'control',0o700)
  owner.cg=root+'/cgroup';os.mkdir(owner.cg);os.mkdir(owner.cg+'/helpers');open(owner.cg+'/helpers/cgroup.procs','w').close()
  owner.deadline=time.monotonic()+.03;owner.cwrite=lambda path,name,value:events.append(name)
  real_stat=os.stat;real_fstat=os.fstat;real_close=os.close;real_open=open;real_read=os.read;real_sync=os.fsync;real_unlink=os.unlink;real_write=os.write
  def root_stat(value):
   return types.SimpleNamespace(**{n:0 if n=='st_uid' else getattr(value,n) for n in dir(value) if n.startswith('st_')})
  def sync(fd):
   real_sync(fd);events.append('control-sync' if fd==owner.control else 'file-sync')
  def unlink(name,**kw):
   assert name=='helper-pending' and kw=={'dir_fd':owner.control};events.append('unlink');real_unlink(name,**kw)
  def spawn(argv,**kw):
   assert events[-1]=='control-sync' and 'preexec_fn' in kw and kw['start_new_session']
   assert m.capture(owner.control,'helper-pending',1024)==m.canonical({'version':1,'generation':owner.generation,'parent_pid':os.getpid()})
   assert real_stat('helper-pending',dir_fd=owner.control).st_mode&0o777==0o400
   return Process()
  def write(fd,data):
   if data==b'12345': events.append('cgroup.procs')
   return real_write(fd,data)
  def opened(path,*a,**kw):
   if path=='/proc/12345/cgroup': events.append('membership');return m.io.StringIO('0::'+owner.cg[14:]+'/helpers\n')
   return real_open(path,*a,**kw)
  def resume(pid,sig):
   assert (pid,sig)==(12345,signal.SIGCONT) and 'helper-pending' not in os.listdir(owner.control) and 'helper-pending' not in owner.records
   assert events.index('cgroup.procs')<events.index('membership')<events.index('unlink') and events[-1]=='control-sync'
   events.append('continue')
  try:
   with ExitStack() as stack:
    patches=[patch.object(m.os,'fchown'),patch.object(m.os,'stat',side_effect=lambda *a,**kw:root_stat(real_stat(*a,**kw))),patch.object(m.os,'fstat',side_effect=lambda fd:root_stat(real_fstat(fd))),patch.object(m.os,'fsync',side_effect=sync),patch.object(m.os,'unlink',side_effect=unlink),patch.object(m.os,'write',side_effect=write),patch('builtins.open',side_effect=opened),patch.object(m.subprocess,'Popen',side_effect=spawn),patch.object(m.os,'pidfd_open',create=True,return_value=77),patch.object(m.os,'P_PIDFD',create=True,new=3),patch.object(m.os,'waitid',create=True,side_effect=waitid),patch.object(m.os,'kill',side_effect=resume),patch.object(m.os,'killpg',side_effect=killpg),patch.object(m.os,'close',side_effect=lambda fd:None if fd==77 else real_close(fd)),patch.object(m.os,'set_blocking'),patch.object(m.os,'read',side_effect=lambda fd,n:(b'xx' if mode=='overflow' else b'') if fd==20 else real_read(fd,n)),patch.object(m.selectors,'DefaultSelector',Poll),patch.object(m.os.path,'exists',side_effect=lambda p:p.endswith('cgroup.kill'))]
    for p in patches: stack.enter_context(p)
    for name,path in [('cgroup',owner.cg),('helpers-cgroup',owner.cg+'/helpers')]: owner.record(name,list(m.identity(os.stat(path))[:2]))
    try:
     measured=mode=='nonzero-measurement'
     assert owner.command(['never-executed'],cap=1,status=measured)==((7,b'') if measured else b'')
    except Exception: assert mode not in ('success','nonzero-measurement')
    else: assert mode in ('success','nonzero-measurement')
   assert owner.failure_stage==('operation' if mode in ('success','nonzero-measurement') else 'helper-finalize' if mode=='finalize-close' else 'helper')
   assert events[-3:]==['killpg','cgroup.kill','reap-and-reuse'],events
   assert ('helper-pending' in os.listdir(owner.control))==(mode in ('early-exit','timeout') or mode.startswith('restop-'))
   if mode=='success':
    assert events.index('cgroup.procs')<events.index('continue')<events.index('killpg')
    with patch.object(m.os,'fchown'),patch.object(m.os,'stat',side_effect=lambda *a,**kw:root_stat(real_stat(*a,**kw))),patch.object(m.os,'fstat',side_effect=lambda fd:root_stat(real_fstat(fd))),patch('builtins.open',side_effect=lambda p,*a,**kw:m.io.StringIO('populated 0\n') if p==owner.cg+'/cgroup.events' else real_open(p,*a,**kw)):
     owner.record('intent',{'generation':owner.generation});owner.record('root',list(m.identity(os.fstat(owner.fd))[:2]))
     real_unlink(owner.cg+'/helpers/cgroup.procs')  # fixture pseudo-file, not a kernel cgroup member
     fresh=m.Custody.__new__(m.Custody);fresh.__dict__.update(owner.__dict__);fresh.records=set()
     fresh.settle_children=lambda:events.append('cleanup');fresh.reopen()
     assert fresh.saved('retired')=={'generation':owner.generation,'failed':True} and not os.path.exists(owner.cg)
     assert events[-1]=='cleanup' and 'helper-pending' not in os.listdir(owner.control)
  finally: os.close(owner.control);os.close(owner.fd)
`,
    ],
    { encoding: "utf8", timeout: 10000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("product custody retirement crash cuts recover without reacquiring commands or adopting cgroups", () => {
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      String.raw`
import copy,importlib.util,json,os,selectors,tempfile,types
from unittest.mock import patch
s=importlib.util.spec_from_file_location('custody','dev/product-test/host-custody.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class Crash(BaseException): pass
for failed in (False,True):
 for cut in ('intent','helpers','parent'):
  for drift in ('none','identity','population','foreign-child','invalid-intent','pending','uncertain'):
   with tempfile.TemporaryDirectory() as root:
    cg=root+'/cgroup';os.mkdir(cg);os.mkdir(cg+'/helpers');os.mkdir(root+'/control')
    cgfd=os.open(cg,os.O_RDONLY|os.O_DIRECTORY)  # keep the original inode unavailable for reuse
    cid='b'*64;image='sha256:'+'c'*64;generation='a'*32;calls=[];removed=[];owners=[];armed=True
    journal={'intent':{'generation':generation},'root':list(m.identity(os.stat(root))[:2]),
     'cgroup':list(m.identity(os.stat(cg))[:2]),'disk':100,'worker-intent':{},
     'worker-receipt':{'id':cid,'spec':{'image':image}},'image-'+image[7:]:{'Config':{'Labels':{}}},
     'state-storage':{},'state-backing':[1,2],'state-loop':{'name':'/dev/loop9'},'state-mount':['exact-mount']}
    live=[{'name':'/dev/loop9'},['exact-mount']];present=True
    real_open=open;real_rmdir=os.rmdir
    def persist(n,v):
     assert n not in journal or journal[n]==v
     journal[n]=copy.deepcopy(v)
     with real_open(root+'/control/'+n,'wb') as f: f.write(m.canonical(v))
    for n,v in list(journal.items()): persist(n,v)
    def command(argv,*a,**kw):
     global present
     assert os.path.isdir(cg+'/helpers') and 'cgroup-retire-intent' not in journal,'command custody retired too soon'
     calls.append(argv[0])
     if argv[0]=='ps': return (cid+'\n').encode() if present else b''
     if argv[0]=='inspect': return m.canonical([{'Id':cid,'Image':image,'Config':{'Labels':{'cogs.product.generation':generation}}}])
     if argv[0]=='rm': assert argv==['rm','-f',cid];present=False
     if argv[0]=='umount': live[1]=None
     if argv[0]=='losetup': assert argv==['losetup','--detach','/dev/loop9'];live[0]=None
     return b''
    def observation(name): command(['inventory']);return tuple(live)
    def record(n,v):
     global armed
     if n=='cgroup-retire-intent':
      assert not present and live==[None,None] and 'state-detached' in journal
      assert ('evidence' in calls)==(not failed)
     persist(n,v)
     if n=='cgroup-retire-intent' and cut=='intent' and armed: armed=False;raise Crash()
    def owner():
     o=m.Custody.__new__(m.Custody);owners.append(o)
     o.root=root;o.cg=cg;o.generation=generation;o.recovery=True;o.failed=failed;o.disk=None
     o.fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY);o.control=os.open(root+'/control',os.O_RDONLY|os.O_DIRECTORY)
     o.ids={};o.images={};o.peers={};o.sealed=[];o.mounts=[];o.records=set(journal);o.selector=selectors.DefaultSelector()
     o.saved=lambda n:json.loads(m.capture(o.control,n));o.record=lambda n,v:(record(n,v),o.records.add(n))[0];o.command=command
     o.docker=lambda *args,**kw:command(list(args),**kw);o.storage_observation=observation
     o.evidence=lambda:command(['evidence'])
     return o
    def remove(path,*a,**kw):
     global armed
     assert path in (cg+'/helpers',cg) and journal['cgroup-retire-intent'] is True
     real_rmdir(path,*a,**kw);removed.append(path)
     if cut==('parent' if path==cg else 'helpers') and armed: armed=False;raise Crash()
    def opened(path,*a,**kw):
     return m.io.StringIO('populated '+('1' if drift=='population' and not armed else '0')+'\n') if path==cg+'/cgroup.events' else real_open(path,*a,**kw)
    try:
     with patch('builtins.open',side_effect=opened),patch.object(m.os,'rmdir',side_effect=remove),patch.object(m.os,'statvfs',return_value=types.SimpleNamespace(f_bfree=100,f_frsize=1)):
      first=owner();first.disk=100;first.ids={'worker':copy.deepcopy(journal['worker-receipt'])}
      first.images={image:journal['image-'+image[7:]]};first.mounts=['state']
      try: first.settle()
      except Crash: pass
      else: raise AssertionError('crash cut not reached')
      assert 'retired' not in journal and not present and live==[None,None]
      prior_calls=list(calls);prior_removed=list(removed)
      if drift=='identity':
       if os.path.exists(cg): os.rename(cg,cg+'.held')
       os.mkdir(cg)  # never adopt a replacement, including after parent absence
      if drift=='foreign-child' and os.path.exists(cg): os.mkdir(cg+'/foreign')
      if drift=='invalid-intent':
       journal.pop('cgroup-retire-intent');persist('cgroup-retire-intent',False)
      if drift in ('pending','uncertain'): persist('helper-'+drift,{'version':1,'generation':generation,'parent_pid':os.getpid()})
      fresh=owner()
      rejected=drift in ('identity','invalid-intent','pending','uncertain') or drift in ('population','foreign-child') and cut!='parent'
      try: fresh.reopen()
      except (RuntimeError,OSError): assert rejected
      else:
       assert not rejected and journal['retired']=={'generation':generation,'failed':True}
       assert not os.path.exists(cg) and removed==[cg+'/helpers',cg]
       fresh.settle()  # repeating terminal settlement has no child effects or removals
       assert removed==[cg+'/helpers',cg]
      assert calls==prior_calls,'recovery reran Docker/inventory/helper commands'
      if rejected:
       assert 'retired' not in journal
       assert all(p!=cg for p in removed[len(prior_removed):])
       if drift=='foreign-child': assert os.path.isdir(cg+'/foreign')
    finally:
     os.close(cgfd)
     for o in owners: os.close(o.control);os.close(o.fd);o.selector.close()
`,
    ],
    { encoding: "utf8", timeout: 10000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("host custody line framing accepts bounded chunks and refuses a pipelined frame", async () => {
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      String.raw`
import importlib.util,os,threading
s=importlib.util.spec_from_file_location('custody','dev/product-test/host-custody.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
r,w=os.pipe(); payload=b'x'*100000+b'\n'
def write_all():
 view=memoryview(payload)
 while view: view=view[os.write(w,view):]
 os.close(w)
t=threading.Thread(target=write_all);t.start()
assert m.line(r,len(payload))==payload; os.close(r);t.join()
r,w=os.pipe();os.write(w,b'{"one":1}\n{"two":2}\n')
try: m.line(r,1024)
except RuntimeError: pass
else: raise AssertionError('pipelined frame accepted')
os.close(r);os.close(w)
assert m.OPERATIONS==frozenset(('authenticate','capability-probe','create','evidence','exec','file','image','lease','lease-directory','mkdir','pair','provenance','seal','settle','status','storage'))
assert m.PROVENANCE_SUBSTAGES==frozenset(('final-head','status','baseline','source','inventory','build-receipt','layer-prefix','layer-count','environment'))
r,w=os.pipe();old=os.dup(1);os.dup2(w,1)
try: m.emit_diagnostic('a'*32,'provenance','layer-count',True)
finally: os.dup2(old,1);os.close(old);os.close(w)
assert os.read(r,256)==b'{"cleanup":"uncertain","diagnostic":"provenance","generation":"'+b'a'*32+b'","substage":"layer-count"}\n';os.close(r)
for stage,substage in (('operation',None),('image','inventory'),('provenance','unknown')):
 try: m.emit_diagnostic('a'*32,stage,substage)
 except RuntimeError: pass
 else: raise AssertionError('unknown diagnostic admitted')
`,
    ],
    { encoding: "utf8", timeout: 10_000 },
  );
  assert.equal(result.status, 0, result.stderr);
  // A constructor that cannot acquire an owner has no closure proof, so its
  // sole public frame is conservatively cleanup-uncertain.
  const unavailable = spawnSync("python3", ["-I", "-B", "dev/product-test/host-custody.py"], {
    input: `{"generation":"${"a".repeat(32)}","seconds":60}\n`,
    encoding: "utf8",
    timeout: 10_000,
  });
  assert.equal(unavailable.status, 1, unavailable.stderr);
  assert.equal(
    unavailable.stdout,
    `{"cleanup":"uncertain","diagnostic":"constructor","generation":"${"a".repeat(32)}"}\n`,
  );
  const root = "/custody/authority";
  for (const [name, leafSubject] of [
    ["envoy", "/CN=fixture.cogs.test"],
    ["telemetry", "/CN=127.0.0.1"],
  ] as const) {
    const argv = syntheticPkiArgv(root, name);
    assert.deepEqual(argv, [
      ["genpkey", "-quiet", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", `${root}/${name}-ca.key`],
      [
        "req",
        "-x509",
        "-key",
        `${root}/${name}-ca.key`,
        "-sha256",
        "-days",
        "1",
        "-subj",
        `/CN=synthetic-${name}-CA`,
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-out",
        `${root}/${name}-ca.crt`,
      ],
      ["genpkey", "-quiet", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", `${root}/${name}.key`],
      ["req", "-new", "-key", `${root}/${name}.key`, "-subj", leafSubject, "-out", `${root}/${name}.csr`],
      [
        "x509",
        "-req",
        "-in",
        `${root}/${name}.csr`,
        "-CA",
        `${root}/${name}-ca.crt`,
        "-CAkey",
        `${root}/${name}-ca.key`,
        "-set_serial",
        "1",
        "-days",
        "1",
        "-extfile",
        `${root}/${name}.ext`,
        "-out",
        `${root}/${name}.crt`,
      ],
    ]);
    assert.equal(
      argv.filter(([command]) => command === "req").every((command) => command.includes("-key")),
      true,
    );
    assert.equal(argv.flat().includes("-newkey"), false);
    assert.equal(
      argv
        .filter(([command]) => command === "req")
        .flat()
        .includes("-quiet"),
      false,
    );
  }
  const runner = await readFile("dev/product-test/runner.ts", "utf8");
  assert.ok(runner.includes('for (const args of syntheticPkiArgv(root, name)) await run("openssl", [...args]);'));
  assert.equal(runner.includes("args.split("), false);
});

test("product custody diagnostics are closed, provenance-paired, and failure artifacts have no authority", async () => {
  const owner = await readFile("dev/product-test/snapshot-owner.ts", "utf8");
  const custody = await readFile("dev/product-test/host-custody.py", "utf8");
  const workflow = await readFile(".github/workflows/insecure-container.yml", "utf8");
  assert.match(owner, /diagnostics\.has\(result\.diagnostic as string\)[\s\S]*paired[\s\S]*cleanup/u);
  assert.doesNotMatch(owner, /result\.diagnostic === "operation"/u);
  assert.match(custody, /self\.failure_stage, self\.failure_substage = "helper-finalize", None/u);
  assert.match(custody, /stage, substage = self\.failure_stage, self\.failure_substage/u);
  for (const stage of [
    "final-head",
    "status",
    "baseline",
    "source",
    "inventory",
    "build-receipt",
    "layer-prefix",
    "layer-count",
    "environment",
  ])
    assert.ok(custody.includes(`self.failure_substage = "${stage}"`), stage);
  assert.match(workflow, /'pass_authority':False,'probe_authority':False/u);
  assert.doesNotMatch(workflow, /partial_output_sha256/u);
  assert.match(workflow, /'run_id':build\['run_id'\],'run_attempt':build\['run_attempt'\]/u);
});

test("workflow failure conversion accepts only closed fake diagnostics and prior exact probes", () => {
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      String.raw`
import hashlib,json,os,re,subprocess,tempfile
from pathlib import Path
from textwrap import dedent
text=Path('.github/workflows/insecure-container.yml').read_text()
source=dedent(re.search(r"<<'PY' \|\| :\n(.*?)\n          PY",text,re.S).group(1))
with tempfile.TemporaryDirectory() as root:
 build=Path(root)/'build.json'; receipt=Path(root)/'receipt'
 bound={'candidate':'a'*40,'tree':'b'*40,'source_inventory':'sha256:'+'c'*64,'run_id':'1','run_attempt':'1','skills':'empty'}
 build.write_text(json.dumps(bound,sort_keys=True,separators=(',',':'))+'\n')
 source=source.replace("'/var/lib/cogs-product-test/build-receipt.json'", "os.environ['BUILD']")
 def convert(rows,authority='probe-only',trailing=b''):
  if receipt.exists(): receipt.chmod(0o600)
  receipt.write_bytes(b''.join(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n' for row in rows)+trailing)
  env={**os.environ,'BUILD':str(build),'RECEIPT':str(receipt),'CANDIDATE':'a'*40,'PROFILE':'empty','AUTHORITY':authority,'STATUS':'1','RUNNER_UID':str(os.getuid()),'RUNNER_GID':str(os.getgid())}
  subprocess.run(['python3','-I','-B','-c',source],env=env,check=True)
  return json.loads(receipt.read_bytes())
 probe={'purpose':'capability-probe','generation':'d'*32,'retired_generation':'d'*32,**bound,'profile_case':'empty','build_receipt_sha256':'sha256:'+hashlib.sha256((json.dumps(bound,sort_keys=True,separators=(',',':'))+'\n').encode()).hexdigest(),'container_id':'e'*64,'removed':'KILL','start_code':0,'running':True,'ssh':True,'sftp':True}
 failure={'version':'cogs.product-failure-diagnostic/v1','generation':'f'*32,'diagnostic':'provenance','substage':'layer-count','cleanup':'uncertain','pass_authority':False,'probe_authority':False}
 accepted=convert([probe,failure])
 assert accepted['generation']=='f'*32 and accepted['diagnostic']=='provenance' and accepted['substage']=='layer-count' and accepted['cleanup_uncertain'] is True
 for hostile in ([probe,failure,{'unknown':True}], [probe,failure]):
  result=convert(hostile,trailing=(b'unknown\n' if len(hostile)==2 else b''))
  assert result['diagnostic']=='constructor' and result['cleanup_uncertain'] is True and 'generation' not in result
 assert convert([], 'candidate-pass')['diagnostic']=='constructor'
 assert convert([probe,failure], 'candidate-pass')['diagnostic']=='constructor'
`,
    ],
    { encoding: "utf8", timeout: 10_000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("product failure diagnostics retain only a closed provenance frame or conservative constructor uncertainty", () => {
  const frame = Object.freeze({
    generation: "a".repeat(32),
    diagnostic: "provenance",
    substage: "layer-count",
    cleanup: "uncertain" as const,
  });
  const line = productFailureDiagnostic("a".repeat(32), frame);
  assert.deepEqual(line, {
    version: "cogs.product-failure-diagnostic/v1",
    generation: "a".repeat(32),
    diagnostic: "provenance",
    substage: "layer-count",
    cleanup: "uncertain",
    pass_authority: false,
    probe_authority: false,
  });
  assert.ok(Object.isFrozen(line));
  assert.deepEqual(productFailureDiagnostic("b".repeat(32), frame), {
    version: "cogs.product-failure-diagnostic/v1",
    generation: "b".repeat(32),
    diagnostic: "constructor",
    cleanup: "uncertain",
    pass_authority: false,
    probe_authority: false,
  });
});

test("product custody aggregates operation, settlement, and closure failures", async () => {
  const operation = new Error("operation"),
    settlement = new Error("settlement"),
    closure = new Error("closure");
  const calls: string[] = [];
  const host: CustodyPort = {
    root: "/custody",
    generation: "a".repeat(32),
    request: async (op) => {
      calls.push(op);
      throw settlement;
    },
    closed: new Promise((_, reject) => setTimeout(() => reject(closure), 0)),
  };
  await assert.rejects(
    withProductCustody(host, async () => {
      throw operation;
    }),
    (error: unknown) => {
      assert.ok(error instanceof AggregateError);
      assert.deepEqual(error.errors, [operation, settlement, closure]);
      return true;
    },
  );
  assert.deepEqual(calls, ["settle"]);
  const uncertain: CustodyPort = {
    ...host,
    request: async <T>() => ({ retired: true, failed: true }) as T,
    closed: Promise.resolve(),
  };
  await assert.rejects(withProductCustody(uncertain, async () => true));
});

test("every capability-removal scenario executes create/start/pinned SSH/SFTP/probe/receipt cleanup without worker authority", async () => {
  const generation = "a".repeat(32);
  const full: ContainerSpec = {
    image: `sha256:${"c".repeat(64)}`,
    network: "none",
    caps: SANDBOX_CAPABILITIES,
    mask: SANDBOX_CAPABILITY_MASK,
    mounts: [],
    tmpfs: {},
  };
  const scenarios: Array<Array<Record<string, unknown>>> = [];
  for (const removed of SANDBOX_CAPABILITIES) {
    for (const failure of [undefined, "create", "capability-probe", "settle"] as const) {
      const calls: Array<Record<string, unknown>> = [];
      const host: CustodyPort = {
        root: `/var/lib/cogs-product-test/${generation}`,
        generation,
        purpose: "capability-probe",
        closed: Promise.resolve(),
        request: async <T>(op: string, fields: Record<string, unknown> = {}) => {
          calls.push({ generation, op, ...fields });
          if (op === failure) throw new Error("injected uncertainty");
          return (
            op === "create"
              ? "b".repeat(64)
              : op === "settle"
                ? { retired: true, failed: true }
                : { purpose: "capability-probe", removed }
          ) as T;
        },
      };
      const execute = () =>
        withProductCustody(host, async () => {
          assert.deepEqual(await capabilityRemovalScenario(host, full, removed), {
            purpose: "capability-probe",
            removed,
          });
          return false;
        });
      if (failure) await assert.rejects(execute);
      else await execute();
      assert.deepEqual(
        calls.map((q) => q.op),
        failure === "create" ? ["create", "settle"] : ["create", "capability-probe", "settle"],
      );
      assert.equal(calls.at(-1)?.passed, false);
      assert.ok(calls[0]);
      const spec = calls[0].spec as ContainerSpec;
      assert.deepEqual(spec, { ...full, ...sandboxCapabilities(removed) });
      assert.deepEqual(
        (calls[0].argv as string[]).filter((_, i, a) => a[i - 1] === "--cap-add"),
        spec.caps,
      );
      assert.throws(() => containerArguments({ ...host, purpose: "run" }, spec, [], "0:0"));
      assert.throws(() => containerArguments(host, full, [], "0:0"));
      if (!failure) scenarios.push(calls);
    }
  }
  const result = spawnSync(
    "python3",
    [
      "-I",
      "-B",
      "-c",
      String.raw`
import copy,importlib.util,json,os,selectors,sys,types
from unittest.mock import patch
s=importlib.util.spec_from_file_location('custody','dev/product-test/host-custody.py')
m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
scenarios=json.load(sys.stdin)
for plan in scenarios:
 for mode in ('success','start-failure','ssh-denied','sftp-denied','lost-start','lost-probe','foreign-cleanup'):
  owner=m.Custody.__new__(m.Custody);owner.generation=plan[0]['generation'];owner.root='/var/lib/cogs-product-test/'+owner.generation
  owner.probe=True;owner.recovery=False;owner.failed=False;owner.cg='/fake-cgroup';owner.disk=None
  owner.ids={};owner.peers={};owner.sealed=[];owner.mounts=[];owner.fd=8;owner.control=9;owner.selector=selectors.DefaultSelector()
  owner.build={'candidate':'a'*40,'tree':'b'*40,'source_inventory':'sha256:'+'c'*64,'run_id':'1','run_attempt':'1','skills':'empty','profile_case':'empty'}
  journal={};calls=[];alive=False;auth=0;cid='b'*64;spec=plan[0]['spec']
  owner.records=set()
  owner.images={spec['image']:{'Config':{'Env':[],'Labels':{}}}}
  owner.record=lambda n,v:journal.setdefault(n,copy.deepcopy(v));owner.saved=lambda n:journal[n]
  def inspect(identity):
   assert identity==cid
   return {'Image':spec['image'],'State':{'Running':alive},'Config':{'Env':['COGS_PROXY_ENDPOINT=http://127.0.0.1:18080'],'Labels':{'cogs.product.generation':'foreign' if mode=='foreign-cleanup' else owner.generation}}}
  owner.inspect=inspect
  def docker(op,*args,**kw):
   global alive
   calls.append(op)
   if op=='create': return (cid+'\n').encode()
   if op=='start':
    assert 'sandbox-receipt' in journal and owner.ids['sandbox']['id']==cid
    assert kw=={'status':True};alive=mode!='start-failure'
    if mode=='lost-start': raise RuntimeError('lost start')
    return (1 if mode=='start-failure' else 0),b''
   if op=='ps': return (cid+'\n').encode() if 'rm' not in calls else b''
   assert op=='rm' and args==('-f',cid);alive=False;return b''
  owner.docker=docker
  def authenticate(role):
   global auth
   calls.append('authenticate');auth+=1
   assert role=='sandbox' and alive
   if mode=='lost-probe': raise RuntimeError('dead authenticated identity')
   owner.ids[role]['pid']=42;return owner.ids[role]
  owner.authenticate=authenticate
  def command(argv,**kw):
   program=argv[3];calls.append(program)
   assert argv[:3]==['nsenter','--net=/proc/self/fd/77','--'] and program in ('ssh','sftp')
   assert kw=={'status':True,'pass_fds':(77,)} and auth>=2
   for value in ('-F','/dev/null','BatchMode=yes','IdentitiesOnly=yes','IdentityAgent=none','StrictHostKeyChecking=yes','GlobalKnownHostsFile=/dev/null','UserKnownHostsFile='+owner.root+'/authority/known_hosts',owner.root+'/authority/client','root@127.0.0.1'): assert value in argv,value
   if program=='sftp': assert argv[-3:]==['-b',owner.root+'/authority/sftp-batch','root@127.0.0.1']
   return (1,b'') if mode==program+'-denied' else (0,b'cogs-capability-probe' if program=='ssh' else b'listing')
  owner.command=command
  with patch.object(m.os,'listdir',side_effect=lambda fd:list(journal)),patch.object(m.os.path,'exists',return_value=False),patch.object(m.os,'open',return_value=77) as opened,patch.object(m.os,'close') as closed:
   try:
    owner.dispatch(copy.deepcopy(plan[0]));measurement=owner.dispatch(copy.deepcopy(plan[1]))
    assert measurement['purpose']=='capability-probe' and measurement['container_id']==cid
    assert measurement['removed']==next(c for c in m.CAPABILITIES if c not in spec['caps'])
    assert measurement['running']==(mode!='start-failure') and measurement['start_code']==int(mode=='start-failure')
    assert measurement['ssh']==(None if mode=='start-failure' else mode!='ssh-denied')
    assert measurement['sftp']==(None if mode in ('start-failure','ssh-denied') else mode!='sftp-denied')
   except RuntimeError: assert mode in ('lost-start','lost-probe')
   finally:
    try: assert owner.dispatch(copy.deepcopy(plan[2]))=={'retired':True,'failed':True}
    except RuntimeError: assert mode=='foreign-cleanup' and 'rm' not in calls and 'retired' not in journal
   assert calls[:2]==['create','start']
   assert ('rm' in calls)==(mode!='foreign-cleanup')
   assert not any('worker' in n or 'lease' in n or 'evidence' in n for n in journal)
   if mode=='success': assert calls.index('start')<calls.index('ssh')<calls.index('sftp')<calls.index('rm')
   if opened.called: closed.assert_called_once_with(77)
  owner.selector.close()
 # Python custody independently rejects reduced run sets, full probe sets and other capability mutations before create.
 for probe,caps,mask in [(False,spec['caps'],spec['mask']),(True,list(m.CAPABILITIES),sum(2**b for b in m.CAPABILITIES.values())),(True,spec['caps'][:-1],spec['mask']),(True,spec['caps']+['SYS_ADMIN'],spec['mask']),(True,spec['caps'],0)]:
  owner.ids={};owner.probe=probe;calls.clear();q=copy.deepcopy(plan[0]);q['spec'].update(caps=caps,mask=mask)
  try: owner.dispatch(q)
  except RuntimeError: pass
  else: raise AssertionError('capability authority drift')
  assert not calls
 owner.probe=True
 for op in ('lease','evidence','status','authenticate','create','settle'):
  q={'op':op,'generation':owner.generation,'role':'worker','spec':spec,'passed':True}
  try: owner.dispatch(q)
  except RuntimeError: pass
  else: raise AssertionError('probe gained '+op+' authority')
`,
    ],
    { input: JSON.stringify(scenarios), encoding: "utf8", timeout: 10000 },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("worker OTLP fetch and first cancellation keep production actual cleanup pending", async () => {
  for (const mode of ["fetch", "cancel"] as const) {
    const h = harness(),
      held = Promise.withResolvers<void>(),
      entered = Promise.withResolvers<void>();
    let lifecycle!: LaunchLifecycle;
    let retired = false,
      closed = false;
    const sink = createCogsWorkerTelemetrySink({
      mode: "otlp",
      tracesEndpoint: "https://synthetic.invalid/v1/traces",
      metricsEndpoint: "https://synthetic.invalid/v1/metrics",
      capacity: 1,
      timeoutMs: 50,
      fetch: Object.freeze(async () => {
        entered.resolve();
        if (mode === "fetch") await held.promise;
        return new Response(new ReadableStream({ cancel: () => held.promise }), { status: 503 });
      }),
    });
    const worker = await startProductionWorker({
      seams: {
        ...h.seams,
        createTelemetry: () => sink,
        createLifecycle: (options) => (lifecycle = new LaunchLifecycle(options)),
      },
    });
    await entered.promise;
    const closing = worker.close().then(() => {
      closed = true;
    });
    const actual = joinCloseWork(beginRegisteredClose(worker)).then(() => {
      retired = true;
    });
    try {
      await new Promise((resolve) => setTimeout(resolve, 100));
      assert.equal(closed, false, mode);
      assert.equal(retired, false, mode);
      assert.notEqual(lifecycle.state, "stopped");
    } finally {
      held.resolve();
    }
    await Promise.all([closing, actual, worker.closed]);
    assert.equal(lifecycle.state, "stopped", "optional collector failure is nonfatal");
  }
});

const secretBearer = "bearer-production-value-000000000000";
const secretProxy = "proxy-production-capability-00000";

test("production auth and Pi startup retain unpinned fetch/cancel before dependency release without healing failure", async () => {
  for (const phase of ["auth", "pi"] as const)
    for (const mode of ["fetch", "cancel"] as const) {
      const h = harness();
      const held = Promise.withResolvers<void>();
      const entered = Promise.withResolvers<void>();
      let lifecycle!: LaunchLifecycle;
      let reads = 0;
      let cancelled = false;
      const store = new OpenBaoModelApiKeyStore({
        origin: "https://synthetic.invalid/",
        mount: "model",
        identity: { withToken: async (_signal, consume) => consume("synthetic-token") },
        fetchImpl: async () => {
          if (++reads === 1 && phase === "pi")
            return new Response(
              JSON.stringify({
                data: {
                  data: { api_key: "synthetic-model-key" },
                  metadata: {
                    version: 1,
                    created_time: "2026-01-01T00:00:00Z",
                    deletion_time: "",
                    destroyed: false,
                    custom_metadata: null,
                  },
                },
              }),
              { headers: { "content-type": "application/json" } },
            );
          entered.resolve();
          if (mode === "fetch") await held.promise;
          return new Response(
            new ReadableStream({
              start(stream) {
                stream.enqueue(new TextEncoder().encode("{"));
              },
              cancel() {
                cancelled = true;
                return held.promise;
              },
            }),
            { headers: { "content-type": "application/json" } },
          );
        },
      });
      const starting = assert.rejects(
        startProductionWorker({
          seams: {
            ...h.seams,
            createModelStore: () => store,
            createLifecycle: (options) => (lifecycle = new LaunchLifecycle(options)),
            createPi: async (options) => {
              await options.modelApiKeys.withApiKey(
                {
                  userId: launch().user_id,
                  provider: launch().model.provider,
                  model: launch().model.id,
                  credentialHandle: launch().model.credential_handle,
                  ...(options.signal ? { signal: options.signal } : {}),
                },
                async () => undefined,
              );
              return h.seams.createPi(options);
            },
          },
        }),
        ProductionWorkerError,
      );
      await entered.promise;
      await new Promise((resolve) => setImmediate(resolve));
      const rejected = assert.rejects(lifecycle.requestShutdown("held-auth", closeContext(20)));
      await new Promise((resolve) => setTimeout(resolve, 40));
      await rejected;
      let retired = false;
      const work = lifecycle.closeWork;
      assert.ok(work);
      const retirement = Promise.all([work.done, work.retired]).then(() => {
        retired = true;
      });
      try {
        assert.equal(retired, false);
        assert.equal(h.log.includes("ssh.close"), false);
        assert.equal(h.log.includes("telemetry.close"), false);
        assert.equal(h.log.includes("egress.close"), false);
        if (mode === "cancel") assert.equal(cancelled, true);
      } finally {
        held.resolve();
      }
      await starting;
      await retirement;
      assert.equal(lifecycle.state, "failed");
      assert.equal(h.log.includes("ssh.close"), true);
      assert.equal(h.log.includes("telemetry.close"), true);
    }
});

test("actual manager/watcher owner cancellation is clean, but revocation before or during shutdown stays failed", async () => {
  for (const mode of ["requested", "revoked", "racing-revocation"] as const) {
    const h = harness();
    const document = launch({
      integrations: launch().integrations.map((value) => {
        assert.ok(value !== null && typeof value === "object" && !Array.isArray(value));
        return { ...value, preset_revision: canonicalPresetPolicyRevision(value) };
      }),
    });
    const held = Promise.withResolvers<void>();
    const denied = Promise.withResolvers<void>();
    const replaced = Promise.withResolvers<void>();
    let lifecycle!: LaunchLifecycle;
    let poll!: () => void;
    let revoked = false,
      released = false;
    const events: string[] = [];
    const config: CogsEnvoyRuntimeConfig = {
      bootstrapJson: "{}",
      routeCount: 1,
      paths: {
        bootstrap: "/run/cogs/egress/envoy/bootstrap.json",
        proxyCertificate: "/run/cogs/egress/envoy/proxy-cert.pem",
        proxyPrivateKey: "/run/cogs/egress/envoy/proxy-key.pem",
        proxyCaCertificate: "/run/cogs/egress/envoy/proxy-ca.pem",
      },
    };
    const worker = await startProductionWorker({
      seams: {
        ...h.seams,
        readLaunch: async () => document,
        createLifecycle(options) {
          lifecycle = new LaunchLifecycle(options);
          return lifecycle;
        },
        createEgress(options) {
          return startCogsEgressRuntimeManager({
            ...options,
            maxSessionExpiresAtMs: 20000,
            nowMs: () => 5000,
            randomSecret: () => "S".repeat(32),
            telemetry: { mode: "injected-stub-evidence" },
            operationTimeoutMs: 1000,
            revocationPollIntervalMs: 50,
            revocationMinPkiRemainingMs: 1000,
            timers: {
              setTimeout(callback, ms) {
                if (ms === 50) {
                  poll = callback;
                  return undefined;
                }
                return setTimeout(callback, ms);
              },
              clearTimeout(timer) {
                clearTimeout(timer as ReturnType<typeof setTimeout>);
              },
            },
            revocation: {
              mode: "injected",
              credentialVersion: "cred1",
              credentialSource: {
                withCredential: async (_request, consume) => consume({ type: "bearer", token: "synthetic-token" }),
              },
              revocationSource: {
                read: async () => ({
                  presetRevision: aggregateCogsEgressRoutePlanRevision(lowerLaunchEgressRoutePlan(options.launch)),
                  credentialVersion: "cred1",
                  revoked,
                  pkiExpiresAtMs: 10000,
                }),
              },
            },
            pkiSource: {
              withPkiMaterial: async (_request, consume) =>
                consume({
                  certificateChainPem: "cert",
                  privateKeyPem: "key",
                  caCertificatePem: "ca",
                  expiresAtMs: 10000,
                }),
            },
            envoyProcess: {
              start: async () => ({
                ready: true,
                close: async () => {
                  events.push("process.close");
                },
              }),
            },
            onReplacementRequired: async (reason, signal) => {
              events.push(reason);
              await options.onReplacementRequired(reason, signal);
              replaced.resolve();
            },
            ports: {
              openWal: async () => ({
                ready: true,
                records: [],
                append: async () => {
                  throw new Error("unused");
                },
                close: async () => {
                  events.push("wal.close");
                },
              }),
              startAuthz: async () =>
                ({
                  ready: true,
                  target: "127.0.0.1:12345",
                  close: async () => {
                    events.push("authz.close");
                    denied.resolve();
                    if (mode === "racing-revocation") await held.promise;
                  },
                }) as CogsExtAuthzServer,
              withConfig: async (_options, _source, consume) => consume(config),
              withTmpfs: async (_config, _pki, consume) => {
                try {
                  return await consume(config.paths);
                } finally {
                  released = true;
                }
              },
            },
          });
        },
      },
    }).catch(() => assert.fail(JSON.stringify({ mode, log: h.log, events })));
    if (mode !== "requested") {
      revoked = true;
      poll();
      await denied.promise;
    }
    if (mode === "revoked") await replaced.promise;
    const closing = worker.close();
    void closing.catch(() => undefined);
    held.resolve();
    if (mode === "requested") {
      await closing;
      await worker.closed;
      assert.equal(lifecycle.state, "stopped");
      assert.ok(events.includes("cancelled"));
    } else {
      await assert.rejects(closing, ProductionWorkerError);
      await assert.rejects(worker.closed, ProductionWorkerError);
      assert.equal(lifecycle.state, "failed");
      assert.ok(events.includes("revoked"));
    }
    assert.equal(released, true);
    for (const event of ["authz.close", "process.close", "wal.close"])
      assert.equal(events.filter((v) => v === event).length, 1);
  }
});

function runtime(): RuntimeConfig {
  return {
    version: "cogs.runtime/v1alpha1",
    profile: "api-key-only",
    paths: {
      launch_document: "/etc/cogs/launch.json",
      api_bearer: "/run/cogs/api/bearer",
      openbao_jwt: "/run/cogs/openbao/jwt",
      proxy_capability: "/run/cogs/proxy/capability",
      envoy_executable: "/usr/local/bin/envoy",
      egress_tmpfs: "/run/cogs/egress",
      audit_wal: "/var/lib/cogs/session/egress-audit.wal",
      agent_directory: "/var/lib/cogs/session/agent",
      session_root: "/var/lib/cogs/session/sessions",
      shared_skill_oci: "/var/lib/cogs/skills/shared-oci",
      private_skill_source: "/var/lib/cogs/skills/private-source",
      private_skill_store: "/var/lib/cogs/skills/private-store",
      skill_snapshot_receipt: "/run/cogs/skills/snapshot-receipt.json",
      skill_snapshot_control_socket: "/run/cogs/skills/control.sock",
    },
    api: { listen_host: "127.0.0.1", port: 18081 },
    openbao: {
      origin: "https://openbao.internal/",
      kubernetes_auth_mount: "kubernetes",
      kubernetes_auth_role: "worker",
      model_kv_mount: "model",
      egress_kv_mount: "egress",
      pki_mount: "pki",
      pki_role: "egress",
      projected_jwt_ttl_seconds: 600,
      max_client_token_ttl_seconds: 600,
    },
    otlp: {
      protocol: "http/json",
      traces_endpoint: "https://otlp.internal/v1/traces",
      metrics_endpoint: "https://otlp.internal/v1/metrics",
      logs_endpoint: "https://otlp.internal/v1/logs",
    },
    egress: { listener_port: 18080, revocation_poll_seconds: 1, completion_capacity: 8 },
    lifecycle: { maximum_session_seconds: 28800, shutdown_timeout_seconds: 1 },
  };
}

function launch(overrides: Partial<LaunchConfig> = {}): LaunchConfig {
  return {
    version: "cogs.dev/v1alpha1",
    user_id: "alice",
    session_id: "session-1",
    workspace_id: "workspace-1",
    sandbox: {
      ssh_endpoint: "sandbox.internal:22",
      ssh_host_key: `SHA256:${"A".repeat(43)}`,
      client_key_path: "/run/cogs/ssh/session-1",
      proxy_auth_handle: "sessions/session-1/proxy",
    },
    model: { provider: "anthropic", id: "model-1", credential_handle: "users/alice/models/anthropic" },
    skills: {
      shared_revision: `sha256:${"a".repeat(64)}`,
      shared_path: "/shared/skills",
      user_revision: `sha256:${"b".repeat(64)}`,
      user_path: "/user/skills",
    },
    integrations: [
      {
        version: "cogs.integration/v1alpha1",
        id: "github",
        preset_revision: `sha256:${"c".repeat(64)}`,
        dns: { mode: "proxy-connect-authority", guest_resolution: false },
        auth: {
          type: "bearer_header",
          header: "Authorization",
          prefix: "Bearer ",
          placeholder: "COGS_PLACEHOLDER_GITHUB_TOKEN",
          secret_handle: "users/alice/integrations/github",
        },
        rules: [
          {
            name: "api",
            host: "api.github.com",
            port: 443,
            methods: ["GET"],
            path_patterns: ["/user"],
            path_policy: { strategy: "exact", normalization: "reject-ambiguous" },
            query_policy: { mode: "deny" },
            redirects: { mode: "deny", max_hops: 0, allowed_hosts: [] },
            inject_auth: true,
          },
        ],
      },
    ],
    limits: {
      cpu: 1,
      memory_bytes: 536870912,
      tool_timeout_seconds: 2,
      turn_timeout_seconds: 62,
      max_tool_output_bytes: 4096,
    },
    ...overrides,
  } as LaunchConfig;
}

function harness() {
  const log: string[] = [];
  let sshLost: (() => void) | undefined;
  let egressReady = true;
  let failAt = "";
  let cleanupFailure = "";
  let apiCloseWait: Promise<void> | undefined;
  let piCloseWait: Promise<void> | undefined;
  let piState: "idle" | "running" = "idle";
  let sshOptions: SshConnectionManagerOptions | undefined;
  const maybe = (stage: string) => {
    log.push(stage);
    if (failAt === stage) throw new Error(`${secretBearer}:${secretProxy}`);
  };
  const identity: OpenBaoIdentityPort = Object.freeze({
    withToken: async (_signal: AbortSignal, operation: (token: string) => Promise<void>) => operation("openbao-token"),
  });
  const model: ModelApiKeySource = Object.freeze({
    withApiKey: async (
      _request: Parameters<ModelApiKeySource["withApiKey"]>[0],
      operation: (apiKey: string) => Promise<void>,
    ) => {
      maybe("auth.probe");
      await operation("model-api-key");
    },
  });
  const ssh = {
    get ready() {
      return true;
    },
    start: async () => maybe("ssh.start"),
    shutdown: async () => {
      maybe("ssh.close");
      if (cleanupFailure === "ssh") throw new Error("ssh close secret");
    },
  } as unknown as SshConnectionManager;
  const egress: CogsEgressRuntimeManager = Object.freeze({
    get ready() {
      return egressReady;
    },
    listenerPort: 18080,
    replacementRequired: false,
    drainCompletions: () => Object.freeze([]),
    close: async () => {
      maybe("egress.close");
      if (cleanupFailure === "egress") throw new Error("egress close secret");
    },
  });
  registerCloseOwner(
    egress,
    createCloseOwner(() => egress.close()),
  );
  const pi = Object.freeze({
    input: async () => "running" as const,
    abort: async () => ({ aborted: false, runState: "idle" as const }),
    state: async () => {
      maybe("pi.state");
      return { runState: piState };
    },
    entries: async () => ({ entries: Object.freeze([]) }),
    createExport: async () => ({ mode: "raw" }) as JsonValue,
    dispose: async () => {
      maybe("pi.dispose");
      await piCloseWait;
      if (cleanupFailure === "pi") throw new Error("pi close secret");
    },
    disposeOwnedRuntime: async () => ({ version: "cogs.pi-owned-runtime-cleanup/v1alpha1", cleaned: true as const }),
    model: {} as CogsPiSessionPorts["model"],
    activeToolNames: () => Object.freeze(["read", "write", "edit", "bash"]),
    sessionFile: () => "/var/lib/cogs/session/sessions/session-1/session.jsonl",
    skillMetadata: () => undefined,
    gitMapRecords: () => Object.freeze([]),
    resolveGitMapping: async () => undefined,
    prepareShutdown: async () => {
      maybe("pi.prepare");
      return { version: "cogs.shutdown-ready/v1alpha1" };
    },
    navigate: async () => ({ cancelled: false }),
  }) as unknown as CogsPiSessionPorts;
  const api: ApiServer = Object.freeze({
    listen: async (port: number | undefined, host: string | undefined) => {
      maybe("api.listen");
      assert.equal(port, 18081);
      assert.equal(host, "127.0.0.1");
      return { port: port ?? 0 };
    },
    close: async () => {
      maybe("api.close");
      await apiCloseWait;
      if (cleanupFailure === "api") throw new Error("api close secret");
    },
    closeAdmission: () => maybe("api.admission.close"),
    publish: () => true,
  });
  registerCloseOwner(
    api,
    createCloseOwner(() => api.close()),
  );
  let telemetry: CogsWorkerTelemetrySink;
  const seams: ProductionWorkerSeams = Object.freeze({
    readRuntime: async () => {
      maybe("runtime");
      return runtime();
    },
    readLaunch: async () => {
      maybe("launch");
      return launch();
    },
    readSecret: async (kind) => {
      maybe(`secret.${kind}`);
      return kind === "api-bearer" ? secretBearer : secretProxy;
    },
    createIdentity: () => {
      maybe("identity");
      return identity;
    },
    createTelemetry: () => {
      maybe("telemetry");
      const base = createCogsWorkerTelemetrySink({ mode: "disabled" });
      telemetry = Object.freeze({
        get ready() {
          return base.ready;
        },
        span: base.span,
        metric: base.metric,
        snapshot: base.snapshot,
        close: async (signal?: AbortSignal) => {
          maybe("telemetry.close");
          await base.close(signal);
        },
      });
      return telemetry;
    },
    prepareStorage: async () => {
      maybe("storage");
      return Object.freeze({
        shared: Object.freeze({ resolve: async () => undefined }) as unknown as CogsSharedSkillOciResolver,
        private: Object.freeze({
          snapshot: async () => undefined,
          resolve: async () => undefined,
        }) as unknown as CogsPrivateSkillStore,
      });
    },
    verifyAuditWal: async () => maybe("audit"),
    createModelStore: () => {
      maybe("model-store");
      return model;
    },
    createSsh: (options: SshConnectionManagerOptions) => {
      maybe("ssh.create");
      sshOptions = options;
      sshLost = () => options.onLost?.("lost");
      return ssh;
    },
    createEgress: async (options: CogsEgressRuntimeManagerOptions) => {
      maybe("egress.start");
      assert.equal(options.proxyCapability, secretProxy);
      assert.equal(options.launch.user_id, "alice");
      assert.equal(options.revocation.mode, "openbao");
      assert.equal(options.telemetry.mode, "otlp");
      return egress;
    },
    createLifecycle: (options: LaunchLifecycleOptions) => {
      maybe("lifecycle");
      return new LaunchLifecycle(options);
    },
    createPi: async (options: AuthenticatedCogsPiSessionOptions) => {
      maybe("pi");
      assert.equal(options.emit({ kind: "warning", correlation_id: "startup", payload: { code: "startup" } }), false);
      assert.equal(options.streamFn, undefined);
      assert.equal(options.ownedRuntime, undefined);
      assert.equal("turnTimeoutMs" in options, false, "authenticated launch remains the sole turn authority");
      return pi;
    },
    createApi: (options: ApiServerOptions) => {
      maybe("api");
      assert.equal(options.bearerToken, secretBearer);
      assert.equal(options.exporter, pi);
      assert.equal(options.lifecycle.ready, true);
      return api;
    },
    now: Date.now,
    randomSecret: () => "internal-random-secret-value",
  });
  return {
    log,
    seams,
    setFail(stage: string) {
      failAt = stage;
    },
    setCleanupFailure(stage: string) {
      cleanupFailure = stage;
    },
    setCleanupWait(stage: "api" | "pi", work: Promise<void>) {
      if (stage === "api") apiCloseWait = work;
      else piCloseWait = work;
    },
    setPiState(state: "idle" | "running") {
      piState = state;
    },
    sshOptions() {
      return sshOptions;
    },
    loseSsh() {
      sshLost?.();
    },
    loseEgress() {
      egressReady = false;
    },
  };
}

function longTurnModelStream(): StreamFn {
  let calls = 0;
  return (model) => {
    calls += 1;
    const stream = createAssistantMessageEventStream();
    const content =
      calls === 1
        ? [{ type: "toolCall" as const, id: "long-tool-1", name: "bash", arguments: { command: "printf fixed" } }]
        : [{ type: "text" as const, text: "long turn settled durably" }];
    const message: AssistantMessage = {
      role: "assistant",
      content,
      api: "anthropic-messages",
      provider: "anthropic",
      model: model.id,
      usage: {
        input: 1,
        output: 1,
        cacheRead: 0,
        cacheWrite: 0,
        totalTokens: 2,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
      },
      stopReason: calls === 1 ? "toolUse" : "stop",
      timestamp: Date.now(),
    };
    queueMicrotask(() => {
      stream.push({ type: "start", partial: message });
      if (calls === 1) {
        const toolCall = message.content[0];
        if (toolCall?.type !== "toolCall") throw new Error("invalid long-turn fixture");
        stream.push({ type: "toolcall_start", contentIndex: 0, partial: message });
        stream.push({ type: "toolcall_end", contentIndex: 0, toolCall, partial: message });
      }
      stream.push({ type: "done", reason: calls === 1 ? "toolUse" : "stop", message });
      stream.end();
    });
    return stream;
  };
}

function emptyPreparedSkills(): never {
  const shared = "a".repeat(64);
  const user = "b".repeat(64);
  return Object.freeze({
    piSkills: Object.freeze([]),
    eagerTrustedSkillPrompt: "",
    agentsFiles: Object.freeze([]),
    metadata: Object.freeze({
      shared: Object.freeze({
        scope: "shared",
        revision: `sha256:${shared}`,
        bundleDigest: `sha256:${shared}`,
        guestRoot: "/shared/skills",
        guestSubtree: `/shared/skills/${shared}`,
        fileCount: 0,
        byteCount: 0,
        readOnlyEnforced: false,
      }),
      user: Object.freeze({
        scope: "user",
        revision: `sha256:${user}`,
        bundleDigest: `sha256:${user}`,
        guestRoot: "/user/skills",
        guestSubtree: `/user/skills/${user}`,
        fileCount: 0,
        byteCount: 0,
        readOnlyEnforced: false,
      }),
      agentsStatus: "missing",
      skillCount: 0,
    }),
    dispose: async () => undefined,
  }) as never;
}

test("schema-valid empty integrations reject in production immediately after both config reads", async () => {
  const h = harness();
  const empty = validateLaunchConfig(launch({ integrations: [] }));
  assert.equal(empty.integrations.length, 0, "shared launch schema remains deliberately unchanged");
  await assert.rejects(
    startProductionWorker({
      seams: {
        ...h.seams,
        readLaunch: async () => {
          await h.seams.readLaunch(runtime());
          return empty;
        },
      },
    }),
    ProductionWorkerError,
  );
  assert.deepEqual(h.log, ["runtime", "launch"], "no secrets, snapshots, telemetry, storage, auth, SSH, Pi or API");
});

test("production defaults to mounted authority and cannot fall back to guest materialization", async () => {
  const h = harness();
  let guestCalls = 0;
  await assert.rejects(
    startProductionWorker({
      seams: {
        ...h.seams,
        createSsh: (options) =>
          Object.assign(h.seams.createSsh(options), {
            withSftp: async () => {
              guestCalls++;
              throw new Error("guest must not be used without snapshot authority");
            },
          }),
        createPi: async (options) => {
          await options.skillPreparer.prepare({ launch: launch() });
          return h.seams.createPi(options);
        },
      },
    }),
    ProductionWorkerError,
  );
  assert.equal(guestCalls, 0);
  assert.equal(h.log.includes("api"), false);
  assert.equal(h.log.includes("ssh.close"), true);
  const source = await readFile(new URL("../src/runtime/compose.ts", import.meta.url), "utf8");
  assert.match(source, /skillPreparer: createCogsMountedSkillSessionPreparer/);
  assert.doesNotMatch(source, /createCogsSkillSessionPreparer/);
  assert.match(source, /await createCogsSharedSkillOciLayoutResolver/);
  assert.match(source, /await createCogsPrivateSkillStore/);
});

test("production SSH uses the sandbox image's single guest-root identity", async () => {
  const sshdConfig = await readFile(new URL("../images/sandbox/sshd_config", import.meta.url), "utf8");
  const allowedUsers = sshdConfig
    .split("\n")
    .filter((line) => line.startsWith("AllowUsers "))
    .flatMap((line) => line.slice("AllowUsers ".length).trim().split(/\s+/u));
  assert.deepEqual(allowedUsers, ["root"]);

  const h = harness();
  const worker = await startProductionWorker({ seams: h.seams });
  assert.equal(h.sshOptions()?.config.username, allowedUsers[0]);
  await worker.close();
});

test("production invokes SFTP with the exact schema-maximum operation timeout", async () => {
  const h = harness();
  let observed = 0;
  const ssh = h.seams.createSsh({} as SshConnectionManagerOptions);
  Object.assign(ssh, {
    withSftp: async (input: { operationTimeoutMs?: number }) => {
      observed = input.operationTimeoutMs ?? 0;
      throw new Error("bounded probe");
    },
  });
  await assert.rejects(
    startProductionWorker({
      seams: {
        ...h.seams,
        readLaunch: async () =>
          launch({ limits: { ...launch().limits, tool_timeout_seconds: 900, turn_timeout_seconds: 1200 } }),
        createSsh: () => ssh,
        createPi: async (options) => {
          await options.toolPorts.read({ path: "/workspace/f" });
          return h.seams.createPi(options);
        },
      },
    }),
    ProductionWorkerError,
  );
  assert.equal(observed, 900_000);
});

test("opt-in production turn timeout settles durable authenticated turn after 60 seconds", {
  skip: process.env.COGS_PRODUCTION_TURN_TIMEOUT_COMPOSED !== "1",
  timeout: 90_000,
}, async () => {
  const root = await mkdtemp(resolve(tmpdir(), "cogs-production-long-turn-"));
  const workspace = resolve(root, "workspace");
  const agentDir = resolve(root, "agent");
  const sessionRoot = resolve(root, "sessions");
  await mkdir(workspace, { recursive: true, mode: 0o700 });
  await mkdir(agentDir, { recursive: true, mode: 0o700 });
  await mkdir(sessionRoot, { recursive: true, mode: 0o700 });
  const h = harness();
  const events: string[] = [];
  let sessionFile: string | undefined;
  let piSession: CogsPiSessionPorts | undefined;
  let worker: ProductionWorkerRuntime | undefined;
  let interval: NodeJS.Timeout | undefined;
  let terminalTimer: NodeJS.Timeout | undefined;
  let failure: unknown;
  let cleanupFailure: unknown;
  let stdout: ((chunk: Buffer) => void) | undefined;
  let stderr: ((chunk: Buffer) => void) | undefined;
  const terminal = Promise.withResolvers<{ code: number; signal: null }>();
  const longPort: CogsExecPort = Object.freeze({
    onStdout: (listener: (chunk: Buffer) => void) => {
      stdout = listener;
    },
    onStderr: (listener: (chunk: Buffer) => void) => {
      stderr = listener;
    },
    terminal: () => terminal.promise,
    signal: async (name: "TERM" | "INT") => {
      if (interval !== undefined) clearInterval(interval);
      if (terminalTimer !== undefined) clearTimeout(terminalTimer);
      terminal.resolve({ code: 128, signal: name } as never);
    },
  });
  const immediatePort = (output: string): CogsExecPort => {
    let publish: ((chunk: Buffer) => void) | undefined;
    return Object.freeze({
      onStdout: (listener: (chunk: Buffer) => void) => {
        publish = listener;
      },
      onStderr: () => undefined,
      terminal: async () => {
        if (output) publish?.(Buffer.from(output));
        return { code: 0, signal: null };
      },
      signal: async () => undefined,
    });
  };
  const started = performance.now();
  try {
    worker = await startProductionWorker({
      seams: {
        ...h.seams,
        readLaunch: async () =>
          launch({
            model: { ...launch().model, id: "claude-sonnet-4-5" },
            limits: { ...launch().limits, tool_timeout_seconds: 90, turn_timeout_seconds: 150 },
          }),
        createSsh: (options) => {
          const manager = h.seams.createSsh(options);
          Object.assign(manager, {
            withBashExec: async (
              input: { wrappedCommand: string; signal?: AbortSignal },
              operation: (port: CogsExecPort, signal: AbortSignal) => Promise<unknown>,
            ) => {
              const operationSignal = input.signal ?? new AbortController().signal;
              if (input.wrappedCommand.includes("/usr/bin/git -C /workspace rev-parse"))
                return operation(immediatePort(`${"a".repeat(40)}\n`), operationSignal);
              if (input.wrappedCommand.includes("/usr/bin/git -C /workspace notes"))
                return operation(immediatePort(""), operationSignal);
              interval = setInterval(() => stdout?.(Buffer.from("progress\n")), 1000);
              terminalTimer = setTimeout(() => {
                if (interval !== undefined) clearInterval(interval);
                stdout?.(Buffer.from("fixed\n"));
                stderr?.(Buffer.alloc(0));
                terminal.resolve({ code: 0, signal: null });
              }, 61_500);
              return operation(longPort, operationSignal);
            },
          });
          return manager;
        },
        createPi: async (options) => {
          const pi = await createAuthenticatedCogsPiSession({
            ...options,
            cwd: workspace,
            agentDir,
            sessionRoot,
            streamFn: longTurnModelStream(),
            skillPreparer: Object.freeze({ prepare: async () => emptyPreparedSkills() }),
            emit: (event) => {
              events.push(event.kind);
              return options.emit(event);
            },
          });
          sessionFile = pi.sessionFile();
          piSession = pi;
          return pi;
        },
        createApi: createApiServer,
      },
    });
    const response = await fetch(`http://127.0.0.1:${worker.apiPort}/v1/input`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${secretBearer}`,
        "content-type": "application/json",
        "x-cogs-correlation-id": "long-turn-correlation",
      },
      body: JSON.stringify({ request_id: "long-turn-request", type: "prompt", content: "run long tool" }),
    });
    assert.equal(response.status, 202);
    const observationDeadline = started + 80_000;
    while (!events.includes("run_settled") && !events.includes("error") && performance.now() < observationDeadline)
      await new Promise((resolveTimer) => setTimeout(resolveTimer, 100));
    if (events.includes("error")) assert.fail("long production turn emitted an error terminal");
    const elapsed = performance.now() - started;
    assert.ok(elapsed >= 61_000, `turn settled too early: ${elapsed}`);
    assert.equal(events.filter((kind) => kind === "run_settled").length, 1);
    assert.ok(sessionFile);
    assert.ok(piSession);
    assert.equal((await lstat(sessionFile)).mode & 0o777, 0o600);
    const durable = await readFile(sessionFile, "utf8");
    assert.match(durable, /run long tool/);
    assert.match(durable, /long turn settled durably/);
    assert.match(durable, /fixed/);
    assert.doesNotMatch(durable, /model-api-key|bearer-production-value/);
    const history = await piSession.entries({ after: undefined, limit: 100 });
    assert.ok(JSON.stringify(history).includes("long turn settled durably"));
    assert.ok(piSession.gitMapRecords().some((record) => record.turn === 1));
  } catch (error) {
    failure = error;
  } finally {
    if (interval !== undefined) clearInterval(interval);
    if (terminalTimer !== undefined) clearTimeout(terminalTimer);
    if (worker !== undefined) {
      try {
        await worker.close();
        await worker.closed;
      } catch (error) {
        cleanupFailure = error;
      }
    }
    if (failure === undefined && cleanupFailure === undefined && sessionFile !== undefined) {
      try {
        const retiredBytes = await readFile(sessionFile, "utf8");
        const reopened = SessionManager.open(sessionFile, dirname(sessionFile), workspace);
        assert.ok(reopened.getEntries().some((entry) => entry.type === "message"));
        assert.match(retiredBytes, /long turn settled durably/);
      } catch (error) {
        cleanupFailure = error;
      }
    }
    try {
      await rm(root, { recursive: true, force: true });
    } catch (error) {
      cleanupFailure =
        cleanupFailure === undefined
          ? error
          : new AggregateError([cleanupFailure, error], "long-turn cleanup operations failed");
    }
  }
  if (failure !== undefined && cleanupFailure !== undefined)
    throw new AggregateError([failure, cleanupFailure], "long-turn assertion and cleanup both failed");
  if (failure !== undefined) throw failure;
  if (cleanupFailure !== undefined) throw cleanupFailure;
});

test("production composition starts in one exact fail-closed order and closes reverse-owned order", async () => {
  const h = harness();
  const worker = await startProductionWorker({ seams: h.seams }).catch((error) => {
    assert.fail(`startup failed after ${h.log.join(",")}: ${String(error)}`);
  });
  assert.equal(worker.ready, true);
  assert.deepEqual(h.log, [
    "runtime",
    "launch",
    "secret.api-bearer",
    "secret.proxy-capability",
    "identity",
    "telemetry",
    "model-store",
    "lifecycle",
    "storage",
    "ssh.create",
    "ssh.start",
    "auth.probe",
    "audit",
    "egress.start",
    "pi",
    "api",
    "api.listen",
  ]);
  await worker.close();
  await assert.rejects(worker.close("requested", { ...closeContext(1000), signal: AbortSignal.abort() }));
  await worker.close();
  await worker.closed;
  assert.deepEqual(h.log.slice(-8), [
    "api.admission.close",
    "pi.state",
    "pi.prepare",
    "pi.dispose",
    "api.close",
    "egress.close",
    "ssh.close",
    "telemetry.close",
  ]);
});

test("production seals admission then retires Pi, API events, and dependencies in order", async () => {
  const h = harness();
  let releaseApi!: () => void;
  const apiRetired = new Promise<void>((resolve) => {
    releaseApi = resolve;
  });
  let releasePi!: () => void;
  const piRetired = new Promise<void>((resolve) => {
    releasePi = resolve;
  });
  h.setCleanupWait("api", apiRetired);
  h.setCleanupWait("pi", piRetired);
  const worker = await startProductionWorker({ seams: h.seams });
  const closing = worker.close();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.log.includes("api.admission.close"), true);
  assert.equal(h.log.includes("api.close"), false);
  assert.equal(h.log.includes("pi.dispose"), true);
  assert.equal(h.log.includes("egress.close"), false);
  releasePi();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.log.includes("api.close"), true);
  assert.equal(h.log.includes("egress.close"), false);
  releaseApi();
  await closing;
  assert.equal(h.log.includes("egress.close"), true);
});

test("real production API keeps shutdown_ready publishable during admission shutdown, then retires events", async () => {
  for (const mode of ["http", "signal", "requested", "publication-failure"] as const) {
    const root = await mkdtemp(resolve(tmpdir(), "cogs-production-shutdown-"));
    const h = harness(),
      held = Promise.withResolvers<void>(),
      entered = Promise.withResolvers<void>();
    const controller = new AbortController();
    let api!: ApiServer, pi!: CogsPiSessionPorts, worker: ProductionWorkerRuntime | undefined;
    let prepares = 0,
      fatals = 0;
    const accepted: boolean[] = [];
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    try {
      const cwd = resolve(root, "cwd"),
        agentDir = resolve(root, "agent");
      await mkdir(cwd);
      await mkdir(agentDir);
      worker = await startProductionWorker({
        signal: controller.signal,
        seams: {
          ...h.seams,
          readRuntime: async () => ({ ...runtime(), api: { listen_host: "127.0.0.1", port: 0 } }),
          readLaunch: async () => launch({ model: { ...launch().model, id: "claude-sonnet-4-5" } }),
          createApi: (options) => (api = createApiServer(options)),
          createPi: async (options) => {
            pi = await createAuthenticatedCogsPiSession({
              ...options,
              cwd,
              agentDir,
              sessionRoot: resolve(root, "sessions"),
              skillPreparer: Object.freeze({ prepare: async () => emptyPreparedSkills() }),
              streamFn: longTurnModelStream(),
              toolPorts: { ...options.toolPorts, bash: async () => ({ stdout: "fixed", exitCode: 0 }) },
              git: {
                repositoryId: "workspace-1",
                observer: Object.freeze({
                  observeHead: async () => ({
                    kind: "observed" as const,
                    repo: "workspace-1",
                    commit: "a".repeat(40),
                    observed_at: "2026-01-01T00:00:00.000Z",
                  }),
                  nearestAncestor: async () => null,
                  appendNote: async () => true,
                  dispose: async () => undefined,
                }),
              },
              emit: (event) => {
                if (mode === "publication-failure" && event.kind === "shutdown_ready")
                  void api.close().catch(() => undefined);
                const result = options.emit(event);
                if (event.kind === "shutdown_ready") accepted.push(result);
                return result;
              },
              onFatal: (reason) => {
                fatals++;
                return options.onFatal(reason);
              },
            });
            const prepare = pi.prepareShutdown.bind(pi);
            Object.defineProperty(pi, "prepareShutdown", {
              value: async (input: Parameters<typeof prepare>[0]) => {
                prepares++;
                entered.resolve();
                await held.promise;
                return prepare(input);
              },
            });
            return pi;
          },
        },
      });
      await pi.input({ requestId: "settle", correlationId: "settle", kind: "prompt", content: "run" });
      for (let i = 0; i < 200 && (await pi.state()).runState !== "settled"; i++)
        await new Promise((resolve) => setTimeout(resolve, 10));
      assert.equal((await pi.state()).runState, "settled");
      const base = `http://127.0.0.1:${worker.apiPort}`;
      const headers = { authorization: `Bearer ${secretBearer}`, "content-type": "application/json" };
      const response = await fetch(`${base}/v1/events`, { headers });
      reader = response.body?.getReader();
      assert.ok(reader);
      let closing: Promise<void>;
      if (mode === "signal") {
        controller.abort();
        closing = worker.closed;
      } else if (mode === "requested") closing = worker.close();
      else {
        const shutdown = await fetch(`${base}/v1/shutdown`, { method: "POST", headers, body: "{}" });
        assert.equal(shutdown.status, 202);
        assert.deepEqual(await shutdown.json(), { version: "cogs.shutdown/v1alpha1", accepted: true });
        closing = worker.closed;
      }
      closing.catch(() => undefined);
      await entered.promise;
      assert.equal(worker.ready, false);
      assert.equal(h.log.includes("egress.close"), false);
      assert.deepEqual(accepted, []);
      assert.equal((await fetch(`${base}/health/ready`, { headers })).status, 503);
      assert.equal(
        (
          await fetch(`${base}/v1/input`, {
            method: "POST",
            headers,
            body: JSON.stringify({ request_id: "late", type: "prompt", content: "no" }),
          })
        ).status,
        503,
      );
      // Repeated shutdown is only an acknowledgement; it must not restart preparation.
      const repeated = await fetch(`${base}/v1/shutdown`, { method: "POST", headers, body: "{}" });
      assert.equal(repeated.status, 202);
      await repeated.arrayBuffer();
      held.resolve();
      if (mode === "publication-failure") {
        await assert.rejects(closing, ProductionWorkerError);
        assert.deepEqual(accepted, [false]);
        assert.ok(fatals > 0);
        assert.equal(h.log.includes("egress.close"), false);
        await assert.rejects(worker.close(), ProductionWorkerError);
      } else {
        let text = "";
        while (!text.includes('"kind":"shutdown_ready"')) {
          const frame = await reader.read();
          assert.equal(frame.done, false, "existing SSE stream must survive preparation");
          text += Buffer.from(frame.value ?? []).toString();
        }
        assert.equal(text.split('"kind":"shutdown_ready"').length - 1, 1);
        await closing;
        assert.deepEqual(accepted, [true]);
        assert.equal(fatals, 0);
        assert.equal(h.log.includes("egress.close"), true);
        await worker.close();
      }
      assert.equal(prepares, 1);
      assert.equal(
        api.publish({ kind: "pi_event", correlation_id: "late", payload: { event: { type: "agent_start" } } }),
        false,
      );
    } finally {
      held.resolve();
      await reader?.cancel().catch(() => undefined);
      await worker?.close().catch(() => undefined);
      await api?.close();
      await rm(root, { recursive: true, force: true });
    }
  }
});

test("production preparation rejection still disposes Pi and retires API without releasing dependencies", async () => {
  const h = harness();
  h.setFail("pi.prepare");
  const worker = await startProductionWorker({ seams: h.seams });
  await assert.rejects(worker.close(), ProductionWorkerError);
  assert.ok(h.log.indexOf("pi.prepare") < h.log.indexOf("pi.dispose"));
  assert.ok(h.log.indexOf("pi.dispose") < h.log.indexOf("api.close"));
  assert.equal(h.log.includes("egress.close"), false);
  await assert.rejects(worker.closed, ProductionWorkerError);
});

test("production late actual success cannot heal failed status or certify clean shutdown", async () => {
  const h = harness(),
    held = Promise.withResolvers<void>();
  h.setCleanupWait("api", held.promise);
  const worker = await startProductionWorker({ seams: h.seams });
  const first = worker.close("requested", { ...closeContext(1000), signal: AbortSignal.abort() });
  const later = worker.close();
  const rejectedLater = assert.rejects(later, ProductionWorkerError);
  assert.notEqual(first, later);
  await assert.rejects(first, ProductionWorkerError);
  assert.equal(h.log.includes("egress.close"), false);
  assert.equal(h.log.includes("ssh.close"), false);
  held.resolve();
  await rejectedLater;
  await assert.rejects(worker.closed, ProductionWorkerError);
  await assert.rejects(worker.close(), ProductionWorkerError);
  assert.equal(h.log.filter((entry) => entry === "api.close").length, 1);
  assert.equal(h.log.filter((entry) => entry === "egress.close").length, 1);
});

test("production Pi cleanup uncertainty blocks dependency and telemetry release", async () => {
  const h = harness();
  h.setCleanupFailure("pi");
  const worker = await startProductionWorker({ seams: h.seams });
  await assert.rejects(worker.close(), ProductionWorkerError);
  assert.equal(h.log.includes("egress.close"), false);
  assert.equal(h.log.includes("ssh.close"), false);
  assert.equal(h.log.includes("telemetry.close"), false);
});

test("every production startup seam fails generically, redacts secrets, and rolls back only acquired owners", async () => {
  const stages = [
    "runtime",
    "launch",
    "secret.api-bearer",
    "secret.proxy-capability",
    "identity",
    "telemetry",
    "model-store",
    "lifecycle",
    "storage",
    "ssh.create",
    "ssh.start",
    "auth.probe",
    "audit",
    "egress.start",
    "pi",
    "api",
    "api.listen",
  ];
  for (const stage of stages) {
    const h = harness();
    h.setFail(stage);
    await assert.rejects(
      startProductionWorker({ seams: h.seams }),
      (error: unknown) => {
        assert.ok(error instanceof ProductionWorkerError, stage);
        assert.equal(error.message, "production worker unavailable");
        assert.doesNotMatch(
          `${error.name}:${error.message}:${error.stack ?? ""}`,
          /bearer-production|proxy-production/,
        );
        return true;
      },
      stage,
    );
  }
});

test("dependency loss revokes the runtime, and close uncertainty remains a generic failure", async () => {
  const lost = harness();
  const worker = await startProductionWorker({ seams: lost.seams });
  lost.loseSsh();
  await assert.rejects(worker.closed, ProductionWorkerError);
  assert.ok(lost.log.indexOf("api.close") < lost.log.indexOf("egress.close"));

  const egressLost = harness();
  const egressWorker = await startProductionWorker({ seams: egressLost.seams });
  egressLost.loseEgress();
  await new Promise((resolve) => setTimeout(resolve, 150));
  await assert.rejects(egressWorker.closed, ProductionWorkerError);

  const uncertain = harness();
  uncertain.setCleanupFailure("egress");
  const second = await startProductionWorker({ seams: uncertain.seams });
  await assert.rejects(second.close(), ProductionWorkerError);
  await assert.rejects(second.closed, ProductionWorkerError);
});

test("late Pi startup remains owned before dependency and telemetry release", async () => {
  const h = harness();
  let entered!: () => void;
  const factoryEntered = new Promise<void>((resolve) => {
    entered = resolve;
  });
  let release!: () => void;
  const delayed = new Promise<void>((resolve) => {
    release = resolve;
  });
  const seams: ProductionWorkerSeams = Object.freeze({
    ...h.seams,
    createPi: async (options) => {
      entered();
      await delayed;
      return h.seams.createPi(options);
    },
  });
  const starting = startProductionWorker({ seams });
  await factoryEntered;
  h.loseSsh();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(h.log.includes("egress.close"), false);
  assert.equal(h.log.includes("ssh.close"), false);
  assert.equal(h.log.includes("telemetry.close"), false);
  release();
  await assert.rejects(starting, ProductionWorkerError);
  assert.ok(h.log.indexOf("pi.dispose") < h.log.indexOf("egress.close"));
  assert.ok(h.log.indexOf("egress.close") < h.log.indexOf("ssh.close"));
  assert.ok(h.log.indexOf("ssh.close") < h.log.indexOf("telemetry.close"));
});

test("late egress startup remains owned and is closed after startup abort", async () => {
  const h = harness();
  const controller = new AbortController();
  let enter!: () => void;
  const entered = new Promise<void>((resolve) => {
    enter = resolve;
  });
  let release!: () => void;
  const delayed = new Promise<void>((resolve) => {
    release = resolve;
  });
  let closes = 0;
  const manager: CogsEgressRuntimeManager = Object.freeze({
    ready: true,
    listenerPort: 18080,
    replacementRequired: false,
    drainCompletions: () => Object.freeze([]),
    close: async () => {
      closes += 1;
    },
  });
  registerCloseOwner(
    manager,
    createCloseOwner(() => manager.close()),
  );
  const seams: ProductionWorkerSeams = Object.freeze({
    ...h.seams,
    createEgress: async () => {
      enter();
      await delayed;
      return manager;
    },
  });
  const start = startProductionWorker({ signal: controller.signal, seams });
  await entered;
  controller.abort();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(closes, 0);
  release();
  await assert.rejects(start, ProductionWorkerError);
  assert.equal(closes, 1);
});

test("caller abort is bounded/idempotent and a running Pi turn is disposed without claiming a settled export", async () => {
  const h = harness();
  h.setPiState("running");
  const controller = new AbortController();
  const worker = await startProductionWorker({ signal: controller.signal, seams: h.seams });
  controller.abort();
  controller.abort();
  await worker.closed;
  assert.equal(h.log.filter((item) => item === "api.close").length, 1);
  assert.equal(h.log.filter((item) => item === "pi.dispose").length, 1);
  assert.equal(h.log.includes("pi.prepare"), false);
});

test("production rejects organization-scoped model and integration API-key handles before reading secrets", async () => {
  const modelHarness = harness();
  const badModel = {
    ...modelHarness.seams,
    readLaunch: async () => launch({ model: { ...launch().model, credential_handle: "organizations/acme/model/key" } }),
  };
  await assert.rejects(startProductionWorker({ seams: badModel }), ProductionWorkerError);
  assert.equal(
    modelHarness.log.some((item) => item.startsWith("secret.")),
    false,
  );

  const integrationHarness = harness();
  const document = launch();
  const integration = document.integrations[0] as Record<string, JsonValue>;
  const badIntegration = {
    ...integrationHarness.seams,
    readLaunch: async () =>
      launch({
        integrations: [
          {
            ...integration,
            auth: {
              ...(integration.auth as Record<string, JsonValue>),
              secret_handle: "organizations/acme/integrations/github",
            },
          },
        ],
      }),
  };
  await assert.rejects(startProductionWorker({ seams: badIntegration }), ProductionWorkerError);
  assert.equal(
    integrationHarness.log.some((item) => item.startsWith("secret.")),
    false,
  );
});

test("main coalesces SIGINT/SIGTERM into one bounded close and removes both handlers", async () => {
  const handlers = new Map<string, () => void>();
  let resolveClosed!: () => void;
  const closed = new Promise<void>((resolve) => {
    resolveClosed = resolve;
  });
  let closes = 0;
  let cleared = 0;
  let failed = 0;
  let hardDeadlineMs = 0;
  const port: ProductionMainPort = Object.freeze({
    start: async () =>
      Object.freeze({
        ready: true as const,
        apiPort: 18081,
        closed,
        close: async () => {
          closes += 1;
          resolveClosed();
        },
      }),
    on: (signal, listener) => handlers.set(signal, listener),
    off: (signal) => handlers.delete(signal),
    setTimer: (_callback, milliseconds) => {
      hardDeadlineMs = milliseconds;
      return Object.freeze({});
    },
    clearTimer: () => {
      cleared += 1;
    },
    failClosed: () => {
      failed += 1;
    },
    hardStop: () => {
      throw new Error("hard deadline");
    },
  });
  const running = runProductionMain(port);
  await new Promise((resolve) => setImmediate(resolve));
  handlers.get("SIGTERM")?.();
  handlers.get("SIGINT")?.();
  await running;
  assert.equal(closes, 1);
  assert.equal(cleared, 1);
  assert.equal(hardDeadlineMs, 31_000);
  assert.equal(failed, 0);
  assert.equal(handlers.size, 0);
});

test("main arms and preserves the hard deadline after spontaneous runtime loss", async () => {
  let failClosed = 0;
  let timers = 0;
  let cleared = 0;
  let deadline = 0;
  const port: ProductionMainPort = Object.freeze({
    start: async () =>
      Object.freeze({
        ready: true as const,
        apiPort: 18081,
        closed: Promise.reject(new Error(secretBearer)),
        close: async () => undefined,
      }),
    on: () => undefined,
    off: () => undefined,
    setTimer: (_callback, milliseconds) => {
      timers += 1;
      deadline = milliseconds;
      return Object.freeze({});
    },
    clearTimer: () => {
      cleared += 1;
    },
    failClosed: () => {
      failClosed += 1;
    },
    hardStop: () => {
      throw new Error("hard deadline");
    },
  });
  await runProductionMain(port);
  assert.equal(failClosed, 1);
  assert.equal(timers, 1);
  assert.equal(deadline, 31_000);
  assert.equal(cleared, 0);
});

test("main arms and preserves the hard deadline when startup ownership is uncertain", async () => {
  let failed = 0;
  let timers = 0;
  let cleared = 0;
  const port: ProductionMainPort = Object.freeze({
    start: async () => {
      throw new Error(secretBearer);
    },
    on: () => undefined,
    off: () => undefined,
    setTimer: (_callback, milliseconds) => {
      assert.equal(milliseconds, 31_000);
      timers += 1;
      return Object.freeze({});
    },
    clearTimer: () => {
      cleared += 1;
    },
    failClosed: () => {
      failed += 1;
    },
    hardStop: () => {
      throw new Error("hard deadline");
    },
  });
  await runProductionMain(port);
  assert.equal(failed, 1);
  assert.equal(timers, 1);
  assert.equal(cleared, 0);
});

test("production import boundary and foundation docs preserve the implemented-source/non-authority split", async () => {
  const [compose, main, foundation] = await Promise.all([
    readFile(new URL("../src/runtime/compose.ts", import.meta.url), "utf8"),
    readFile(new URL("../src/main.ts", import.meta.url), "utf8"),
    readFile(new URL("../docs/operations/production-runtime-foundation.md", import.meta.url), "utf8"),
  ]);
  const source = `${compose}\n${main}`;
  assert.doesNotMatch(source, /(?:from|import\()\s*["'][^"']*dev\//);
  assert.doesNotMatch(
    source,
    /deterministic|fixture|oauth|process\.env|AWS|terraform|tofu|docker|kubernetes-client|@kubernetes/iu,
  );
  assert.doesNotMatch(source, /child_process|execFile|\bspawn\(/u);
  assert.match(compose, /executablePath:\s*runtime\.paths\.envoy_executable/u);
  assert.match(compose, /exporter:\s*pi/u);
  assert.match(compose, /mode:\s*"otlp"/u);
  assert.match(foundation, /now provide `src\/main\.ts`, fail-closed production composition/u);
  assert.match(foundation, /Helm chart remains NOTES-only with zero submitted manifests/u);
  assert.match(foundation, /readiness v5 removes `RELEASE_IMAGE_SET_ABSENT`/iu);
  assert.match(foundation, /`NO_EXECUTABLE_PROVIDER_ROUTE`; and every false runtime\/provider\/Kubernetes\/cloud/u);
  assert.doesNotMatch(foundation, /following remain unimplemented:[\s\S]*`src\/main\.ts`/u);
});
