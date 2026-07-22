import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const root = process.cwd();
const verifier = join(root, "deploy/aws-feasibility/remote/verify-completion-artifacts.py");
const helperPath = join(root, "deploy/aws-feasibility/remote/completion_artifact_acquisition.py");
const pythonHelper = String.raw`
import hashlib,importlib.util,json,os,stat,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location("acquisition",sys.argv[1])
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)

class Response:
 def __init__(self,status,headers,body=b"",version=11):
  self.status=status;self.headers=tuple(headers);self.body=body;self.version=version;self.offset=0;self.closed=False
 def read(self,size,deadline):
  chunk=self.body[self.offset:self.offset+size];self.offset+=len(chunk);return chunk
 def close(self):self.closed=True

class Transport:
 def __init__(self,responses):self.responses=list(responses);self.requests=[]
 def request(self,request,timeout):
  self.requests.append(request)
  if not self.responses:raise AssertionError("unexpected request")
  return self.responses.pop(0)

def head(body,content="application/octet-stream"):
 return [("Content-Length",str(len(body))),("Content-Type",content)]
def token():
 body=b'{"token":"synthetic-token"}'
 return Response(200,head(body,"application/json"),body)
def row(name,body,url):return {"cache_name":name,"url":url,"size":len(body),"sha256":hashlib.sha256(body).hexdigest()}
def route(name,body,source,url,content="application/octet-stream"):
 return m.Route(row(name,body,url),source,content,(content,))
def artifact(body,content="application/octet-stream"):return Response(200,head(body,content),body)
def artifact_root(base):return Path(base)/".state"/"completion-v1"/"artifacts"
def acquire(routes,base,transport):m._acquire_rows(tuple(routes),artifact_root(base),transport,{"metadata":10,"artifact_read":120})
def close_fds(values):
 for value in reversed(values):os.close(value)
def expect_failure(callback):
 try:callback()
 except Exception:return
 raise AssertionError("expected failure")

action=sys.argv[2]
if action=="environment":
 m._reject_ambient_authority(json.loads(sys.argv[3]))
elif action=="gate-order":
 root=artifact_root(sys.argv[3]);original=dict(os.environ);called=[]
 try:
  os.environ.clear();os.environ[m.APPROVAL_NAME]="wrong"
  m._tls_context=lambda:called.append(True)
  expect_failure(lambda:m.acquire_artifacts({},root))
  assert not called and not root.parent.parent.exists()
 finally:
  os.environ.clear();os.environ.update(original)
elif action=="outbound":
 context=m._tls_context();assert context.check_hostname and context.verify_mode==m.ssl.CERT_REQUIRED
 assert context.minimum_version>=m.ssl.TLSVersion.TLSv1_2
 calls=[]
 class Raw:
  version=11;status=200
  def getheaders(self):return [("Content-Length","0"),("Content-Type","application/octet-stream")]
  def close(self):pass
  def read(self,size):return b""
 class Connection:
  def __init__(self,host,port,timeout,context):self.host=host;self.port=port;self.timeout=timeout;self.context=context;self.sock=type("Sock",(),{"settimeout":lambda self,value:None})()
  def putrequest(self,*args,**kwargs):calls.append(("request",args,kwargs))
  def putheader(self,*args):calls.append(("header",args))
  def endheaders(self):calls.append(("end",))
  def getresponse(self):return Raw()
  def close(self):calls.append(("close",))
 original=m.http.client.HTTPSConnection;m.http.client.HTTPSConnection=Connection
 try:
  response=m._HttpsTransport(object()).request(m.Request("https://registry-1.docker.io/path",(("Accept","type"),("User-Agent",m.USER_AGENT),("Connection","close"))),5)
  assert calls[0]==("request",("GET","/path"),{"skip_host":True,"skip_accept_encoding":True})
  assert [item[1] for item in calls if item[0]=="header"]==[("Host","registry-1.docker.io"),("Accept","type"),("User-Agent",m.USER_AGENT),("Connection","close")]
  assert all("Accept-Encoding" not in str(item) and "Authorization" not in str(item) for item in calls)
  response.close()
 finally:m.http.client.HTTPSConnection=original
elif action=="complete":
 base=Path(sys.argv[3]);oci=b"oci";deb=b"debian"
 routes=[route("oci.bin",oci,"oci-index","https://registry-1.docker.io/v2/library/debian/manifests/sha256:"+"a"*64,"application/vnd.oci.image.index.v1+json"),route("deb.bin",deb,"debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/dists/trixie/InRelease")]
 transport=Transport([token(),artifact(oci,"application/vnd.oci.image.index.v1+json"),artifact(deb)])
 acquire(routes,base,transport)
 assert len(transport.requests)==3
 assert transport.requests[0].url==m.TOKEN_URL and all(name!="Authorization" for name,_ in transport.requests[0].headers)
 assert dict(transport.requests[1].headers)["Authorization"]=="Bearer synthetic-token"
 assert "Authorization" not in dict(transport.requests[2].headers)
 cache=artifact_root(base)/"cache"
 assert {item.name for item in cache.iterdir()}=={"oci.bin","deb.bin"}
 assert all(stat.S_IMODE(item.stat().st_mode)==0o400 for item in cache.iterdir())
 assert (artifact_root(base)/m.SENTINEL).read_bytes()==m.SENTINEL_BYTES
 resumed=Transport([]);acquire(routes,base,resumed);assert not resumed.requests
elif action=="redirects":
 base=Path(sys.argv[3]);blob=b"blob";digest=hashlib.sha256(blob).hexdigest()
 oci=m.Route({**row("blob.bin",blob,"https://registry-1.docker.io/v2/library/debian/blobs/sha256:"+digest),"sha256":digest},"oci-layer","application/vnd.oci.image.layer.v1.tar+gzip",("application/octet-stream",))
 cdn=f"https://production.cloudflare.docker.com/registry-v2/docker/registry/v2/blobs/sha256/{digest[:2]}/{digest}/data?signature=x"
 debbody=b"snapshot";deb=route("snapshot.bin",debbody,"debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/file")
 redirect=lambda location:Response(307,[("Content-Length","0"),("Location",location)],b"")
 snapshot_redirect=Response(302,[("Content-Length","0"),("Location","/file/"+"a"*40)],b"")
 transport=Transport([token(),redirect(cdn),artifact(blob),snapshot_redirect,artifact(debbody)])
 acquire([oci,deb],base,transport)
 assert "Authorization" in dict(transport.requests[1].headers)
 assert "Authorization" not in dict(transport.requests[2].headers)
 assert "Authorization" not in dict(transport.requests[3].headers) and "Authorization" not in dict(transport.requests[4].headers)
 assert transport.requests[2].url==cdn and transport.requests[4].url.endswith("/file/"+"a"*40)
elif action=="hostile-headers":
 invalid=[
  Response(200,[("Content-Length","1"),("Content-Length","1")]),
  Response(200,[("Content-Length"," 1")]),
  Response(200,[("Transfer-Encoding","chunked"),("Transfer-Encoding","chunked")]),
  Response(200,[("Content-Encoding","gzip")]),
  Response(200,[("Authorization","secret")]),
  Response(200,[("Set-Cookie","secret")]),
  Response(200,[("Content-Length","1"),("WWW-Authenticate","Basic")]),
 ]
 for response in invalid:expect_failure(lambda response=response:m._strict_headers(response))
 for value in ["", "01", " 1", "+1", "1 ", "x", "1"*40]:
  expect_failure(lambda value=value:m._content_length({"content-length":value},10,1))
elif action=="hostile-token":
 bodies=[b'{"token":"a","token":"b"}',b'{"token":"a","access_token":"b"}',b'{"token":"bad token"}',b'{',b'{}']
 for body in bodies:
  expect_failure(lambda body=body:m._anonymous_registry_token(Transport([Response(200,head(body,"application/json"),body)]),time.monotonic()+10,10))
 expect_failure(lambda:m._anonymous_registry_token(Transport([Response(401,[("Content-Length","0"),("WWW-Authenticate","Bearer realm=hostile")],b"")]),time.monotonic()+10,10))
elif action=="token-protocol":
 body=b'{"token":"synthetic-token"}'
 valid=[
  Response(200,[("Transfer-Encoding","chunked"),("Content-Type","application/json")],body),
  Response(200,head(body,"application/json; charset=utf-8"),body),
  Response(200,head(body,"Application/JSON; Charset=UTF-8"),body),
 ]
 for response in valid:
  assert m._anonymous_registry_token(Transport([response]),time.monotonic()+10,10)=="synthetic-token" and response.closed
 hostile=[
  Response(200,[("Content-Length",str(len(body))),("Transfer-Encoding","chunked"),("Content-Type","application/json")],body),
  Response(200,[("Transfer-Encoding","gzip"),("Content-Type","application/json")],body),
  Response(200,[("Transfer-Encoding","chunked, gzip"),("Content-Type","application/json")],body),
  Response(200,[("Transfer-Encoding","chunked; hostile"),("Content-Type","application/json")],body),
  Response(200,[("Transfer-Encoding","chunked"),("Transfer-Encoding","chunked"),("Content-Type","application/json")],body),
  Response(200,[("Transfer-Encoding","chunked"),("Content-Encoding","gzip"),("Content-Type","application/json")],body),
  Response(200,[("Transfer-Encoding","chunked"),("Content-Type","application/json")],b"x"*(m.TOKEN_BODY_MAX+1)),
  Response(200,head(body,"application/json; charset=ascii"),body),
  Response(200,head(body,"application/json; charset=utf-8; hostile=x"),body),
  Response(200,head(body,"text/json"),body),
 ]
 for response in hostile:
  expect_failure(lambda response=response:m._anonymous_registry_token(Transport([response]),time.monotonic()+10,10));assert response.closed
 redirect_route=route("final.bin",b"x","debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/final")
 redirect=Response(302,[("Transfer-Encoding","chunked"),("Location","/file/"+"a"*40)],b"")
 expect_failure(lambda:m._final_response(redirect_route,None,Transport([redirect]),time.monotonic()+10,10));assert redirect.closed
elif action=="artifact-chunked":
 base=Path(sys.argv[3]);body=b"artifact";route1=route("final.bin",body,"debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/final")
 response=Response(200,[("Transfer-Encoding","chunked"),("Content-Type","application/octet-stream")],body)
 expect_failure(lambda:acquire([route1],base,Transport([response])));assert response.closed
 cache=artifact_root(base)/"cache";assert not (cache/"final.bin").exists() and not (cache/".final.bin.partial").exists()
elif action=="response-close":
 body=b"x";route1=route("final.bin",body,"debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/final")
 bad_type=Response(200,head(body,"text/hostile"),body);transport=Transport([bad_type])
 expect_failure(lambda:m._final_response(route1,None,transport,time.monotonic()+10,10));assert bad_type.closed
 duplicate=Response(200,[("Content-Length","1"),("Content-Length","1"),("Content-Type","application/octet-stream")],body);transport=Transport([duplicate])
 expect_failure(lambda:m._final_response(route1,None,transport,time.monotonic()+10,10));assert duplicate.closed
elif action=="hostile-redirects":
 body=b"x";digest=hashlib.sha256(body).hexdigest();baseurl="https://registry-1.docker.io/v2/library/debian/blobs/sha256:"+digest
 oci=m.Route({**row("x",body,baseurl),"sha256":digest},"oci-layer","type",("application/octet-stream",))
 for location in ["http://production.cloudflare.docker.com/x","https://evil.example/x",f"https://production.cloudflare.docker.com/wrong/{digest}/data",f"https://user@production.cloudflare.docker.com/blobs/sha256/{digest[:2]}/{digest}/data"]:
  expect_failure(lambda location=location:m._oci_redirect(oci,location))
 current="https://snapshot.debian.org/archive/debian/20260713T000000Z/a"
 for location in ["https://evil.example/file/"+"a"*40,"http://snapshot.debian.org/file/"+"a"*40,"https://snapshot.debian.org:444/file/"+"a"*40,"https://snapshot.debian.org/file/"+"a"*40+"?x=1","https://snapshot.debian.org/archive/debian/20260713T000000Z/%2e%2e/hostile"]:
  expect_failure(lambda location=location:m._debian_redirect(current,location,{current}))
elif action=="cleanup":
 base=Path(sys.argv[3]);good=b"good";bad=b"baad";first=b"first"
 routes=[route("first.bin",first,"debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/first"),route("bad.bin",good,"debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/bad")]
 transport=Transport([artifact(first),artifact(bad)])
 expect_failure(lambda:acquire(routes,base,transport))
 cache=artifact_root(base)/"cache"
 assert (cache/"first.bin").read_bytes()==first
 assert not (cache/"bad.bin").exists() and not (cache/".bad.bin.partial").exists()
elif action=="invalid-final":
 base=Path(sys.argv[3]);body=b"expected";route1=route("final.bin",body,"debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/final")
 fds=m._open_private_chain(artifact_root(base));m._sentinel(fds[-2]);cache=fds[-1]
 descriptor=os.open("final.bin",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400,dir_fd=cache);os.write(descriptor,b"hostile");os.close(descriptor);os.chmod("final.bin",0o400,dir_fd=cache);before=os.stat("final.bin",dir_fd=cache,follow_symlinks=False);close_fds(fds)
 transport=Transport([]);expect_failure(lambda:acquire([route1],base,transport))
 final=artifact_root(base)/"cache"/"final.bin";after=final.stat()
 assert final.read_bytes()==b"hostile" and (before.st_dev,before.st_ino)==(after.st_dev,after.st_ino) and not transport.requests
elif action=="stale-partial":
 base=Path(sys.argv[3]);body=b"x";route1=route("final.bin",body,"debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/final")
 fds=m._open_private_chain(artifact_root(base));m._sentinel(fds[-2]);cache=fds[-1]
 descriptor=os.open(".final.bin.partial",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=cache);os.write(descriptor,b"preserve");os.close(descriptor);close_fds(fds)
 expect_failure(lambda:acquire([route1],base,Transport([])))
 assert (artifact_root(base)/"cache"/".final.bin.partial").read_bytes()==b"preserve"
elif action=="state-boundary":
 base=Path(sys.argv[3]);outside=Path(sys.argv[4]);outside.mkdir();(base/".state").symlink_to(outside,target_is_directory=True)
 expect_failure(lambda:m._open_private_chain(artifact_root(base)))
 assert (base/".state").is_symlink()
elif action=="sentinel":
 base=Path(sys.argv[3]);fds=m._open_private_chain(artifact_root(base));artifacts=fds[-2]
 descriptor=os.open(m.SENTINEL,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600,dir_fd=artifacts);os.write(descriptor,b"invalid\n");os.close(descriptor);close_fds(fds)
 expect_failure(lambda:acquire([],base,Transport([])))
 assert (artifact_root(base)/m.SENTINEL).read_bytes()==b"invalid\n"
elif action=="publish-race":
 base=Path(sys.argv[3]);body=b"expected";route1=route("final.bin",body,"debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/final")
 original=m.os.link
 def race(source,target,src_dir_fd,dst_dir_fd,follow_symlinks):
  descriptor=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o400,dir_fd=dst_dir_fd);os.write(descriptor,b"attacker");os.close(descriptor);os.chmod(target,0o400,dir_fd=dst_dir_fd);raise FileExistsError()
 m.os.link=race
 try:expect_failure(lambda:acquire([route1],base,Transport([artifact(body)])))
 finally:m.os.link=original
 cache=artifact_root(base)/"cache";assert (cache/"final.bin").read_bytes()==b"attacker" and not (cache/".final.bin.partial").exists()
else:raise RuntimeError()
`;

function run(action: string, ...args: string[]) {
  return spawnSync("python3", ["-c", pythonHelper, helperPath, action, ...args], {
    cwd: root,
    env: { PATH: process.env.PATH ?? "", PYTHONDONTWRITEBYTECODE: "1" },
    encoding: "utf8",
    timeout: 20_000,
  });
}

async function withTemp(prefix: string, callback: (dir: string) => void | Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  try {
    await callback(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("acquisition gate and ambient authority fail before TLS, state, or transport", async () => {
  const gate = "COGS_STAGE2_ARTIFACT_ACQUISITION_APPROVED";
  const value = "download-16-fixed-public-stage2-artifacts";
  assert.equal(run("environment", JSON.stringify({ [gate]: value })).status, 0);
  for (const environ of [
    {},
    { [gate]: "wrong" },
    { [gate.toLowerCase()]: value },
    { [gate]: value, HTTPS_PROXY: "hostile" },
    { [gate]: value, ssl_cert_file: "hostile" },
    { [gate]: value, SSLKEYLOGFILE: "hostile" },
    { [gate]: value, NETRC: "hostile" },
    { [gate]: value, DOCKER_AUTH_CONFIG: "hostile" },
    { [gate]: value, AWS_PROFILE: "hostile" },
  ]) {
    assert.notEqual(run("environment", JSON.stringify(environ)).status, 0);
  }
  await withTemp("cogs-acquire-gate-", async (dir) => {
    assert.equal(run("gate-order", dir).status, 0);
    await assert.rejects(readFile(join(dir, ".state")));
  });
});

test("low-level HTTPS request emits only exact headers and disables implicit compression", () => {
  const result = run("outbound");
  assert.equal(result.status, 0, result.stderr);
});

test("fake acquisition creates private cache, binds auth by host, and resumes without HTTP", async () => {
  await withTemp("cogs-acquire-complete-", (dir) => {
    const result = run("complete", dir);
    assert.equal(result.status, 0, result.stderr);
  });
});

test("OCI CDN and Debian redirects are bounded and strip registry authorization", async () => {
  await withTemp("cogs-acquire-redirect-", (dir) => {
    const result = run("redirects", dir);
    assert.equal(result.status, 0, result.stderr);
  });
  assert.equal(run("hostile-redirects").status, 0);
});

test("token framing accepts only bounded CL or chunked JSON with optional UTF-8 charset", async () => {
  const tokenResult = run("token-protocol");
  assert.equal(tokenResult.status, 0, tokenResult.stderr);
  await withTemp("cogs-acquire-chunked-", (dir) => {
    const artifactResult = run("artifact-chunked", dir);
    assert.equal(artifactResult.status, 0, artifactResult.stderr);
  });
});

test("duplicate authority headers and hostile framing fail before body acceptance", () => {
  const result = run("hostile-headers");
  assert.equal(result.status, 0, result.stderr);
  const tokenResult = run("hostile-token");
  assert.equal(tokenResult.status, 0, tokenResult.stderr);
  const closeResult = run("response-close");
  assert.equal(closeResult.status, 0, closeResult.stderr);
});

test("failure removes only owned partials and retains already published exact finals", async () => {
  await withTemp("cogs-acquire-cleanup-", (dir) => {
    const result = run("cleanup", dir);
    assert.equal(result.status, 0, result.stderr);
  });
});

test("invalid finals and stale partials remain preserved without HTTP", async () => {
  await withTemp("cogs-acquire-invalid-", (dir) => {
    const result = run("invalid-final", dir);
    assert.equal(result.status, 0, result.stderr);
  });
  await withTemp("cogs-acquire-stale-", (dir) => {
    const result = run("stale-partial", dir);
    assert.equal(result.status, 0, result.stderr);
  });
});

test("private state and sentinel reject hostile preexisting boundaries without repair", async () => {
  await withTemp("cogs-acquire-state-", async (dir) => {
    const outside = join(dir, "outside");
    await mkdir(join(dir, "base"));
    const result = run("state-boundary", join(dir, "base"), outside);
    assert.equal(result.status, 0, result.stderr);
  });
  await withTemp("cogs-acquire-sentinel-", (dir) => {
    const result = run("sentinel", dir);
    assert.equal(result.status, 0, result.stderr);
  });
});

test("create-only final publication preserves a raced final and cleans its owned partial", async () => {
  await withTemp("cogs-acquire-race-", (dir) => {
    const result = run("publish-race", dir);
    assert.equal(result.status, 0, result.stderr);
  });
});

test("fixed acquisition CLI and helper expose no dynamic or cloud execution seam", async () => {
  const verifierText = await readFile(verifier, "utf8");
  const helperText = await readFile(helperPath, "utf8");
  assert.match(verifierText, /argv == \["acquire-artifacts"\]/u);
  assert.match(helperText, /putrequest\("GET", target, skip_host=True, skip_accept_encoding=True\)/u);
  assert.doesNotMatch(
    helperText,
    /urllib\.request|requests|netrc|subprocess|tempfile|shell=True|extractall|\.extract\(/u,
  );
  assert.doesNotMatch(helperText, /\b(?:boto3?|aws|tofu|terraform|ctr)\b|["']docker["']/u);
  assert.doesNotMatch(helperText, /open\([^\n]*["']w|rename|replace/u);
  assert.notEqual(spawnSync("python3", [verifier, "acquire-artifacts", "extra"], { cwd: root }).status, 0);
  const hostileHome = await mkdtemp(join(tmpdir(), "cogs-acquire-home-"));
  try {
    await writeFile(join(hostileHome, ".netrc"), "machine hostile");
    await mkdir(join(hostileHome, ".docker"));
    await writeFile(join(hostileHome, ".docker", "config.json"), "hostile");
    assert.doesNotMatch(helperText, /expanduser|HOME|\.netrc|config\.json/u);
  } finally {
    await rm(hostileHome, { recursive: true, force: true });
  }
});
