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
import contextlib,hashlib,http.client,importlib.util,io,json,os,socketserver,stat,sys,threading,time
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
def failure_stage(callback):
 try:callback()
 except m.AcquisitionError as error:return error.stage
 raise AssertionError("expected acquisition failure")

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
 class Wire:
  def __init__(self):self.timeouts=[]
  def settimeout(self,value):self.timeouts.append(value)
 class Raw:
  version=11;status=200
  def __init__(self,body=b""):self.body=body;self.closed=0;self.finished=False
  def getheaders(self):return [("Content-Length",str(len(self.body))),("Content-Type","application/octet-stream")]
  def isclosed(self):return self.finished
  def close(self):self.closed+=1;self.finished=True
  def read(self,size):chunk=self.body[:size];self.body=self.body[len(chunk):];self.finished=not self.body;return chunk
 class Connection:
  def __init__(self,host,port,timeout,context):self.host=host;self.port=port;self.timeout=timeout;self.context=context;self.sock=Wire();self.raw=Raw(b"x")
  def putrequest(self,*args,**kwargs):calls.append(("request",args,kwargs))
  def putheader(self,*args):calls.append(("header",args))
  def endheaders(self):calls.append(("end",))
  def getresponse(self):self.wire=self.sock;self.sock=None;return self.raw
  def close(self):calls.append(("close",))
 original=m.http.client.HTTPSConnection;m.http.client.HTTPSConnection=Connection
 try:
  response=m._HttpsTransport(object()).request(m.Request("https://registry-1.docker.io/path",(("Accept","type"),("User-Agent",m.USER_AGENT),("Connection","close"))),5)
  assert calls[0]==("request",("GET","/path"),{"skip_host":True,"skip_accept_encoding":True})
  assert [item[1] for item in calls if item[0]=="header"]==[("Host","registry-1.docker.io"),("Accept","type"),("User-Agent",m.USER_AGENT),("Connection","close")]
  assert all("Accept-Encoding" not in str(item) and "Authorization" not in str(item) for item in calls)
  assert response.connection.sock is None;expect_failure(lambda:response.read(1,time.monotonic()-1))
  assert response.read(1,time.monotonic()+5)==b"x" and response.read_socket.timeouts
  assert response.read(1,time.monotonic()-1)==b""
  response.close();response.close();assert response.read_socket is None and response.response.closed==1 and calls.count(("close",))==1
  expect_failure(lambda:response.read(1,time.monotonic()+5))
  class Detached:
   sock=None
   def __init__(self):self.closed=0
   def close(self):self.closed+=1
  class Bad:
   version=11;status=200
   def __init__(self):self.closed=0
   def getheaders(self):return []
   def isclosed(self):return False
   def read(self,size):return "bad"
   def close(self):self.closed+=1
  wire=Wire();connection=Detached();bad=Bad();invalid=m._LiveResponse(connection,bad,wire)
  expect_failure(lambda:invalid.read(1,time.monotonic()+5));invalid.close();invalid.close()
  assert invalid.read_socket is None and bad.closed==1 and connection.closed==1
  class EqualEmpty:
   def __eq__(self,other):return True
  for hostile in [b"x",bytearray(),EqualEmpty()]:
   closed_bad=Bad();closed_bad.isclosed=lambda:True;closed_bad.read=lambda size,hostile=hostile:hostile;wire=Wire();invalid=m._LiveResponse(Detached(),closed_bad,wire)
   expect_failure(lambda:invalid.read(1,time.monotonic()-1));assert not wire.timeouts;invalid.close()
 finally:m.http.client.HTTPSConnection=original
elif action=="local-eof-lifecycle":
 payloads=[b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc",b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n0\r\n\r\n"]
 for payload in payloads:
  class Handler(socketserver.BaseRequestHandler):
   def handle(self):self.request.recv(4096);self.request.sendall(payload)
  class Server(socketserver.TCPServer):allow_reuse_address=True
  server=Server(("127.0.0.1",0),Handler);thread=threading.Thread(target=server.handle_request);thread.start();connection=None;live=None
  try:
   connection=http.client.HTTPConnection("127.0.0.1",server.server_address[1],timeout=5);connection.request("GET","/",headers={"Connection":"close"});wire=connection.sock;raw=connection.getresponse()
   assert connection.sock is None and not raw.isclosed();live=m._LiveResponse(connection,raw,wire)
   assert live.read(100,time.monotonic()+5)==b"abc" and raw.isclosed() and wire.fileno()==-1
   assert live.read(1,time.monotonic()-1)==b""
  finally:
   if live is not None:live.close()
   elif connection is not None:connection.close()
   thread.join(5);server.server_close();assert not thread.is_alive()
elif action=="connection-close-artifact":
 base=Path(sys.argv[3]);body=b"artifact";route1=route("final.bin",body,"debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/final")
 class Wire:
  def __init__(self):self.timeouts=[]
  def settimeout(self,value):self.timeouts.append(value)
 class Raw:
  version=11;status=200
  def __init__(self):self.offset=0;self.closed=0;self.finished=False
  def getheaders(self):return head(body)
  def isclosed(self):return self.finished
  def read(self,size):chunk=body[self.offset:self.offset+size];self.offset+=len(chunk);self.finished=self.offset==len(body);return chunk
  def close(self):self.closed+=1;self.finished=True
 class Connection:
  sock=None
  def __init__(self):self.closed=0
  def close(self):self.closed+=1
 wire=Wire();raw=Raw();connection=Connection();live=m._LiveResponse(connection,raw,wire)
 acquire([route1],base,Transport([live]));final=artifact_root(base)/"cache"/"final.bin"
 assert final.read_bytes()==body and wire.timeouts and raw.closed==1 and connection.closed==1 and live.read_socket is None
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
 redirect=lambda location:Response(307,[("Content-Length","0"),("Location",location),("Content-Type","text/html; charset=utf-8")],b"")
 snapshot_redirect=Response(302,[("Content-Length","0"),("Location","/file/"+"a"*40),("Content-Type","application/octet-stream")],b"")
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
elif action=="token-cookie":
 base=Path(sys.argv[3]);body=b'{"token":"synthetic-token"}';cookies=[("Set-Cookie","a=b; Secure"),("set-cookie","c=d; HttpOnly")]
 one=Response(200,head(body,"application/json")+cookies[:1],body)
 assert m._anonymous_registry_token(Transport([one]),time.monotonic()+10,10)=="synthetic-token" and one.closed
 many=Response(200,head(body,"application/json")+cookies,body);parsed=m._strict_headers(many,True)
 assert "set-cookie" not in parsed and parsed==dict((name.lower(),value) for name,value in head(body,"application/json"))
 many=Response(200,head(body,"application/json")+cookies,body)
 assert m._anonymous_registry_token(Transport([many]),time.monotonic()+10,10)=="synthetic-token" and many.closed
 route1=route("oci.bin",b"oci","oci-index","https://registry-1.docker.io/v2/library/debian/manifests/sha256:"+"a"*64)
 transport=Transport([Response(200,head(body,"application/json")+cookies,body),artifact(b"oci")]);acquire([route1],base,transport)
 assert len(transport.requests)==2 and all(name.lower()!="cookie" for request in transport.requests for name,_value in request.headers)
 assert dict(transport.requests[1].headers)["Authorization"]=="Bearer synthetic-token"
 token_stage=lambda response:failure_stage(lambda:m._anonymous_registry_token(Transport([response]),time.monotonic()+10,10))
 non200=Response(401,head(b"","application/json")+cookies[:1],b"");assert token_stage(non200)=="token.header-authority" and non200.closed
 count_exact=Response(200,head(body,"application/json")+[("Set-Cookie","x")]*62,body)
 assert m._anonymous_registry_token(Transport([count_exact]),time.monotonic()+10,10)=="synthetic-token" and count_exact.closed
 count_over=Response(200,head(body,"application/json")+[("Set-Cookie","x")]*63,body);assert token_stage(count_over)=="token.header-shape" and count_over.closed
 fixed=head(body,"application/json");base_bytes=sum(len(name)+len(value.encode())+4 for name,value in fixed);cookie_overhead=len("Set-Cookie")+4
 value_bytes=m.HEADER_BYTES_MAX-base_bytes-2*cookie_overhead;first=value_bytes//2;second=value_bytes-first
 aggregate_cookies=[("Set-Cookie","x"*first),("set-cookie","x"*second)]
 aggregate_exact=Response(200,fixed+aggregate_cookies,body)
 assert m._anonymous_registry_token(Transport([aggregate_exact]),time.monotonic()+10,10)=="synthetic-token" and aggregate_exact.closed
 aggregate_over=Response(200,fixed+aggregate_cookies[:1]+[("set-cookie","x"*(second+1))],body)
 assert token_stage(aggregate_over)=="token.header-shape" and aggregate_over.closed
 malformed=[("Set Cookie","x"),("Set-Cookie","x\t"),("Set-Cookie","é")]
 for name,value in malformed:
  response=Response(200,fixed+[(name,value)],body);assert token_stage(response)=="token.header-shape" and response.closed
 authority=["Authorization","Proxy-Authorization","WWW-Authenticate","Proxy-Authenticate","Authentication-Info","Proxy-Authentication-Info"]
 for name in authority:
  response=Response(200,head(body,"application/json")+[(name,"x")],body);assert token_stage(response)=="token.header-authority" and response.closed
 artifact_cookie=Response(200,head(b"x")+cookies[:1],b"x");debian=route("final.bin",b"x","debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/final")
 assert failure_stage(lambda:m._final_response(debian,None,Transport([artifact_cookie]),time.monotonic()+10,10))=="artifact.response-headers" and artifact_cookie.closed
 for cookie_name in ["Cookie","cookie","COOKIE","CoOkIe"]:
  outbound=Transport([]);headers=(("Accept","application/json"),("User-Agent",m.USER_AGENT),("Connection","close"),(cookie_name,"x"))
  assert failure_stage(lambda:m._request(outbound,m.TOKEN_URL,headers,time.monotonic()+10,10,"token.request","token.headers",True))=="token.request" and not outbound.requests
elif action=="artifact-chunked":
 base=Path(sys.argv[3]);body=b"artifact";route1=route("final.bin",body,"debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/final")
 response=Response(200,[("Transfer-Encoding","chunked"),("Content-Type","application/octet-stream")],body)
 expect_failure(lambda:acquire([route1],base,Transport([response])));assert response.closed
 cache=artifact_root(base)/"cache";assert not (cache/"final.bin").exists() and not (cache/".final.bin.partial").exists()
elif action=="stage-map":
 base=Path(sys.argv[3]);body=b'{"token":"synthetic-token"}'
 assert m.STAGES==frozenset({"preflight","tls","routes","state","token.request","token.headers","token.header-shape","token.header-encoding","token.header-authority","token.status","token.content-type","token.framing","token.body","token.json","artifact.request","artifact.headers","artifact.response-headers","artifact.redirect","artifact.redirect.status","artifact.redirect.location","artifact.redirect.location-shape","artifact.redirect.location.url","artifact.redirect.location.host","artifact.redirect.location.host-docker-com","artifact.redirect.location.host-cloudflare-storage","artifact.redirect.location.host-docker-io","artifact.redirect.location.host-other","artifact.redirect.location.query","artifact.redirect.location.path","artifact.redirect.framing","artifact.redirect.framing.transfer","artifact.redirect.framing.length","artifact.redirect.framing.body","artifact.redirect.count","artifact.final","artifact.body","publish","postverify"})
 original_env=dict(os.environ);original_tls=m._tls_context;original_routes=m._artifact_routes
 def boom(*_args):raise RuntimeError()
 try:
  os.environ.clear();os.environ[m.APPROVAL_NAME]="wrong"
  assert failure_stage(lambda:m.acquire_artifacts({},artifact_root(base/"preflight")))=="preflight"
  os.environ[m.APPROVAL_NAME]=m.APPROVAL_VALUE;m._tls_context=boom
  assert failure_stage(lambda:m.acquire_artifacts({},artifact_root(base/"tls")))=="tls"
  m._tls_context=lambda:object();m._artifact_routes=boom
  assert failure_stage(lambda:m.acquire_artifacts({},artifact_root(base/"routes")))=="routes"
 finally:
  os.environ.clear();os.environ.update(original_env);m._tls_context=original_tls;m._artifact_routes=original_routes
 token_stage=lambda response:failure_stage(lambda:m._anonymous_registry_token(Transport([response]),time.monotonic()+10,10))
 assert token_stage(Response(200,[("Content-Length","1"),("Content-Length","1")],b""))=="token.header-shape"
 assert token_stage(Response(200,head(body,"application/json")+[("Content-Encoding","gzip")],body))=="token.header-encoding"
 assert token_stage(Response(200,head(body,"application/json")+[("Authentication-Info","hostile")],body))=="token.header-authority"
 assert token_stage(Response(401,head(b"","application/json"),b""))=="token.status"
 assert token_stage(Response(200,head(body,"text/plain"),body))=="token.content-type"
 assert token_stage(Response(200,[("Content-Length",str(len(body))),("Transfer-Encoding","chunked"),("Content-Type","application/json")],body))=="token.framing"
 class BrokenHeaders:
  version=11;status=200
  def __init__(self):self.closed=False
  @property
  def headers(self):raise RuntimeError()
  def close(self):self.closed=True
 broken=BrokenHeaders();assert token_stage(broken)=="token.headers" and broken.closed
 assert token_stage(Response(200,[("Content-Length",str(len(body)+1)),("Content-Type","application/json")],body))=="token.body"
 assert token_stage(Response(200,head(b"{","application/json"),b"{"))=="token.json"
 assert failure_stage(lambda:m._anonymous_registry_token(Transport([]),time.monotonic()+10,10))=="token.request"
 route1=route("final.bin",b"good","debian-inrelease","https://snapshot.debian.org/archive/debian/20260713T000000Z/final")
 assert failure_stage(lambda:m._final_response(route1,None,Transport([]),time.monotonic()+10,10))=="artifact.request"
 duplicate=Response(200,[("Content-Length","4"),("Content-Length","4"),("Content-Type","application/octet-stream")],b"good")
 assert failure_stage(lambda:m._final_response(route1,None,Transport([duplicate]),time.monotonic()+10,10))=="artifact.response-headers" and duplicate.closed
 valid_redirect=Response(302,[("Location","/file/"+"a"*40),("Content-Type","text/plain; charset=utf-8")],b"");final=artifact(b"good");transport=Transport([valid_redirect,final])
 returned=m._final_response(route1,None,transport,time.monotonic()+10,10);assert returned is final and valid_redirect.closed
 assert all(name.lower()!="content-type" for request in transport.requests for name,_value in request.headers);returned.close()
 invalid_status=Response(304,[("Content-Length","0"),("Location","/file/"+"a"*40)],b"")
 assert failure_stage(lambda:m._final_response(route1,None,Transport([invalid_status]),time.monotonic()+10,10))=="artifact.redirect.status" and invalid_status.closed
 missing_location=Response(302,[("Content-Length","0")],b"")
 assert failure_stage(lambda:m._final_response(route1,None,Transport([missing_location]),time.monotonic()+10,10))=="artifact.redirect.location" and missing_location.closed
 debian_path="/file/"+"a"*40
 debian_locations=[
  ("artifact.redirect.location-shape","x"*16385),
  ("artifact.redirect.location.url","http://snapshot.debian.org"+debian_path),
  ("artifact.redirect.location.host-other","https://hostile.invalid"+debian_path),
  ("artifact.redirect.location.query","https://snapshot.debian.org"+debian_path+"?x=1"),
  ("artifact.redirect.location.path","https://snapshot.debian.org/archive/debian/20260713T000000Z/%2e%2e/hostile"),
 ]
 for expected,location in debian_locations:
  redirect=Response(302,[("Content-Length","0"),("Location",location)],b"")
  assert failure_stage(lambda:m._final_response(route1,None,Transport([redirect]),time.monotonic()+10,10))==expected and redirect.closed
 exact_debian_locations=[("artifact.redirect.location-shape",""),("artifact.redirect.location.path","https://snapshot.debian.org/not-allowed")]
 for expected,location in exact_debian_locations:
  redirect=Response(302,[("Content-Length","0"),("Location",location)],b"");later=artifact(b"good");transport=Transport([redirect,later])
  assert failure_stage(lambda:m._final_response(route1,None,transport,time.monotonic()+10,10))==expected and redirect.closed
  assert len(transport.requests)==1 and transport.responses==[later] and not later.closed
 assert m.REDIRECT_BODY_MAX==4096 and m.REDIRECT_BODY_MAX*16*3==196608
 for metadata in [b"\x00\xff",bytes(range(256))*16]:
  redirect=Response(302,[("Content-Length",str(len(metadata))),("Location","/file/"+"a"*40),("Content-Type","text/plain")],metadata);final=artifact(b"good");transport=Transport([redirect,final])
  returned=m._final_response(route1,None,transport,time.monotonic()+10,10)
  assert returned is final and redirect.closed and redirect.offset==len(metadata) and len(transport.requests)==2;returned.close()
 strict_target_body=b"metadata";strict_target=Response(302,[("Content-Length",str(len(strict_target_body))),("Location","/not-allowed")],strict_target_body);later=artifact(b"good");transport=Transport([strict_target,later])
 assert failure_stage(lambda:m._final_response(route1,None,transport,time.monotonic()+10,10))=="artifact.redirect.location.path" and strict_target.closed and strict_target.offset==len(strict_target_body)
 assert len(transport.requests)==1 and transport.responses==[later] and not later.closed
 framings=[
  ("artifact.redirect.framing.length",Response(302,[("Content-Length","00"),("Location","/file/"+"a"*40),("Content-Type","text/plain")],b"")),
  ("artifact.redirect.framing.length",Response(302,[("Content-Length",str(m.REDIRECT_BODY_MAX+1)),("Location","/file/"+"a"*40)],b"")),
  *[("artifact.redirect.framing.transfer",Response(302,[("Transfer-Encoding",value),("Location","/file/"+"a"*40),("Content-Type","text/plain")],b"")) for value in ["chunked","gzip","chunked, gzip"]],
  ("artifact.redirect.framing.transfer",Response(302,[("Transfer-Encoding","chunked"),("Content-Length","1"),("Location","/file/"+"a"*40)],b"x")),
  ("artifact.redirect.framing.body",Response(302,[("Content-Length","4"),("Location","/file/"+"a"*40)],b"x")),
  ("artifact.redirect.framing.body",Response(302,[("Content-Length","1"),("Location","/file/"+"a"*40)],b"xx")),
  ("artifact.redirect.framing.body",Response(302,[("Content-Length","0"),("Location","/file/"+"a"*40),("Content-Type","text/plain")],b"x")),
 ]
 for expected,redirect in framings:
  later=artifact(b"good");transport=Transport([redirect,later])
  assert failure_stage(lambda:m._final_response(route1,None,transport,time.monotonic()+10,10))==expected and redirect.closed
  assert len(transport.requests)==1 and transport.responses==[later] and not later.closed
 class DeadlineRedirect(Response):
  def read(self,size,deadline):
   if deadline<=time.monotonic():raise TimeoutError()
   return super().read(size,deadline)
 class ThrowingRedirect(Response):
  def read(self,_size,_deadline):raise OSError("fixed")
 original_monotonic=m.time.monotonic;ticks=iter([0,20]);m.time.monotonic=lambda:next(ticks)
 try:
  expired=DeadlineRedirect(302,[("Content-Length","1"),("Location","/file/"+"a"*40)],b"x");later=artifact(b"good");transport=Transport([expired,later])
  assert failure_stage(lambda:m._final_response(route1,None,transport,10,10))=="artifact.redirect.framing.body" and expired.closed
  assert len(transport.requests)==1 and transport.responses==[later] and not later.closed
 finally:m.time.monotonic=original_monotonic
 throwing=ThrowingRedirect(302,[("Content-Length","1"),("Location","/file/"+"a"*40)],b"x");later=artifact(b"good");transport=Transport([throwing,later])
 assert failure_stage(lambda:m._final_response(route1,None,transport,time.monotonic()+10,10))=="artifact.redirect.framing.body" and throwing.closed
 assert len(transport.requests)==1 and transport.responses==[later] and not later.closed
 duplicate_framing=Response(302,[("Content-Length","0"),("content-length","0"),("Location","/file/"+"a"*40)],b"");later=artifact(b"good");transport=Transport([duplicate_framing,later])
 assert failure_stage(lambda:m._final_response(route1,None,transport,time.monotonic()+10,10))=="artifact.response-headers" and duplicate_framing.closed
 assert len(transport.requests)==1 and transport.responses==[later] and not later.closed
 assert failure_stage(lambda:m._stage("artifact.redirect.framing",lambda:m._fail(False)))=="artifact.redirect.framing"
 cycle=[Response(302,[("Content-Length","0"),("Location","/file/"+"a"*40)],b"") for _item in range(2)]
 assert failure_stage(lambda:m._final_response(route1,None,Transport(cycle),time.monotonic()+10,10))=="artifact.redirect.count" and all(item.closed for item in cycle)
 excessive=[Response(302,[("Content-Length","0"),("Location","/file/"+character*40)],b"") for character in "abcd"]
 assert failure_stage(lambda:m._final_response(route1,None,Transport(excessive),time.monotonic()+10,10))=="artifact.redirect.count" and all(item.closed for item in excessive)
 oci=route("oci.bin",b"good","oci-layer","https://registry-1.docker.io/v2/library/debian/blobs/sha256:"+"a"*64)
 oci_status=Response(302,[("Content-Length","0"),("Location","https://production.cloudflare.docker.com/blobs/sha256/x")],b"")
 assert failure_stage(lambda:m._final_response(oci,"synthetic-token",Transport([oci_status]),time.monotonic()+10,10))=="artifact.redirect.status" and oci_status.closed
 oci_digest=oci.row["sha256"];oci_path=f"/blobs/sha256/{oci_digest[:2]}/{oci_digest}/data";oci_base="https://production.cloudflare.docker.com"
 assert m.CDN_HOSTS=={"production.cloudflare.docker.com","production.cloudfront.docker.com","docker-images-prod.6aa30f8b08e16409b46e0173d6de2f56.r2.cloudflarestorage.com"}
 for host in m.CDN_HOSTS:
  allowed=f"https://{host}{oci_path}?x=1";redirect=Response(307,[("Content-Length","0"),("Location",allowed)],b"");final=artifact(b"good");transport=Transport([redirect,final])
  returned=m._final_response(oci,"synthetic-token",transport,time.monotonic()+10,10);assert returned is final and redirect.closed
  first_names={name.lower() for name,_value in transport.requests[0].headers};redirected_names={name.lower() for name,_value in transport.requests[1].headers}
  assert len(transport.requests)==2 and transport.requests[1].url==allowed and "authorization" in first_names
  assert not {"authorization","cookie","content-type"}&redirected_names;returned.close()
 oci_locations=[
  ("artifact.redirect.location-shape","x"*16385),
  ("artifact.redirect.location.url","http://production.cloudflare.docker.com"+oci_path),
  ("artifact.redirect.location.host-docker-com","https://hostile.docker.com"+oci_path),
  ("artifact.redirect.location.host-cloudflare-storage","https://hostile.cloudflarestorage.com"+oci_path),
  ("artifact.redirect.location.host-docker-io","https://hostile.docker.io"+oci_path),
  ("artifact.redirect.location.host-other","https://docker.com"+oci_path),
  ("artifact.redirect.location.query",oci_base+oci_path+"?x="+"a"*8193),
  ("artifact.redirect.location.path",oci_base+"/blobs/sha256/x"),
 ]
 for expected,location in oci_locations:
  redirect=Response(307,[("Content-Length","0"),("Location",location)],b"")
  assert failure_stage(lambda:m._final_response(oci,"synthetic-token",Transport([redirect]),time.monotonic()+10,10))==expected and redirect.closed
 cloudfront_locations=[
  ("artifact.redirect.location.host-docker-com","https://evil.production.cloudfront.docker.com"+oci_path),
  ("artifact.redirect.location.host-other","https://production.cloudfront.docker.com.evil"+oci_path),
 ]
 for expected,location in cloudfront_locations:
  redirect=Response(307,[("Content-Length","0"),("Location",location)],b"");later=artifact(b"good");transport=Transport([redirect,later])
  assert failure_stage(lambda:m._final_response(oci,"synthetic-token",transport,time.monotonic()+10,10))==expected and redirect.closed
  assert len(transport.requests)==1 and "Authorization" in dict(transport.requests[0].headers) and transport.responses==[later] and not later.closed
 for host in ["evilcloudflarestorage.com","cloudflarestorage.com.evil","evildocker.com","docker.com.evil","evildocker.io","docker.io.evil"]:
  redirect=Response(307,[("Content-Length","0"),("Location",f"https://{host}{oci_path}")],b"");later=artifact(b"good");transport=Transport([redirect,later])
  assert failure_stage(lambda:m._final_response(oci,"synthetic-token",transport,time.monotonic()+10,10))=="artifact.redirect.location.host-other" and redirect.closed
  assert len(transport.requests)==1 and transport.responses==[later] and not later.closed
 oci_target=oci_base+oci_path+"?x=1"
 oci_redirects=[Response(307,[("Content-Length","0"),("Location",oci_target)],b"") for _item in range(2)];oci_transport=Transport(oci_redirects)
 assert failure_stage(lambda:m._final_response(oci,"synthetic-token",oci_transport,time.monotonic()+10,10))=="artifact.redirect.count" and all(item.closed for item in oci_redirects)
 assert [request.url for request in oci_transport.requests]==[oci.row["url"],oci_target]
 assert "Authorization" in dict(oci_transport.requests[0].headers) and "Authorization" not in dict(oci_transport.requests[1].headers)
 hostile_headers=[
  Response(302,[("Content-Length","0"),("Location","/file/"+"a"*40),("Content-Encoding","gzip")],b""),
  Response(302,[("Content-Length","0"),("Location","/file/"+"a"*40),("Set-Cookie","x")],b""),
  Response(302,[("Content-Length","0"),("Location","/file/"+"a"*40),("Content-Type","text/plain"),("cOnTeNt-TyPe","text/html")],b""),
 ]
 for redirect in hostile_headers:
  assert failure_stage(lambda redirect=redirect:m._final_response(route1,None,Transport([redirect]),time.monotonic()+10,10))=="artifact.response-headers" and redirect.closed
 chunked=Response(200,[("Transfer-Encoding","chunked"),("Content-Type","application/octet-stream")],b"good")
 assert failure_stage(lambda:m._final_response(route1,None,Transport([chunked]),time.monotonic()+10,10))=="artifact.final" and chunked.closed
 wrong_type=Response(200,head(b"good","text/plain"),b"good")
 assert failure_stage(lambda:m._final_response(route1,None,Transport([wrong_type]),time.monotonic()+10,10))=="artifact.final" and wrong_type.closed
 assert failure_stage(lambda:m._stage("artifact.headers",lambda:m._fail(False)))=="artifact.headers"
 assert failure_stage(lambda:m._stage("artifact.headers",lambda:m._fail(False,"artifact.final")))=="artifact.final"
 short=Response(200,head(b"good"),b"bad");bodybase=base/"body";bodybase.mkdir()
 assert failure_stage(lambda:acquire([route1],bodybase,Transport([short])))=="artifact.body" and short.closed
 racebase=base/"race";racebase.mkdir();original=m.os.link
 def race(*args,**kwargs):raise FileExistsError()
 m.os.link=race
 try:assert failure_stage(lambda:acquire([route1],racebase,Transport([artifact(b"good")])))=="publish"
 finally:m.os.link=original
 outside=base/"outside";outside.mkdir();statebase=base/"state";statebase.mkdir();(statebase/".state").symlink_to(outside,target_is_directory=True)
 assert failure_stage(lambda:acquire([route1],statebase,Transport([])))=="state"
 assert failure_stage(lambda:m._stage("publish",lambda:m._fail(False,"artifact.body")))=="artifact.body"
 assert m.AcquisitionError("hostile").stage is None
elif action=="cli-stage":
 specv=importlib.util.spec_from_file_location("verifier",sys.argv[3]);v=importlib.util.module_from_spec(specv);specv.loader.exec_module(v)
 assert v.ACQUISITION_STAGES==m.STAGES
 sys.modules["completion_artifact_acquisition"]=m;v.verify_contract=lambda _path:{}
 def acquisition_failure(*_args):raise m.AcquisitionError("artifact.redirect.framing.body")
 m.acquire_artifacts=acquisition_failure
 try:v.acquire_completion_artifacts("contract","root")
 except v.VerificationError as error:assert error.stage=="artifact.redirect.framing.body"
 else:raise AssertionError("expected staged verification failure")
 m.acquire_artifacts=lambda *_args:None
 def postverify_failure(*_args):raise v.VerificationError()
 v.verify_package_archives=postverify_failure
 try:v.acquire_completion_artifacts("contract","root")
 except v.VerificationError as error:assert error.stage=="postverify"
 else:raise AssertionError("expected postverify failure")
 dynamic="https://hostile.invalid Authorization Bearer secret "+"a"*64
 def staged(*_args):
  try:raise RuntimeError(dynamic)
  except RuntimeError as error:raise v.VerificationError("artifact.redirect.framing.body") from error
 v.acquire_completion_artifacts=staged;stderr=io.StringIO()
 with contextlib.redirect_stderr(stderr):code=v.main(["acquire-artifacts"])
 lines=stderr.getvalue().splitlines();assert code==1 and lines==["completion artifact verification failed","completion artifact acquisition stage: artifact.redirect.framing.body"]
 assert dynamic not in stderr.getvalue() and "https://" not in stderr.getvalue() and "Bearer" not in stderr.getvalue() and not any(part in stderr.getvalue() for part in ["registry-1.docker.io","snapshot.debian.org"])
 def ordinary(*_args):raise v.VerificationError("artifact.redirect.framing.body")
 v.verify_contract=ordinary;stderr=io.StringIO()
 with contextlib.redirect_stderr(stderr):code=v.main(["verify-contract"])
 assert code==1 and stderr.getvalue()=="completion artifact verification failed\n"
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
  expect_failure(lambda location=location:m._debian_redirect(current,location))
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

test("HTTPS response retains its captured wire and closed EOF lifecycle", async () => {
  const result = run("outbound");
  assert.equal(result.status, 0, result.stderr);
  const lifecycleResult = run("local-eof-lifecycle");
  assert.equal(lifecycleResult.status, 0, lifecycleResult.stderr);
  await withTemp("cogs-acquire-close-", (dir) => {
    const artifactResult = run("connection-close-artifact", dir);
    assert.equal(artifactResult.status, 0, artifactResult.stderr);
  });
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

test("token framing and discarded response cookies remain token-only and bounded", async () => {
  const tokenResult = run("token-protocol");
  assert.equal(tokenResult.status, 0, tokenResult.stderr);
  await withTemp("cogs-acquire-cookie-", (dir) => {
    const cookieResult = run("token-cookie", dir);
    assert.equal(cookieResult.status, 0, cookieResult.stderr);
  });
  await withTemp("cogs-acquire-chunked-", (dir) => {
    const artifactResult = run("artifact-chunked", dir);
    assert.equal(artifactResult.status, 0, artifactResult.stderr);
  });
});

test("closed acquisition stages preserve first failure and CLI emits constants only", async () => {
  await withTemp("cogs-acquire-stage-", (dir) => {
    const result = run("stage-map", dir);
    assert.equal(result.status, 0, result.stderr);
  });
  const cliResult = run("cli-stage", verifier);
  assert.equal(cliResult.status, 0, cliResult.stderr);
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
