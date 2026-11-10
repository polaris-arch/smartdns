#!/usr/bin/env python3
"""Remote-only paired load check; no production code or public test changes."""
import os,sys,json,subprocess,time,socket,select,struct,statistics,hashlib
from pathlib import Path
repo=Path.cwd();proof=Path(os.environ['PROOF']);proof.mkdir(parents=True,exist_ok=True)
metadata={'os_release':Path('/etc/os-release').read_text(),'clock_ticks':os.sysconf('SC_CLK_TCK'),'cpu_count':os.cpu_count()}
for k,cmd in {'compiler':['cc','--version'],'openssl':['openssl','version','-a'],'libc':['getconf','GNU_LIBC_VERSION'],'packages':['dpkg-query','-W','libssl-dev','libc6']}.items():
 r=subprocess.run(cmd,capture_output=True,text=True);metadata[k]={'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
(proof/'environment.json').write_text(json.dumps(metadata,indent=2)+'\n')
head='5b63e8e2455cac148fa08bfac69a9a9e928d4fab';roots={}
fixture='''
TEST(HTTP2, NormalLoadObservation)
{
    const std::string dir = getenv("BENCH_DIR");
    smartdns::Server server;
    ASSERT_TRUE(server.Start("bind 127.0.0.1:60053\\nserver https://127.0.0.1:63054/dns-query -no-check-certificate -alpn h2\\ncache-size 0\\nspeed-check-mode none\\ndualstack-ip-selection no\\nlog-level error\\n"));
    LimitedHTTP2DoHUpstream upstream;
    ASSERT_TRUE(upstream.Start(63054, 32, "192.0.2.19")) << upstream.LastError();
    { std::ofstream ready(dir + "/ready"); ready << server.ProcessId(); }
    while (access((dir + "/stop").c_str(), F_OK) != 0) poll(nullptr, 0, 100);
    server.Stop();
    EXPECT_EQ(server.GetWaitStatus(), 0);
}
'''
for side in ['before','after']:
 root=Path('/tmp/public-h2-load-'+side);subprocess.run(['git','worktree','add','--detach',str(root),head],check=True)
 if side=='before':subprocess.run(['git','restore','--source=HEAD^','--','src','test/cases/test-http2-cancellation.cc'],cwd=root,check=True)
 p=root/'test/server.h';t=p.read_text();assert t.count('bool IsRunning();')==1;p.write_text(t.replace('bool IsRunning();','bool IsRunning();\n\tpid_t ProcessId() const { return pid_; }'))
 p=root/'test/cases/test-http2.cc';t=p.read_text();old='struct pollfd pfd = {fd, POLLIN | POLLOUT, 0};\n\t\t\t\tpoll(&pfd, 1, 10);';assert t.count(old)==1
 t=t.replace(old,'struct pollfd pfd = {fd, (short)(POLLIN | (http2_ctx_want_write(ctx) ? POLLOUT : 0)), 0};\n\t\t\t\tpoll(&pfd, 1, SSL_pending(conn.ssl) ? 0 : 10);')
 p.write_text('#include <fstream>\n'+t+fixture)
 with (proof/(side+'-build.log')).open('w') as log:subprocess.run(['make','-C','test','-j4'],cwd=root,stdout=log,stderr=subprocess.STDOUT,check=True)
 (proof/(side+'-harness.diff')).write_bytes(subprocess.check_output(['git','diff','--binary'],cwd=root))
 (proof/(side+'-binary.sha256')).write_text(hashlib.file_digest((root/'test/test.bin').open('rb'),'sha256').hexdigest())
 roots[side]=root

def resources(pid):
 t=Path('/proc',str(pid),'stat').read_text().rsplit(')',1)[1].split();status=Path('/proc',str(pid),'status').read_text().splitlines();rss=next(int(l.split()[1]) for l in status if l.startswith('VmRSS:'));return (int(t[11])+int(t[12]))/os.sysconf('SC_CLK_TCK'),rss,int(t[19])

def load(pid,limit,rate,duration,tag):
 sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.connect(('127.0.0.1',60053));sock.setblocking(False)
 pending={};lat=[];planned=sent=bad=cap=late=timeout=0;start=time.monotonic();end=start+duration;next_send=start;sample=start;cpu0,rss0,birth=resources(pid);rss=[rss0];seq=0
 while time.monotonic()<end or pending:
  now=time.monotonic()
  while True:
   try:data=sock.recv(4096)
   except BlockingIOError:break
   if len(data)<12:bad+=1;continue
   sid,flags,qd,an,ns,ar=struct.unpack('!6H',data[:12]);item=pending.pop(sid,None)
   if item is None:bad+=1;continue
   when,q=item
   if not flags&0x8000 or qd!=1 or flags&15 or an<1 or data[-4:]!=bytes([192,0,2,19]) or data[12:12+len(q)]!=q:bad+=1
   else:lat.append((time.monotonic()-when)*1000)
  now=time.monotonic()
  for sid,(when,q) in list(pending.items()):
   if now-when>2:timeout+=1;del pending[sid]
  while next_send<end and now>=next_send:
   planned+=1
   if now-next_send>1/rate:late+=1
   if len(pending)>=limit:cap+=1
   else:
    seq+=1;sid=seq%65536;labels=(f'q{seq}.{tag}.test').split('.');q=b''.join(bytes([len(x)])+x.encode() for x in labels)+b'\0'+struct.pack('!HH',1,1);wire=struct.pack('!6H',sid,0x100,1,0,0,0)+q
    sock.send(wire);pending[sid]=(time.monotonic(),q);sent+=1
   next_send+=1/rate
  if now>=sample:
   cpu,mem,seen=resources(pid);assert seen==birth;rss.append(mem);sample=now+0.1
  if now>=end and not pending:break
  wait=max(0,min(0.01,next_send-now if next_send<end else 0.01));select.select([sock],[],[],wait)
 cpu1,mem,seen=resources(pid);assert seen==birth;rss.append(mem);elapsed=time.monotonic()-start;sock.close();lat.sort()
 return {'planned':planned,'sent':sent,'success':len(lat),'invalid':bad,'timeout':timeout,'capacity_missed_slots':cap,'late_slots':late,'target_qps':rate,'send_qps':sent/duration,'completion_qps':len(lat)/elapsed,'resource_interval_seconds':elapsed,'target_load_met':planned==sent and cap==0,'seconds':duration,'elapsed_with_drain':elapsed,'inflight_limit':limit,'p50_ms':lat[int((len(lat)-1)*.5)] if lat else None,'p95_ms':lat[int((len(lat)-1)*.95)] if lat else None,'p99_ms':lat[int((len(lat)-1)*.99)] if lat else None,'resolver_cpu_seconds':cpu1-cpu0,'cpu_us_per_success':(cpu1-cpu0)*1e6/len(lat) if lat else None,'resolver_rss_kib_start':rss0,'resolver_rss_kib_max':max(rss),'resolver_rss_kib_end':rss[-1],'pid_starttime':birth}

rows=[]
for limit,rate in [(1,50),(16,500)]:
 for roundno in range(3):
  order=['before','after'] if roundno%2==0 else ['after','before']
  for side in order:
   d=proof/f'c{limit}-r{roundno}-{side}';d.mkdir();log=(d/'harness.log').open('w');env=dict(os.environ,BENCH_DIR=str(d));proc=subprocess.Popen([str(roots[side]/'test/test.bin'),'--gtest_filter=HTTP2.NormalLoadObservation'],cwd=roots[side],env=env,stdout=log,stderr=subprocess.STDOUT)
   try:
    deadline=time.monotonic()+20
    while not (d/'ready').exists():
     if proc.poll() is not None or time.monotonic()>deadline:raise RuntimeError('harness not ready')
     time.sleep(.05)
    pid=int((d/'ready').read_text());assert int(next(l.split()[1] for l in Path('/proc',str(pid),'status').read_text().splitlines() if l.startswith('PPid:')))==proc.pid;warm=load(pid,limit,rate,3,'warm');assert warm['success']>0 and warm['sent']==warm['success'] and warm['timeout']==warm['invalid']==0
    result=load(pid,limit,rate,20,'sample');result.update(side=side,round=roundno,pid=pid,warmup=warm);rows.append(result);(proof/'samples.json').write_text(json.dumps(rows,indent=2)+'\n')
    assert result['sent']==result['success'] and result['timeout']==result['invalid']==0,result
   finally:
    (d/'stop').touch()
    try:rc=proc.wait(timeout=20)
    except subprocess.TimeoutExpired:proc.terminate();rc=proc.wait(timeout=5)
    log.close()
   assert rc==0,(side,roundno,rc)
(proof/'method.json').write_text(json.dumps({'head':head,'parent':subprocess.check_output(['git','rev-parse',head+'^'],text=True).strip(),'normal_load_only':True,'peer_poll_fix_symmetric':True,'performance_resources':'forked resolver child only; peer excluded','no_fault_injection':True,'warmup_seconds':3,'measurement_seconds':20,'rounds_per_workload':3,'order':'AB,BA,AB','claim':'bounded observation only; no benefit or statistical equivalence claim'},indent=2)+'\n')

assert all(r["target_load_met"] for r in rows), "requested load not attained; samples cannot establish non-degradation"
