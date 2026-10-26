// node --experimental-strip-types test-diagnostics-model.cjs PREPARED_SOURCE
const assert = require('node:assert/strict');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
(async () => {
  const source = process.argv[2]; assert(source, 'prepared frontend source is required');
  const { groupEvents, eventCategory, eventTime, upstreamAddressText, queryAccounting } = await import(pathToFileURL(path.resolve(source,
    'src/components/dashboard/upstream-servers/diagnostics-model.ts')).href);
  const base = { kind:10,phase:3,code:429,age_ms:102100,ip:'120.53.53.53',query_id:1 };
  const burst = Array.from({length:14},(_,i)=>({...base,sequence:30-i,query_id:i+1,
    age_ms:102100+(i<4?0:1200),ip:i<4?'120.53.53.53':'1.12.12.12',domain:`request-${i}.example`}));
  const groups = groupEvents(burst);
  assert.equal(groups.length,1); assert.equal(groups[0].events.length,14);
  assert.deepEqual(groups[0].ips,['120.53.53.53','1.12.12.12']);
  assert.equal(new Set(groups[0].events.map(e=>e.query_id)).size,14);
  assert.equal(groupEvents([...burst,{...base,sequence:1,age_ms:110000}]).length,2);
  const dns = {...base,kind:1,code:3,qtype:28,domain:'one.example'};
  assert.equal(groupEvents([{...dns,sequence:3},{...dns,sequence:2,ip:'::1'},{...dns,sequence:1,domain:'two.example'}]).length,2);
  assert.equal(eventCategory(base),'http'); assert.equal(eventCategory(dns),'dns');
  assert.equal(eventCategory({...base,kind:0}),'timeout');
  for (const invalid of [undefined,null,0,-1,NaN,Infinity,8640000000000001]) assert.equal(eventTime(invalid),null);
  const timestamp=Date.UTC(2026,9,24,3,0,0,123);
  assert.match(eventTime(timestamp,'en-GB'),/2026/); assert.match(eventTime(timestamp,'en-GB'),/\.123/);
  assert.equal(burst.length,14); assert.equal(burst[0].sequence,30); // Presentation never mutates raw data.
  const provider = {pool_enabled:true,ip:'',endpoint_ips:['223.5.5.5','2400:3200::1','223.5.5.5'],diagnostics:{runtime:{wans:[
    {connected:true,ip:'223.5.5.5'},{connected:true,ip:'223.5.5.5'},{connected:false,ip:'2400:3200::1'}]}}};
  const original = JSON.stringify(provider);
  assert.equal(upstreamAddressText(provider),'223.5.5.5');
  provider.diagnostics.runtime.wans.push({connected:true,ip:'2400:3200::1'});
  assert.equal(upstreamAddressText(provider),'223.5.5.5, 2400:3200::1');
  provider.diagnostics.runtime.wans.forEach(w=>w.connected=false);
  assert.equal(upstreamAddressText(provider),'—'); // Do not claim an idle candidate is connected.
  assert.equal(upstreamAddressText({...provider,diagnostics:{runtime:{}}}),'—');
  assert.equal(upstreamAddressText({pool_enabled:false,ip:'::1'}),'::1');
  assert.equal(upstreamAddressText({pool_enabled:true,ip:'',endpoint_ips:['1.12.12.12','1.12.12.12']}),'1.12.12.12');
  const untouched = JSON.parse(original);upstreamAddressText(untouched);assert.equal(JSON.stringify(untouched),original);
  assert.deepEqual(queryAccounting({query_count:122,success_count:105,failure_count:0,skip_count:17,in_flight:0}),{total:122,accepted:105,failed:0,unsent:17,pending:0,closed:true});
  assert.equal(queryAccounting({query_count:122,success_count:100,failure_count:2,skip_count:17,in_flight:3}).closed,true);
  assert.equal(queryAccounting({query_count:122,success_count:105,failure_count:0,skip_count:17,in_flight:1}).closed,false);
  for (const invalid of [undefined,NaN,Infinity,-1,Number.MAX_SAFE_INTEGER+1]) assert.equal(queryAccounting({query_count:invalid,success_count:0,failure_count:0,skip_count:0,in_flight:0}),null);
  process.stdout.write('PASS: burst grouping, retained query/backend identity, category filters and captured timestamps\n');
})().catch(error=>{process.stderr.write(String(error.stack)+'\n');process.exitCode=1;});
