#!/usr/bin/env python3
"""Remote-only frame-sequence diagnosis; never changes public candidates."""
import hashlib,json,os,subprocess,xml.etree.ElementTree as E
from pathlib import Path
proof=Path(os.environ['PROOF']);proof.mkdir(parents=True,exist_ok=True)
base='320061d07c3d559a2fa734b2b4bc2891c86f4422'
current='1978967034778782c7982812f0a0977f94094162'
versions={'current':current,'decode_discarded_probe':current}
fixture=r"""
TEST_F(LIBHTTP2, DIAG_NormalIndexedHeaderReuse)
{
    http2_ctx *ctx = http2_ctx_server_new("diagnosis", bio_read, bio_write, &server_sock, nullptr);
    ASSERT_NE(ctx, nullptr);
    const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    ASSERT_EQ(write(client_sock,preface,sizeof(preface)-1),(ssize_t)sizeof(preface)-1);
    WriteClientFrame(4,0,0,nullptr,0);
    ASSERT_EQ(http2_ctx_handshake(ctx),1);
    const uint8_t first[] = {0x82,0x86,0x84,0x40,6,'x','-','l','a','t','e',1,'v'};
    WriteClientFrame(1,5,1,first,sizeof(first));
    int ret=http2_ctx_poll(ctx,nullptr,0,nullptr);
    ASSERT_TRUE(ret==0 || ret==HTTP2_ERR_EAGAIN) << ret;
    const uint8_t next[] = {0x82,0x86,0x84,0xbe};
    WriteClientFrame(1,5,3,next,sizeof(next));
    ret=http2_ctx_poll(ctx,nullptr,0,nullptr);
    EXPECT_TRUE(ret==0 || ret==HTTP2_ERR_EAGAIN) << ret;
    EXPECT_EQ(http2_ctx_is_closed(ctx),0);
    http2_stream *stream=http2_ctx_accept_stream(ctx);
    ASSERT_NE(stream,nullptr);
    EXPECT_STREQ(http2_stream_get_header(stream,"x-late"),"v");
    http2_stream_close(stream);
    http2_ctx_close(ctx);
}
"""
for fragmented in [False,True]:
    fixture+=r"""
TEST_F(LIBHTTP2, DIAG_NAME)
{
    http2_ctx *ctx = http2_ctx_server_new("diagnosis", bio_read, bio_write, &server_sock, nullptr);
    ASSERT_NE(ctx,nullptr);
    const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    ASSERT_EQ(write(client_sock,preface,sizeof(preface)-1),(ssize_t)sizeof(preface)-1);
    WriteClientFrame(4,0,0,nullptr,0);
    ASSERT_EQ(http2_ctx_handshake(ctx),1);
    // A stream-local Content-Length error, while the sender is still open.
    const uint8_t request[] = {0x83,0x86,0x84,0x0f,0x0d,1,'1'};
    WriteClientFrame(1,4,1,request,sizeof(request));
    int ret=http2_ctx_poll(ctx,nullptr,0,nullptr);
    ASSERT_TRUE(ret==0 || ret==HTTP2_ERR_EAGAIN) << ret;
    const uint8_t body[] = {'a','b'};
    WriteClientFrame(0,0,1,body,sizeof(body));
    ret=http2_ctx_poll(ctx,nullptr,0,nullptr);
    ASSERT_TRUE(ret==0 || ret==HTTP2_ERR_EAGAIN) << ret;
    ASSERT_EQ(http2_ctx_is_closed(ctx),0);
    // Valid HPACK trailer already in flight before the sender observes RST.
    const uint8_t trailer[] = {0x40,6,'x','-','l','a','t','e',1,'v'};
    DIAG_TRAILER
    ret=http2_ctx_poll(ctx,nullptr,0,nullptr);
    EXPECT_TRUE(ret==0 || ret==HTTP2_ERR_EAGAIN) << "late trailer poll=" << ret;
    EXPECT_EQ(http2_ctx_is_closed(ctx),0) << "after late trailer";
    const uint8_t next[] = {0x82,0x86,0x84,0xbe};
    WriteClientFrame(1,5,3,next,sizeof(next));
    ret=http2_ctx_poll(ctx,nullptr,0,nullptr);
    EXPECT_TRUE(ret==0 || ret==HTTP2_ERR_EAGAIN) << "next normal request poll=" << ret;
    EXPECT_EQ(http2_ctx_is_closed(ctx),0) << "after next normal stream";
    http2_ctx_close(ctx);
}
""".replace('DIAG_NAME','DIAG_ResetStream'+('FragmentedTrailer' if fragmented else 'IndexedTrailer')).replace('DIAG_TRAILER',
 'WriteClientFrame(1,1,1,trailer,5); WriteClientFrame(9,4,1,trailer+5,sizeof(trailer)-5);' if fragmented else 'WriteClientFrame(1,5,1,trailer,sizeof(trailer));')
(proof/'fixture.cc').write_text(fixture)
results=[]
for name,sha in versions.items():
    root=Path('/tmp/h2-diagnose-'+name)
    subprocess.run(['git','worktree','add','--detach',str(root),current],check=True)
    subprocess.run(['git','restore','--source='+sha,'--','src'],cwd=root,check=True)
    subprocess.run(['git','diff','--exit-code',sha,'--','src'],cwd=root,check=True)
    if name=='decode_discarded_probe':
        # Hypothesis isolation only: reuse the existing temporary-stream decode
        # path for discarded blocks. This is NOT a production fix candidate.
        p=root/'src/http_parse/http2.c';t=p.read_text()
        old="""\t\tif (stream->state == HTTP2_STREAM_CLOSED && stream->end_stream_read_handled) {
\t\t\t_http2_mark_stream_reset(stream);
\t\t\treturn 0;
\t\t}
\t\tctx->status = HTTP2_ERR_PROTOCOL;
\t\treturn -1;
\t}

\t/* Clear old headers only if this is a new HEADERS frame */"""
        new="""\t\tif (stream->state == HTTP2_STREAM_CLOSED && stream->end_stream_read_handled) {
\t\t\t_http2_init_tmp_stream(ctx, &tmp_stream, stream_id);
\t\t\tstream = &tmp_stream;
\t\t\tuse_tmp_stream = 1;
\t\t\trefuse_stream = 2;
\t\t} else {
\t\t\tctx->status = HTTP2_ERR_PROTOCOL;
\t\t\treturn -1;
\t\t}
\t}

\t/* Clear old headers only if this is a new HEADERS frame */"""
        assert t.count(old)==1;t=t.replace(old,new)
        old='\tif (refuse_stream) {\n\t\thttp2_send_rst_stream(ctx, stream_id, HTTP2_RST_REFUSED_STREAM);'
        new='\tif (refuse_stream) {\n\t\tif (refuse_stream == 1) http2_send_rst_stream(ctx, stream_id, HTTP2_RST_REFUSED_STREAM);'
        assert t.count(old)==1;p.write_text(t.replace(old,new))

    subprocess.run(['git','restore','--source='+base,'--','test/Makefile','test/cases/test-hpack-state.cc'],cwd=root,check=True)
    p=root/'test/cases/test-lib-http2.cc';p.write_text(p.read_text()+fixture)
    (proof/(name+'-input.diff')).write_bytes(subprocess.check_output(['git','diff','--binary'],cwd=root))
    with (proof/(name+'-build.log')).open('w') as log:
        subprocess.run(['make','-C','test','-j4'],cwd=root,stdout=log,stderr=subprocess.STDOUT,check=True)
    with (proof/(name+'-run.log')).open('w') as log:
        run=subprocess.run(['timeout','60','./test/test.bin','--gtest_filter=LIBHTTP2.DIAG_*','--gtest_output=xml:'+str(proof/(name+'.xml'))],cwd=root,stdout=log,stderr=subprocess.STDOUT)
    cases=list(E.parse(proof/(name+'.xml')).getroot().iter('testcase'))
    results.append({'name':name,'src':sha,'exit':run.returncode,'binary_sha256':hashlib.file_digest((root/'test/test.bin').open('rb'),'sha256').hexdigest(),'cases':[{'name':t.attrib['name'],'failures':[f.attrib.get('message') for f in t.findall('failure')],'skipped':t.find('skipped') is not None} for t in cases]})
    (proof/'results.json').write_text(json.dumps(results,indent=2)+'\n')
assert all(r['exit'] in (0,1) and {t['name'] for t in r['cases']}=={'DIAG_NormalIndexedHeaderReuse','DIAG_ResetStreamIndexedTrailer','DIAG_ResetStreamFragmentedTrailer'} and not any(t['skipped'] for t in r['cases']) for r in results)

assert all(not t['failures'] for t in results[1]['cases']), 'discarded-block hypothesis probe did not resolve the cases'
assert not results[0]['cases'][0]['failures'] and all(t['failures'] for t in results[0]['cases'][1:]), 'original control no longer reproduces'
