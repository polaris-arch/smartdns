#!/usr/bin/env python3
"""Execute the exact public PR commands in a disposable remote worktree."""
import json,os,subprocess,shutil
from pathlib import Path
repo=Path.cwd();pr=int(os.environ['PR']);proof=Path(os.environ['PROOF']);proof.mkdir(parents=True,exist_ok=True)
item=next(x for x in json.loads((repo/'.github/verification/public-recipes.json').read_text()) if x['pr']==pr)
metadata={'os_release':Path('/etc/os-release').read_text()}
for name,cmd in {'compiler':['cc','--version'],'openssl':['openssl','version','-a'],'libc':['getconf','GNU_LIBC_VERSION'],'rustc':['rustc','--version'],'cargo':['cargo','--version'],'packages':['dpkg-query','-W','libssl-dev','libc6','libclang-dev']}.items():
 if shutil.which(cmd[0]):
  r=subprocess.run(cmd,capture_output=True,text=True);metadata[name]={'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
(proof/'environment.json').write_text(json.dumps(metadata,indent=2)+'\n')
mode=os.environ.get('ABI_BITS');recipe=item['abi_recipes'][mode] if mode else item['native_recipe']
root=Path('/tmp')/('public-reproduction-'+str(pr)+('-'+mode if mode else ''))
subprocess.run(['git','worktree','add','--detach',str(root),item['candidate']],check=True)
(proof/'commands.sh').write_text(recipe)
(proof/'source.txt').write_text(subprocess.check_output(['git','rev-parse','HEAD','HEAD^{tree}','HEAD^'],cwd=root,text=True))
try:
 with (proof/'run.log').open('w') as log:
  subprocess.run(['bash','-c',recipe],cwd=root,stdout=log,stderr=subprocess.STDOUT,check=True)
 assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==item['candidate']
 if mode:
  text=(proof/'run.log').read_text();assert 'test result: ok. 1 passed; 0 failed' in text
  expected=4 if mode=='32' else 8;assert 'time_t='+str(expected)+' pointer=' in text and 'time_t_bytes='+str(expected) in text
 for name in ['after.xml','before.xml','time-abi.c','before-abi.log','plugin/smartdns-ui/Cargo.lock']:
  p=root/name
  if p.is_file():shutil.copyfile(p,proof/p.name)
 (proof/'baseline.diff').write_bytes(subprocess.check_output(['git','diff','--binary'],cwd=root))
 (proof/'result.json').write_text(json.dumps({'pr':pr,'source':item['candidate'],'abi_bits':mode,'exact_public_commands':'PASS'})+'\n')
finally:
 for name in ['after.xml','before.xml','before-abi.log']:
  p=root/name
  if p.is_file() and not (proof/p.name).exists():shutil.copyfile(p,proof/p.name)
