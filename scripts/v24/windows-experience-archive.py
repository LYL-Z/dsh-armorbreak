"""Bounded ZIP packaging/extraction for the Windows development experience."""
import hashlib, json, pathlib, re, stat, sys, zipfile
MAX_TOTAL=128*1024*1024
MANIFEST='experience-files.json'
def path_parts(name):
    if not isinstance(name,str) or '\\' in name or ':' in name or not name or name.startswith('/'):
        raise ValueError('EXPERIENCE_ARCHIVE_PATH')
    parts=name.split('/')
    if any(p in ('','.','..') or p.endswith((' ','.')) or re.search(r'[\x00-\x1f<>?"*|]',p) or re.match(r'^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)',p,re.I) for p in parts):raise ValueError('EXPERIENCE_ARCHIVE_PATH')
    allowed=name in ('Start ArmorBreak.cmd','README.txt','workspace/README.txt',MANIFEST)
    allowed|=len(parts)>3 and parts[:2]==['app','node_modules'] and parts[2] in ('dsh-armorbreak','typescript','yaml')
    allowed|=len(parts)==2 and parts[0]=='verification' and (parts[1] in ('sbom.spdx.json','THIRD_PARTY_NOTICES.txt','preview-build.json','SHA256SUMS.txt') or parts[1].startswith('armorbreak-npm-candidate-') and parts[1].endswith('.tgz'))
    if not allowed:raise ValueError('EXPERIENCE_ARCHIVE_UNEXPECTED_FILE')
    return parts
def manifest_rows(data):
    if len(data)>1024*1024:raise ValueError('EXPERIENCE_MANIFEST_LIMIT')
    manifest=json.loads(data)
    if manifest['schema']!='armorbreak.windows-experience/v1' or len(manifest['files'])>5000:raise ValueError('EXPERIENCE_MANIFEST_INVALID')
    rows={};casefold=set();total=0
    for row in manifest['files']:
        name=row['path'];path_parts(name)
        if name==MANIFEST or name.casefold() in casefold or not isinstance(row['bytes'],int) or not 0<=row['bytes']<=64*1024*1024:raise ValueError('EXPERIENCE_ARCHIVE_MEMBERS')
        total+=row['bytes'];casefold.add(name.casefold());rows[name]=row
    if total>MAX_TOTAL or not {'Start ArmorBreak.cmd','README.txt','workspace/README.txt'}<=rows.keys():raise ValueError('EXPERIENCE_ARCHIVE_LIMIT_OR_MISSING')
    return manifest,rows
def check(data,row):
    if len(data)!=row['bytes'] or hashlib.sha256(data).hexdigest()!=row['sha256']:raise ValueError('EXPERIENCE_FILE_DRIFT')
def pack(root,archive):
    root=root.resolve(strict=True)
    if archive.resolve().is_relative_to(root):raise ValueError('ARCHIVE_MUST_BE_OUTSIDE_INPUT')
    raw=(root/MANIFEST).read_bytes();manifest,rows=manifest_rows(raw)
    found=set()
    for path in root.rglob('*'):
        info=path.lstat()
        if path.is_symlink():raise ValueError('EXPERIENCE_ARCHIVE_LINK')
        if path.is_file():
            if info.st_nlink!=1:raise ValueError('EXPERIENCE_ARCHIVE_LINK')
            found.add(path.relative_to(root).as_posix())
        elif not path.is_dir():raise ValueError('EXPERIENCE_ARCHIVE_SPECIAL_FILE')
    if found!=set(rows)|{MANIFEST}:raise ValueError('EXPERIENCE_ARCHIVE_UNEXPECTED_FILE')
    with zipfile.ZipFile(archive,'x',compression=zipfile.ZIP_DEFLATED) as z:
        for name in sorted(found):
            data=(root/pathlib.Path(*path_parts(name))).read_bytes()
            if name!=MANIFEST:check(data,rows[name])
            item=zipfile.ZipInfo(name,date_time=(2000,1,1,0,0,0));item.external_attr=(stat.S_IFREG|0o644)<<16;item.compress_type=zipfile.ZIP_DEFLATED
            z.writestr(item,data)
    return {'schema':'armorbreak.windows-experience-zip/v1','commit':manifest['commit'],'version':manifest['version'],'members':len(found),'bytes':archive.stat().st_size,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest()}
def extract(archive,root):
    if root.exists():raise ValueError('REFUSE_EXISTING_OUTPUT')
    with zipfile.ZipFile(archive) as z:
        members=z.infolist();names=[i.filename for i in members]
        if len(names)>5001 or len(set(n.casefold() for n in names))!=len(names) or sum(i.file_size for i in members)>MAX_TOTAL+1024*1024:raise ValueError('EXPERIENCE_ARCHIVE_LIMIT_OR_DUPLICATE')
        for item in members:
            path_parts(item.filename)
            if not stat.S_ISREG(item.external_attr>>16):raise ValueError('EXPERIENCE_ARCHIVE_LINK_OR_DIRECTORY')
        raw=z.read(MANIFEST);manifest,rows=manifest_rows(raw)
        if set(names)!=set(rows)|{MANIFEST}:raise ValueError('EXPERIENCE_ARCHIVE_MEMBERS')
        data={name:z.read(name) for name in names}
        for name,row in rows.items():check(data[name],row)
    root.mkdir(parents=True)
    for name,content in data.items():
        destination=root.joinpath(*path_parts(name));destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(content)
    return {'schema':'armorbreak.windows-experience-extraction/v1','commit':manifest['commit'],'members':len(names),'status':'EXTRACTED_AND_HASH_VERIFIED'}
if __name__=='__main__':
    mode,source,destination=sys.argv[1:]
    if mode=='pack':result=pack(pathlib.Path(source),pathlib.Path(destination))
    elif mode=='extract':result=extract(pathlib.Path(source),pathlib.Path(destination))
    else:raise ValueError('pack or extract is required')
    print(json.dumps(result,indent=2))
