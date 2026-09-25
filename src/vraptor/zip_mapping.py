"""Direct, read-only Velociraptor KapeFiles zip mapping (no extraction)."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from urllib.parse import unquote
import zipfile

import yaml
from .common.atomic_io import write_json_atomic, write_text_atomic


def prepare_zip(source, remap, binary, hostname):
    from .export_mapping import digest
    source, remap = Path(source).resolve(), Path(remap).resolve()
    if source == remap:
        raise ValueError('Remap must not overwrite evidence')
    password_path = os.environ.get('VRAPTOR_ZIP_PASSWORD_FILE', '')
    if password_path:
        password_file = Path(password_path).expanduser().resolve()
        info = password_file.stat()
        if not password_file.is_file() or info.st_uid != os.getuid() or info.st_mode & 0o077 or not 0 < info.st_size <= 4096:
            raise ValueError('ZIP password file must be owner-only, nonempty, and at most 4096 bytes')
        password_path = str(password_file)
    scope = ('LET ZIP_PASSWORDS <= read_file(filename=' + json.dumps(password_path) + ', accessor="file", length=4096)') if password_path else ''
    identity = digest(source)
    metadata = remap.with_suffix('.export.json')
    if remap.exists():
        if not metadata.exists():
            raise ValueError('Existing remap has no ZIP binding')
        saved = json.loads(metadata.read_text())
        if (saved.get('source') != str(source) or saved.get('inventory_sha256') != identity
                or saved.get('password_file', '') != password_path or saved.get('hostname') != hostname or saved.get('remap_sha256') != digest(remap)):
            raise ValueError('ZIP binding or remap changed; saved identity preserved')
        if password_path:
            query = scope + '\nSELECT len(list=read_file(accessor="collector", filename=pathspec(DelegateAccessor="file", DelegatePath=' + json.dumps(str(source)) + ', Path="/uploads.json"), length=1)) AS ReadBytes FROM scope()'
            result = subprocess.run([binary, 'query', '--nobanner', query], capture_output=True, text=True, timeout=60, check=True)
            if json.loads(result.stdout) != [{'ReadBytes': 1}]:
                raise ValueError('Cannot read encrypted collection on resume; check password')
        return saved
    records = []
    with zipfile.ZipFile(source) as archive:
        encrypted = 'data.zip' in archive.namelist() or any(i.flag_bits & 1 for i in archive.infolist())
        if encrypted and ('data.zip' not in archive.namelist() or any(i.flag_bits & 1 and i.compress_type != 99 for i in archive.infolist())):
            raise ValueError('Only AES-encrypted Velociraptor data.zip containers are supported; legacy ZipCrypto is unsupported')
        if encrypted and not password_path:
            raise ValueError('Encrypted ZIP requires VRAPTOR_ZIP_PASSWORD_FILE (owner-only file; no trailing newline)')
        native = None
        if encrypted:
            query_file = Path(__file__).parent / 'resources/vql/kapefiles_zip_inventory.vql'
            result = subprocess.run([binary, 'query', '--nobanner', '--from_files',
                                     '--env', 'EvidencePath=' + str(source),
                                     '--env', 'PasswordFile=' + password_path, str(query_file)],
                                    capture_output=True, text=True, timeout=120, check=True)
            native = json.loads(result.stdout)[0]
            if not native.get('Index') or not native.get('Members'):
                raise ValueError('Cannot read encrypted collection; check password and container layout')
        entries = archive.infolist()
        if native:
            entries = []
            for member in native['Members']:
                item = zipfile.ZipInfo(member['Path'].lstrip('/'))
                item.file_size = member['Size']
                entries.append(item)
        members = {}
        for item in entries:
            parts = tuple(unquote(x) for x in item.filename.split('/'))
            if item.is_dir():
                continue
            if any(x in ('', '.', '..') or ('/' in x and parts[0] == 'uploads') for x in parts) or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError('Unsafe ZIP member')
            if parts in members:
                raise ValueError('Duplicate ZIP member')
            members[parts] = item
        seen = set()
        index_rows = native['Index'] if native else [json.loads(line) for line in archive.read('uploads.json').splitlines()]
        for row in index_rows:
            if row.get('Type') == 'idx':
                continue
            parts = row.get('_Components')
            if not isinstance(parts, list) or len(parts) < 4 or parts[0] != 'uploads':
                raise ValueError('Invalid upload components')
            accessor, drive = parts[1:3]
            if accessor not in ('auto', 'file', 'ntfs') or not re.fullmatch(r'(?:\\+\.\\+)?[A-Za-z]:', drive):
                raise ValueError('Unsupported accessor, drive or VSS path')
            if any(not isinstance(x, str) or x in ('', '.', '..') or '/' in x or '\\' in x for x in parts[3:]):
                raise ValueError('Invalid upload filename')
            member = members.get(tuple(parts))
            if member is None or member.file_size != row.get('uploaded_size'):
                raise ValueError('Missing or truncated upload')
            if row.get('file_size') != row.get('uploaded_size') and tuple(parts[:-1] + [parts[-1] + '.idx']) not in members:
                raise ValueError('Sparse upload missing index')
            target = drive + '\\' + '\\'.join(parts[3:])
            key = (accessor, target.casefold())
            if key in seen:
                raise ValueError('Duplicate virtual upload path')
            seen.add(key)
            records.append(dict(accessor=accessor, target=target, member=member.filename,
                                size=row['file_size'], relative='/'.join(parts[3:])))
    if not records:
        raise ValueError('ZIP contains no uploaded files')
    remap.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=remap.parent) as tmp:
        base = Path(tmp) / 'base.yaml'
        subprocess.run([binary, 'deaddisk', '--hostname', hostname,
                        '--add_windows_directory', tmp, str(base)], check=True, capture_output=True, timeout=60)
        config = yaml.safe_load(base.read_text())
    with tempfile.TemporaryDirectory(dir=remap.parent) as tmp:
        records_file, base_file = Path(tmp) / 'records.json', Path(tmp) / 'base.yaml'
        records_file.write_text(json.dumps(records))
        base_file.write_text(yaml.safe_dump(config))
        generator = Path(__file__).parent / 'resources/vql/kapefiles_zip_remapping.vql'
        result = subprocess.run([binary, 'query', '--nobanner', '--from_files',
            '--env', 'RecordsFile=' + str(records_file), '--env', 'BaseFile=' + str(base_file),
            '--env', 'EvidencePath=' + str(source), '--env', 'MountScope=' + scope, str(generator)],
            check=True, capture_output=True, text=True, timeout=60)
        generated = json.loads(result.stdout)
        if len(generated) != 1 or not generated[0].get('Remapping'):
            raise ValueError('VQL remapping generation failed')
        data = generated[0]['Remapping']
    # Probe before publishing the remap so failed preparation is retryable.
    with tempfile.TemporaryDirectory(dir=remap.parent) as tmp:
        candidate = Path(tmp) / 'remap.yaml'
        candidate.write_text(data)
        probes = {}
        for row in records:
            probes.setdefault((row['accessor'], row['target'].split(':')[0]), row)
        for row in probes.values():
            result = subprocess.run([binary, '--remap', str(candidate), 'query', '--nobanner',
                '--env', 'Probe=' + row['target'], '--env', 'Accessor=' + row['accessor'],
                'SELECT Size, len(list=read_file(filename=Probe, accessor=Accessor, length=1)) AS ReadBytes FROM stat(filename=Probe, accessor=Accessor)'],
                check=True, capture_output=True, text=True, timeout=60)
            rows = json.loads(result.stdout)
            if len(rows) != 1 or rows[0]['Size'] != row['size'] or rows[0]['ReadBytes'] != min(1, row['size']):
                raise ValueError('ZIP mapped read verification failed: ' + row['target'])
    if digest(source) != identity:
        raise ValueError('ZIP changed during preparation')
    saved = dict(version=1, evidence_type='velociraptor-kapefiles-zip', source=str(source), hostname=hostname,
                 inventory_sha256=identity, remap_sha256=hashlib.sha256(data.encode()).hexdigest(),
                 files=len(records), password_file=password_path, verified_files=[],
                 limitations=['only captured files', 'ZIP timestamps are not forensic timestamps',
                              'user and Amcache hives not mapped', 'external tools cannot use virtual paths', 'encoded member basenames retain ZIP spelling'])
    write_text_atomic(remap, data)
    write_json_atomic(metadata, saved)
    return saved
