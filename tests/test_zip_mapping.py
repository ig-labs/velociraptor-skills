import json
from pathlib import Path
import subprocess
import shutil
import zipfile

import pytest

from vraptor.export_mapping import detect, prepare

from vraptor.paths import resolve_velociraptor_binary

BINARY = Path(resolve_velociraptor_binary(None, Path(__file__).resolve().parents[1]))
pytestmark = pytest.mark.skipif(not BINARY.is_file(), reason='Native Velociraptor required')


def archive(tmp_path, encrypted=False):
    root = tmp_path / 'input'
    member = root / 'uploads/auto/C%3A/Windows/example.txt'
    member.parent.mkdir(parents=True)
    member.write_bytes(b'evidence')
    row = dict(_Components=['uploads', 'auto', 'C:', 'Windows', 'example.txt'], file_size=8, uploaded_size=8)
    (root / 'uploads.json').write_text(json.dumps(row) + '\n')
    output = tmp_path / 'collection.zip'
    inner = tmp_path / 'data.zip' if encrypted else output
    with zipfile.ZipFile(inner, 'w') as z:
        for p in root.rglob('*'):
            if p.is_file():
                z.write(p, p.relative_to(root))
    if encrypted:
        if not shutil.which('7z'):
            pytest.skip('7z required for AES fixture')
        subprocess.run(['7z', 'a', '-tzip', '-mem=AES256', '-psynthetic-test-password', str(output), 'data.zip'], cwd=tmp_path, check=True)
    return output


def test_zip_mapping_and_resume(tmp_path):
    source = archive(tmp_path)
    before = source.read_bytes()
    assert detect(source) == 'velociraptor-kapefiles-zip'
    remap = tmp_path / 'runtime/remapping.yaml'
    saved = prepare(source, remap, str(BINARY), 'zip-test')
    result = subprocess.run([str(BINARY), '--remap', str(remap), 'query',
        'SELECT Name, Size, IsDir FROM glob(globs="C:/Windows/*", accessor="auto")'],
        capture_output=True, text=True, check=True)
    assert json.loads(result.stdout) == [dict(Name='example.txt', Size=8, IsDir=False)]
    assert prepare(source, remap, str(BINARY), 'zip-test') == saved
    local_query = 'LET Mapping <= parse_yaml(filename=' + json.dumps(str(remap)) + ') LET Applied <= remap(config=Mapping) SELECT Name, Size, IsDir FROM glob(globs="C:/Windows/*", accessor="auto")'
    local = subprocess.run([str(BINARY), 'query', local_query], capture_output=True, text=True, check=True)
    assert json.loads(local.stdout) == json.loads(result.stdout)
    assert source.read_bytes() == before
    assert not (remap.parent / 'export-view').exists()
    with pytest.raises(ValueError, match='changed'):
        prepare(source, remap, str(BINARY), 'other-host')


def test_password_zip(tmp_path, monkeypatch):
    source = archive(tmp_path, encrypted=True)
    remap = tmp_path / 'runtime/remapping.yaml'
    with pytest.raises(ValueError, match='PASSWORD_FILE'):
        prepare(source, remap, str(BINARY), 'zip-test')
    password = tmp_path / 'password'
    password.write_text('synthetic-test-password')
    password.chmod(0o600)
    monkeypatch.setenv('VRAPTOR_ZIP_PASSWORD_FILE', str(password))
    prepare(source, remap, str(BINARY), 'zip-test')
    assert 'synthetic-test-password' not in remap.read_text()
    assert 'synthetic-test-password' not in remap.with_suffix('.export.json').read_text()
    password.write_text('wrong')
    with pytest.raises(ValueError, match='resume'):
        prepare(source, remap, str(BINARY), 'zip-test')


def test_wrong_password(tmp_path, monkeypatch):
    source = archive(tmp_path, encrypted=True)
    password = tmp_path / 'password'
    password.write_text('wrong')
    password.chmod(0o600)
    monkeypatch.setenv('VRAPTOR_ZIP_PASSWORD_FILE', str(password))
    with pytest.raises(ValueError, match='Cannot read'):
        prepare(source, tmp_path / 'runtime/remapping.yaml', str(BINARY), 'zip-test')


def test_zip_changed_after_mapping(tmp_path):
    source = archive(tmp_path)
    remap = tmp_path / 'runtime/remapping.yaml'
    prepare(source, remap, str(BINARY), 'zip-test')
    with zipfile.ZipFile(source, 'a') as z:
        z.writestr('extra.txt', 'changed')
    with pytest.raises(ValueError, match='changed'):
        prepare(source, remap, str(BINARY), 'zip-test')


def test_rejects_unindexed_and_duplicate_uploads(tmp_path):
    source = archive(tmp_path)
    with pytest.warns(UserWarning, match='Duplicate name'):
        with zipfile.ZipFile(source, 'a') as z:
            z.writestr('uploads/auto/C%3A/Windows/example.txt', b'other')
    with pytest.raises(ValueError, match='Duplicate'):
        prepare(source, tmp_path / 'runtime/remapping.yaml', str(BINARY), 'zip-test')
