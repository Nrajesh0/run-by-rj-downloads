#!/usr/bin/env python3
"""Authenticate a small website-only overlay, never app/repository files."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

LIMIT = 5 * 1024 * 1024
FILES = {'index.html', 'style.css', 'theme.js', 'assets/workspace.jpg', 'icon.svg', 'website.json'}
BOUNDS = {'website.tar.gz': LIMIT, 'release-signing-key.asc': 128 * 1024,
          'SHA256SUMS': 4096, 'SHA256SUMS.asc': 64 * 1024}


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def newest(releases, version):
    candidates = [r for r in releases if not r['draft'] and
                  re.fullmatch(r'website-' + re.escape(version) + r'-[1-9][0-9]*', r['tag_name'])]
    return max(candidates, key=lambda r: int(r['tag_name'].rsplit('-', 1)[1]), default=None)


def receipt(release):
    if release is None:
        return None
    return {'id': release['id'], 'tag': release['tag_name'],
            'assets': sorted([a['name'], a.get('id'), a['size'], a.get('updated_at'), a.get('digest')]
                             for a in release['assets'])}


def verify(assets, expected, verifier, site=None):
    for name, bound in BOUNDS.items():
        path = assets / name
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= bound:
            raise ValueError('Invalid website asset bounds')
    public = (assets / 'release-signing-key.asc').read_bytes()
    if not public.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----') or b'PRIVATE KEY' in public:
        raise ValueError('Website key must be public')
    with tempfile.TemporaryDirectory(prefix='run-website-verify-') as temporary:
        root = Path(temporary); home = root / 'key'; home.mkdir(mode=0o700)
        try:
            verifier.command('gpg', '--homedir', home, '--batch', '--import', assets / 'release-signing-key.asc')
            if verifier.primary_keys(home) != [expected['app']['fingerprint']] or verifier.primary_keys(home, True):
                raise ValueError('Website signing key differs from app trust')
            verifier.command('gpg', '--homedir', home, '--batch', '--verify', assets / 'SHA256SUMS.asc', assets / 'SHA256SUMS')
        finally:
            verifier.command('gpgconf', '--homedir', home, '--kill', 'gpg-agent')
        found = set()
        for line in (assets / 'SHA256SUMS').read_text().splitlines():
            match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9._-]+)', line)
            if not match or match[2] not in {'website.tar.gz', 'release-signing-key.asc'} or match[2] in found:
                raise ValueError('Invalid website inventory')
            found.add(match[2])
            if sha256(assets / match[2]) != match[1]:
                raise ValueError('Website checksum mismatch')
        if found != {'website.tar.gz', 'release-signing-key.asc'}:
            raise ValueError('Incomplete website inventory')
        destination = root / 'extracted'; destination.mkdir()
        with tarfile.open(assets / 'website.tar.gz', 'r:gz') as archive:
            names, members, total = set(), [], 0
            for item in archive:
                path = PurePosixPath(item.name); total += item.size
                relative = path.relative_to('website').as_posix() if path.parts and path.parts[0] == 'website' else None
                if (not item.isfile() or relative not in FILES or relative in names or item.size < 0 or
                        total > LIMIT or '\\' in item.name or path.as_posix() != item.name):
                    raise ValueError('Website archive may contain only exact allowlisted files')
                names.add(relative); members.append(item)
            if names != FILES:
                raise ValueError('Incomplete website archive')
            archive.extractall(destination, members=members, filter='data')
        record = destination / 'website/website.json'
        if record.stat().st_size > 4096 or json.loads(record.read_text()) != expected:
            raise ValueError('Website source or app binding differs')
        if site is not None:
            for name in FILES:
                target = site / name
                if target.is_symlink():
                    raise ValueError('Website destination cannot be a link')
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(destination / 'website' / name, target)


def apply(repository, release, output, app, app_archive_hash, verifier):
    if release is None:
        return
    if {a['name'] for a in release['assets']} != set(BOUNDS) or len(release['assets']) != len(BOUNDS):
        raise ValueError('Unexpected website attachments')
    expected = {'schema': 1, 'app': app, 'app_archive_sha256': app_archive_hash,
                'source': verifier.identity(release, 'RuN-Source-Commit'),
                'sequence': int(release['tag_name'].rsplit('-', 1)[1])}
    obj = verifier.api(repository, 'git/ref/tags/' + release['tag_name'])['object']
    for _ in range(8):
        if obj['type'] != 'tag':
            break
        obj = verifier.api(repository, 'git/tags/' + obj['sha'])['object']
    if obj.get('type') != 'commit' or obj.get('sha') != verifier.identity(release, 'RuN-Publication-Commit'):
        raise ValueError('Website publication tag changed')
    with tempfile.TemporaryDirectory(prefix='run-website-download-') as directory:
        for asset in release['assets']:
            if not 0 < asset['size'] <= BOUNDS[asset['name']]:
                raise ValueError('Website download exceeds bound')
            subprocess.run(['gh', 'release', 'download', release['tag_name'], '--repo', repository,
                            '--dir', directory, '--pattern', asset['name']], check=True)
        verify(Path(directory), expected, verifier, output / 'site')
