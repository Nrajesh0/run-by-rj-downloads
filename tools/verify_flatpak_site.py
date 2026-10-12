#!/usr/bin/env python3
"""Deploy only a bounded site authenticated by the owner's pinned public key."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import tempfile

LIMIT = 900 * 1024 * 1024
INVENTORY = {'run-by-rj-development.flatpak', 'release-signing-key.asc', 'manifest.json', 'pages-site.tar.gz'}
BOUNDS = {'release-signing-key.asc': 128 * 1024, 'SHA256SUMS': 4096,
          'SHA256SUMS.asc': 64 * 1024, 'pages-site.tar.gz': LIMIT}


def command(*args):
    return subprocess.check_output(list(map(str, args)))


def api(repository, resource):
    return json.loads(command('gh', 'api', f'repos/{repository}/{resource}'))


def identity(release, label):
    values = re.findall(r'^' + re.escape(label) + r': ([0-9a-f]{40})$', release.get('body') or '', re.MULTILINE)
    if len(values) != 1:
        raise ValueError('Missing or ambiguous release identity: ' + label)
    return values[0]


def newest(repository):
    pages = json.loads(command('gh', 'api', '--paginate', '--slurp', f'repos/{repository}/releases?per_page=100'))
    candidates = [r for page in pages for r in page if not r['draft'] and
                  re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', r['tag_name']) and
                  any(a['name'] == 'pages-site.tar.gz' for a in r['assets'])]
    if not candidates:
        raise ValueError('No published signed-site release exists yet')
    return max(candidates, key=lambda r: tuple(map(int, r['tag_name'][1:].split('.'))))


def primary_keys(home, secret=False):
    data = command('gpg', '--homedir', home, '--batch', '--with-colons',
                   '--list-secret-keys' if secret else '--list-keys').decode()
    result, primary = [], False
    for line in data.splitlines():
        fields = line.split(':')
        if fields[0] in ('pub', 'sec'):
            primary = True
        elif fields[0] == 'fpr' and primary:
            result.append(fields[9]); primary = False
    return result


def extract_site(archive, destination):
    with tarfile.open(archive, 'r:gz') as stream:
        members = []
        names = set()
        size = 0
        for member in stream:
            path = PurePosixPath(member.name)
            size += member.size
            if (len(members) >= 100_000 or size > LIMIT or member.size < 0 or
                    path.is_absolute() or '..' in path.parts or '\\' in member.name or
                    not path.parts or path.parts[0] != 'site' or
                    path.as_posix() in names or not (member.isfile() or member.isdir())):
                raise ValueError('Unsafe or oversized site archive')
            names.add(path.as_posix()); members.append(member)
        stream.extractall(destination, members=members, filter='data')


def verify(assets, output, expected):
    for name, bound in BOUNDS.items():
        path = assets / name
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= bound:
            raise ValueError('Invalid asset bounds: ' + name)
    public = (assets / 'release-signing-key.asc').read_bytes()
    if b'PRIVATE KEY' in public or not public.startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----'):
        raise ValueError('Expected an armored public key only')
    with tempfile.TemporaryDirectory(prefix='run-public-verification-') as directory:
        home = Path(directory); home.chmod(0o700)
        try:
            command('gpg', '--homedir', home, '--batch', '--import', assets / 'release-signing-key.asc')
            if primary_keys(home) != [expected['fingerprint']] or primary_keys(home, True):
                raise ValueError('Public signing key differs from the pinned owner fingerprint')
            command('gpg', '--homedir', home, '--batch', '--verify', assets / 'SHA256SUMS.asc', assets / 'SHA256SUMS')
        finally:
            command('gpgconf', '--homedir', home, '--kill', 'gpg-agent')
    found = set()
    for line in (assets / 'SHA256SUMS').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([A-Za-z0-9._-]+)', line)
        if not match or match[2] not in INVENTORY or match[2] in found:
            raise ValueError('Invalid signed checksum inventory')
        found.add(match[2])
        if match[2] in BOUNDS:
            with (assets / match[2]).open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != match[1]:
                    raise ValueError('Signed asset checksum mismatch')
    if found != INVENTORY:
        raise ValueError('Incomplete signed checksum inventory')
    extract_site(assets / 'pages-site.tar.gz', output)
    record = output / 'site/release.json'
    if not record.is_file() or record.stat().st_size > 4096 or json.loads(record.read_text()) != expected:
        raise ValueError('Signed site does not match release, hosting URL or pinned key')
    for name in ['index.html', 'run-by-rj.flatpakref', 'run-by-rj.flatpakrepo', 'repo/summary', 'repo/summary.sig']:
        if not (output / 'site' / name).is_file():
            raise ValueError('Incomplete signed update site')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path(__file__).resolve().parents[1] / 'distribution.json')
    parser.add_argument('--output', type=Path, required=True)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument('--download', action='store_true')
    modes.add_argument('--check-freshness', action='store_true')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    repository = os.environ.get('GH_REPO', '')
    if repository != config['repository']:
        raise ValueError('Unexpected downloads repository')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise ValueError('Invalid public repository')
    release = newest(repository)
    receipt = {'release_id': release['id'], 'tag': release['tag_name'],
               'source': identity(release, 'RuN-Source-Commit'),
               'publication': identity(release, 'RuN-Publication-Commit')}
    if args.check_freshness:
        if json.loads((args.output / 'verified-release.json').read_text()) != receipt:
            raise ValueError('A newer or changed release exists; rerun deployment')
        return
    requested = os.environ.get('REQUESTED_VERSION', '')
    if requested and requested != release['tag_name'][1:]:
        raise ValueError('Requested version is not newest; refuse rollback')
    pin = config['fingerprint']
    if os.environ.get('BASE_URL', '').rstrip('/') != config['base_url']:
        raise ValueError('GitHub Pages URL differs from pinned distribution configuration')
    if not re.fullmatch(r'[0-9A-F]{40}|[0-9A-F]{64}', pin):
        raise ValueError('Set the full public FLATPAK_GPG_FINGERPRINT repository variable')
    obj = api(repository, 'git/ref/tags/' + release['tag_name'])['object']
    for _ in range(8):
        if obj['type'] != 'tag':
            break
        obj = api(repository, 'git/tags/' + obj['sha'])['object']
    if obj['type'] != 'commit' or obj['sha'] != receipt['publication']:
        raise ValueError('Public release tag changed')
    assets = {a['name']: a for a in release['assets']}
    if len(assets) != len(release['assets']) or set(assets) != INVENTORY | {'SHA256SUMS', 'SHA256SUMS.asc'}:
        raise ValueError('Unexpected public release attachments')
    for name, bound in BOUNDS.items():
        if not 0 < assets[name]['size'] <= bound:
            raise ValueError('Release attachment exceeds size budget: ' + name)
    args.output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix='run-download-assets-') as directory:
        for name in BOUNDS:
            subprocess.run(['gh', 'release', 'download', release['tag_name'], '--repo', repository,
                            '--dir', directory, '--pattern', name], check=True)
        verify(Path(directory), args.output, {'version': release['tag_name'][1:], 'commit': receipt['source'],
            'base_url': os.environ.get('BASE_URL', '').rstrip('/'), 'fingerprint': pin,
            'branch': 'development-security-v2', 'application': 'io.github.nrajesh0.RunByRj'})
    (args.output / 'verified-release.json').write_text(json.dumps(receipt))
    print('Verified signed site for ' + release['tag_name'])


if __name__ == '__main__':
    main()
