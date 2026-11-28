#!/usr/bin/env python3
# Copyright (c) 2026 TULPAR project team
# SPDX-License-Identifier: GPL-2.0-only
"""Generates tulpar-cry-test-vectors.h, the published vectors of the M-CRY crypto tests (RSD-CRY-01).

The vectors come from two pinned sources, checked out with only the files listed below:

  NIST ACVP-Server, https://github.com/usnistgov/ACVP-Server, commit ACVP_COMMIT,
    gen-val/json-files/{ML-KEM-keyGen-FIPS203,ML-KEM-encapDecap-FIPS203,ML-DSA-keyGen-FIPS204}/
  Project Wycheproof, https://github.com/C2SP/wycheproof, commit WYCHEPROOF_COMMIT,
    testvectors_v1/{mlkem_1024_test,mldsa_87_sign_seed_test,mldsa_87_verify_test,
    hkdf_sha384_test}.json

Usage:
  python3 -I tulpar-cry-test-vectors.py --wycheproof DIR --acvp DIR > tulpar-cry-test-vectors.h
  clang-format -i tulpar-cry-test-vectors.h
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ACVP_COMMIT = '975de31eb83d87039ec88934fdc47d8c312b892d'
WYCHEPROOF_COMMIT = '65ca494727a52944c204441c860b039e6786b99b'
CHUNK = 64


def fail(message):
    sys.exit(f'tulpar-cry-test-vectors.py: {message}')


def check_commit(clone, expected):
    actual = subprocess.run(['git', '-C', str(clone), 'rev-parse', 'HEAD'],
                            capture_output=True, text=True, check=True).stdout.strip()
    if actual != expected:
        fail(f'{clone} is at {actual}, expected {expected}')


def load(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def find(data, tc_id):
    """Return (group, test) of the test case with the given tcId."""
    for group in data['testGroups']:
        for test in group['tests']:
            if test['tcId'] == tc_id:
                return group, test
    fail(f'tcId {tc_id} not found')


def require(condition, message):
    if not condition:
        fail(message)


def collect(wycheproof, acvp):
    """Return a list of (name, comment, hex) in output order."""
    out = []
    acvp_files = Path(acvp) / 'gen-val' / 'json-files'
    acvp_tag = f'ACVP-Server {ACVP_COMMIT[:12]}'

    keygen = load(acvp_files / 'ML-KEM-keyGen-FIPS203' / 'internalProjection.json')
    group, test = find(keygen, 51)
    require(group['parameterSet'] == 'ML-KEM-1024', 'ML-KEM keyGen tcId 51 is not ML-KEM-1024')
    where = f'{acvp_tag}, ML-KEM-keyGen-FIPS203 tcId 51'
    out += [('kAcvpMlKemKeyGenD', f'{where}: d', test['d']),
            ('kAcvpMlKemKeyGenZ', f'{where}: z', test['z']),
            ('kAcvpMlKemKeyGenEk', f'{where}: ek', test['ek'])]

    encap = load(acvp_files / 'ML-KEM-encapDecap-FIPS203' / 'internalProjection.json')
    group, test = find(encap, 51)
    require(group['parameterSet'] == 'ML-KEM-1024' and group['function'] == 'encapsulation',
            'ML-KEM encapDecap tcId 51 is not an ML-KEM-1024 encapsulation')
    where = f'{acvp_tag}, ML-KEM-encapDecap-FIPS203 tcId 51'
    out += [('kAcvpMlKemEncapEk', f'{where}: ek', test['ek']),
            ('kAcvpMlKemEncapM', f'{where}: m', test['m']),
            ('kAcvpMlKemEncapC', f'{where}: c', test['c']),
            ('kAcvpMlKemEncapK', f'{where}: k', test['k'])]
    group, test = find(encap, 159)
    require(group['parameterSet'] == 'ML-KEM-1024' and group['function'] == 'encapsulationKeyCheck'
            and test['testPassed'] is False, 'ML-KEM encapDecap tcId 159 is not a failing key check')
    out += [('kAcvpMlKemBadEk',
             f'{acvp_tag}, ML-KEM-encapDecap-FIPS203 tcId 159: ek that fails the modulus check',
             test['ek'])]

    dsa = load(acvp_files / 'ML-DSA-keyGen-FIPS204' / 'internalProjection.json')
    group, test = find(dsa, 51)
    require(group['parameterSet'] == 'ML-DSA-87', 'ML-DSA keyGen tcId 51 is not ML-DSA-87')
    where = f'{acvp_tag}, ML-DSA-keyGen-FIPS204 tcId 51'
    out += [('kAcvpMlDsaKeyGenSeed', f'{where}: seed', test['seed']),
            ('kAcvpMlDsaKeyGenPk', f'{where}: pk', test['pk'])]

    wp_files = Path(wycheproof) / 'testvectors_v1'
    wp_tag = f'Wycheproof {WYCHEPROOF_COMMIT[:12]}'

    kem = load(wp_files / 'mlkem_1024_test.json')
    for name, tc_id in (('Valid', 2), ('Reject', 194)):
        group, test = find(kem, tc_id)
        require(group['parameterSet'] == 'ML-KEM-1024' and test['result'] == 'valid',
                f'mlkem_1024_test tcId {tc_id} is not a valid ML-KEM-1024 case')
        where = f'{wp_tag}, mlkem_1024_test.json tcId {tc_id}'
        out += [(f'kWpMlKem{name}Seed', f'{where}: seed d || z', test['seed']),
                (f'kWpMlKem{name}Ek', f'{where}: ek', test['ek']),
                (f'kWpMlKem{name}C', f'{where}: c', test['c']),
                (f'kWpMlKem{name}K', f'{where}: K', test['K'])]

    sign = load(wp_files / 'mldsa_87_sign_seed_test.json')
    verify = load(wp_files / 'mldsa_87_verify_test.json')
    sign_group, sign_test = find(sign, 1)
    require(sign_group is sign['testGroups'][0], 'sign tcId 1 is not in testGroups[0]')
    require('ctx' not in sign_test and sign_test['result'] == 'valid',
            'sign tcId 1 is not a valid signature with the empty context')
    where = f'{wp_tag}, mldsa_87_sign_seed_test.json'
    out += [('kWpMlDsaSeed', f'{where} testGroups[0]: privateSeed', sign_group['privateSeed']),
            ('kWpMlDsaPk', f'{where} testGroups[0]: publicKey', sign_group['publicKey']),
            ('kWpMlDsaMsg', f'{where} tcId 1: msg', sign_test['msg']),
            ('kWpMlDsaSig', f'{where} tcId 1: deterministic sig', sign_test['sig'])]
    for name, tc_id in (('Short', 6), ('Flipped', 8)):
        group, test = find(verify, tc_id)
        require(group['publicKey'] == sign_group['publicKey'], f'verify tcId {tc_id} uses another key')
        require(test['msg'] == sign_test['msg'] and test['result'] == 'invalid',
                f'verify tcId {tc_id} is not an invalid signature over the sign tcId 1 message')
        out += [(f'kWpMlDsa{name}Sig',
                 f'{wp_tag}, mldsa_87_verify_test.json tcId {tc_id}: {test["comment"]}', test['sig'])]

    hkdf = load(wp_files / 'hkdf_sha384_test.json')
    group, test = find(hkdf, 70)
    require(test['result'] == 'valid' and test['size'] == 48, 'hkdf tcId 70 is not a valid 48-byte case')
    where = f'{wp_tag}, hkdf_sha384_test.json tcId 70'
    out += [('kWpHkdfIkm', f'{where}: ikm', test['ikm']),
            ('kWpHkdfSalt', f'{where}: salt', test['salt']),
            ('kWpHkdfInfo', f'{where}: info', test['info']),
            ('kWpHkdfOkm', f'{where}: okm (48 bytes)', test['okm'])]
    return out


def render(entries):
    lines = [
        '/*',
        ' * Copyright (c) 2026 TULPAR project team',
        ' *',
        ' * SPDX-License-Identifier: GPL-2.0-only',
        ' */',
        '',
        '// Generated by module/test/tulpar-cry-test-vectors.py; do not edit by hand.',
        f'// NIST ACVP-Server, https://github.com/usnistgov/ACVP-Server, commit {ACVP_COMMIT}',
        f'// Project Wycheproof, https://github.com/C2SP/wycheproof, commit {WYCHEPROOF_COMMIT}',
        '',
        '#ifndef TULPAR_CRY_TEST_VECTORS_H',
        '#define TULPAR_CRY_TEST_VECTORS_H',
        '',
        '#include <string_view>',
        '',
        'namespace ns3',
        '{',
        'namespace tulpar',
        '{',
        '/**',
        ' * @ingroup tulpar-tests',
        ' * Published test vectors of the M-CRY crypto tests (RSD-CRY-01), as hexadecimal strings.',
        ' */',
        'namespace vectors',
        '{',
    ]
    for name, comment, value in entries:
        value = value.lower()  # ACVP writes upper-case hexadecimal, Wycheproof lower-case
        require(len(value) % 2 == 0 and all(c in '0123456789abcdef' for c in value),
                f'{name} is not hexadecimal')
        lines.append('')
        lines.append(f'/// {comment}')
        chunks = [value[i:i + CHUNK] for i in range(0, len(value), CHUNK)] or ['']
        lines.append(f'constexpr std::string_view {name} =')
        lines += [f'    "{chunk}"' for chunk in chunks[:-1]]
        lines.append(f'    "{chunks[-1]}";')
        lines.append(f'static_assert({name}.size() == {len(value)});')
    lines += [
        '',
        '} // namespace vectors',
        '} // namespace tulpar',
        '} // namespace ns3',
        '',
        '#endif // TULPAR_CRY_TEST_VECTORS_H',
    ]
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--wycheproof', required=True, help='checkout of C2SP/wycheproof')
    parser.add_argument('--acvp', required=True, help='checkout of usnistgov/ACVP-Server')
    args = parser.parse_args()
    check_commit(args.wycheproof, WYCHEPROOF_COMMIT)
    check_commit(args.acvp, ACVP_COMMIT)
    sys.stdout.write(render(collect(args.wycheproof, args.acvp)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
