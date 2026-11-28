#!/usr/bin/env python3
# Copyright (c) 2026 TULPAR project team
# SPDX-License-Identifier: GPL-2.0-only
"""Self-test of tools/check_static.py: every rule must catch a planted violation.

RSD-SIM-02a asks for a test that fails when an agent class includes the
ground-truth header. Cases 1 and 2 plant exactly that and expect the checker to
fail; the other cases do the same for the other rules. The clean tree must pass.
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from check_static import Checker  # noqa: E402

RULES = json.loads((HERE / 'deps_rules.json').read_text(encoding='utf-8'))


def run_checker(root):
    c = Checker(root, RULES)
    c.check_sources()
    c.check_cmake()
    c.check_routing()
    return {rule for rule, _, _ in c.violations}


def append(root, rel, text):
    path = Path(root) / rel
    path.write_text(path.read_text(encoding='utf-8') + text, encoding='utf-8')


def include_botan(root, rel):
    """Plant the vendored Botan header and include it from another file (RSD-CRY-01e)."""
    header = Path(root) / 'third_party' / 'botan-3.13.0' / 'botan_all.h'
    header.parent.mkdir(parents=True, exist_ok=True)
    header.write_text('// stub of the vendored Botan amalgamation header\n', encoding='utf-8')
    append(root, rel, '\n#include "botan_all.h"\n')


def replace(root, rel, old, new):
    path = Path(root) / rel
    content = path.read_text(encoding='utf-8')
    assert old in content, (rel, old)
    path.write_text(content.replace(old, new, 1), encoding='utf-8')


CASES = [
    ('agent includes the ground-truth header by name (RSD-SIM-02a)', 'harness',
     lambda r: append(r, 'module/agent/sec/tulpar-sec.cc', '\n#include "tulpar-ground-truth.h"\n')),
    ('agent includes the ground-truth header by relative path (MD9)', 'harness',
     lambda r: append(r, 'module/agent/obs/tulpar-obs.cc', '\n#include "../../sim/tulpar-ground-truth.h"\n')),
    ('agent includes the exported harness header (MD9)', 'harness',
     lambda r: append(r, 'module/agent/mis/tulpar-mis.cc', '\n#include "ns3/tulpar-scenario.h"\n')),
    ('LSC includes an agent module (MD19)', 'lsc',
     lambda r: append(r, 'module/agent/lsc/tulpar-lsc.cc', '\n#include "tulpar-cry.h"\n')),
    ('security includes mission (MD5)', 'sec_motion',
     lambda r: append(r, 'module/agent/sec/tulpar-sec.cc', '\n#include "tulpar-mis.h"\n')),
    ('delivery includes the evidence store (Table 4.25, MD1)', 'module',
     lambda r: append(r, 'module/agent/del/tulpar-del.cc', '\n#include "tulpar-evs.h"\n')),
    ('agent reads the wall clock (RSD-SIM-01a)', 'wall_clock',
     lambda r: append(r, 'module/agent/com/tulpar-com.cc',
                      '\nstatic auto t0 = std::chrono::system_clock::now();\n')),
    ('agent uses an unseeded random device (RSD-SIM-01c)', 'wall_clock',
     lambda r: append(r, 'module/agent/evs/tulpar-evs.cc', '\nstatic std::random_device rd;\n')),
    ('LSC target links M-CRY (MD19)', 'lsc',
     lambda r: replace(r, 'module/CMakeLists.txt',
                       'INCLUDE ${TULPAR_DIR}/agent/lsc\n  DEPS tulpar_common',
                       'INCLUDE ${TULPAR_DIR}/agent/lsc\n  DEPS tulpar_common tulpar_cry')),
    ('agent target links the harness library (MD9)', 'harness',
     lambda r: replace(r, 'module/CMakeLists.txt',
                       'INCLUDE ${TULPAR_DIR}/agent/cry\n  DEPS tulpar_common',
                       'INCLUDE ${TULPAR_DIR}/agent/cry\n  DEPS tulpar_common ${libtulpar}')),
    ('mesh core includes an ns-3 socket (RSD-NET-01a)', 'mesh_core',
     lambda r: append(r, 'module/agent/com/tulpar-mesh-core.cc', '\n#include "ns3/socket.h"\n')),
    ('mesh core links its UDP adapter (RSD-NET-01a)', 'mesh_core',
     lambda r: replace(r, 'module/CMakeLists.txt',
                       'INCLUDE ${TULPAR_DIR}/agent/com\n)',
                       'INCLUDE ${TULPAR_DIR}/agent/com\n  DEPS tulpar_com\n)')),
    ('scenario installs the default routing of InternetStackHelper (RSD-NET-01a)', 'routing',
     lambda r: replace(r, 'module/sim/tulpar-scenario.cc',
                       '    internet.SetRoutingHelper(Ipv4StaticRoutingHelper());\n', '')),
    ('scenario fills global routing tables (RSD-NET-01a)', 'routing',
     lambda r: append(r, 'module/sim/tulpar-scenario.cc',
                      '\nstatic void F() { Ipv4GlobalRoutingHelper::PopulateRoutingTables(); }\n')),
    ('agent adds a static route (RSD-NET-01a)', 'routing',
     lambda r: append(r, 'module/agent/com/tulpar-com.cc',
                      '\nstatic void G(Ptr<Ipv4StaticRouting> s) { s->AddHostRouteTo(Ipv4Address(), 1); }\n')),
    ('an agent module other than M-CRY includes Botan (RSD-CRY-01e)', 'module',
     lambda r: include_botan(r, 'module/agent/com/tulpar-com.cc')),
    ('M-COM target links Botan (RSD-CRY-01e)', 'module',
     lambda r: replace(r, 'module/CMakeLists.txt',
                       'DEPS tulpar_common tulpar_cry tulpar_mesh_core',
                       'DEPS tulpar_common tulpar_cry tulpar_botan tulpar_mesh_core')),
]


def main():
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp) / 'clean'
        shutil.copytree(ROOT / 'module', base / 'module')
        found = run_checker(base)
        print(('PASS' if not found else 'FAIL') + f' clean tree has no violation {sorted(found)}')
        failures += bool(found)
        for i, (title, rule, plant) in enumerate(CASES, 1):
            case = Path(tmp) / f'case{i}'
            shutil.copytree(ROOT / 'module', case / 'module')
            plant(case)
            found = run_checker(case)
            ok = rule in found
            failures += not ok
            print(('PASS' if ok else 'FAIL') + f' {title}: expected [{rule}], got {sorted(found)}')
    print(f'test_check_static: {len(CASES) + 1 - failures}/{len(CASES) + 1} passed')
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
