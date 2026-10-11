# Third-Party Notices

Acuario incorporates and depends on third-party components that remain under
their own licenses. This file records those notices, as required by the AGPL
(sections 4 and 5) and by the licenses of the components themselves. Nothing
here modifies the AGPL, which governs Acuario as a whole - see `LICENSE`.

## Incorporated source code

Certain Portions of Acuario incorporate source code originally authored by **Eric
Hartford** under the MIT License. Those portions are incorporated across parts
of Acuario's codebase and remain under the MIT License reproduced below. MIT
is compatible with the GNU AGPL and may be incorporated into an AGPL-licensed
work; the combined work is licensed under AGPL-3.0-or-later.

The MIT License is satisfied by preserving the copyright and permission notice
below; it does not require a file-by-file inventory, so none is asserted here.

```
MIT License

Copyright (c) 2026 Eric Hartford

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Python dependencies

A license scan over the installed dependency tree (203 third-party
distributions, 2026-09-07) found the large majority permissive and
AGPL-compatible - MIT, Apache-2.0, BSD (2/3-Clause), MPL-2.0, ISC, PSF, and
zlib. The components carrying copyleft or proprietary terms are recorded
below with their handling.

| Component | License | Status |
|---|---|---|
| `scapy` | **GPL-2.0-only** | AGPL-incompatible - and never imported in Acuario (only a stale comment referenced it). **Removed** from the dependency set. |
| `pymetasploit3` | MIT | Optional `metasploit` extra only (v1.0.x; <https://github.com/DanMcInerney/pymetasploit3>). The distributed package ships an MIT `LICENSE` file; the PyPI metadata's bare "GPL" string is stale and unversioned. MIT is AGPL-compatible. |
| `asyncssh` | EPL-2.0 OR GPL-2.0-or-later | Compatible via its GPL-2.0-**or-later** arm (upgradable to GPLv3 / AGPLv3). |
| `docutils` | Public Domain / BSD / GPL (multi) | Compatible via the Public-Domain / BSD option. |

**NVIDIA CUDA runtime (proprietary).** The optional ML / vector extra pulls
NVIDIA CUDA runtime libraries (`nvidia-cublas`, `nvidia-cudnn`,
`nvidia-cuda-runtime`, `nvidia-cusparse`, and related) under NVIDIA's
proprietary license. These are separately-distributed GPU runtime components,
used unmodified and not incorporated into Acuario's source - the same posture
any GPL/AGPL project has toward CUDA or the host OS. They are not shipped as
part of Acuario.

Re-run the scan before each release:

```bash
uv run --with pip-licenses pip-licenses --format=markdown --with-urls --with-license-file
```

Calling a hosted LLM API over the network is mere network interaction and
raises no copyleft question; vendoring a proprietary client library does, and
must be checked against its terms first.
