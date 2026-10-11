# Contributing to Acuario

Thanks for your interest in Acuario - Multi AI Agent Source Code Auditing
Sandbox.

## Licensing of contributions

Acuario is licensed under the **GNU Affero General Public License v3.0 or later**
(`AGPL-3.0-or-later`). Contributions are accepted on an **inbound = outbound**
basis, which means:

- **You keep your copyright.** You are not asked to assign or transfer
  copyright in your work to DSCI or to anyone else.
- **Your contribution is licensed under the same terms as the project.** By
  submitting a contribution, you license it to the project and to all
  downstream recipients under AGPL-3.0-or-later - the identical terms that
  cover the rest of Acuario.
- **No relicensing rights are requested.** DSCI does not ask for, and does
  not receive, permission to distribute your contribution under any licence
  other than the project's own.
- **You may reuse your own work.** As the copyright holder of your
  contribution, you remain free to use it in your own projects under whatever
  terms you choose.

There is no Contributor Licence Agreement to sign.

## Developer Certificate of Origin

We use the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO) rather than a CLA. By signing off on a commit, you certify that:

1. You wrote the contribution yourself, or you otherwise have the right to
   submit it under AGPL-3.0-or-later; and
2. If your employer or institution holds rights in work you produce, you have
   their permission to contribute it, or they have waived those rights; and
3. You understand that the contribution is public, is recorded permanently,
   and is redistributed under the project's licence.

Sign off your commits by adding the `-s` flag:

```bash
git commit -s -m "Add taint analysis for Python subprocess sinks"
```

This appends a line to your commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

Use your real name and a real email address.

## Keep the AGPL source offer satisfiable

Acuario is AGPL-3.0. Under section 13, anyone who runs a *modified* version as
a network service must offer its users the Corresponding Source of the exact
revision they interact with. Acuario ships as a command-line tool and exposes
no network service of its own, so there is nothing to serve today.

If your pull request adds a network-facing interface - a web UI, an HTTP API,
or a hosted service - you are adding exactly the surface section 13 governs.
Make sure that interface can hand its users the source of the revision it is
running. A pull request that adds a network service without a working source
offer will be sent back.

## Third-party code and dependencies

Acuario is strong copyleft, which means not every licence can be combined
with it.

- **Do not** paste code from another project into Acuario unless its licence
  is AGPL-v3-compatible. If you are unsure, ask in the pull request before
  writing the code rather than after.
- **Compatible** inbound licences include MIT, BSD-2/3-Clause, ISC,
  Apache-2.0, GPL-3.0, and AGPL-3.0 itself. Section 13 of the License
  expressly permits combining Acuario with GPL-v3 code; in the combined
  work, the GPL-licensed part stays under the GPL and the rest stays AGPL.
- **Incompatible** licences include GPL-2.0-only (no "or later" clause), and
  any proprietary, source-available, or field-of-use-restricted licence -
  SSPL, BSL, Elastic, Confluent, and anything marked "non-commercial use
  only".
- Permissive code flows **into** copyleft, never the reverse. Apache-2.0 can
  come into Acuario; Acuario cannot go into an Apache-2.0 project.
- **The AGPL is stickier than the GPL.** Acuario's code cannot be pulled into
  a GPL-only project, because the GPL has no equivalent of section 13 and so
  cannot carry its network obligation. If you want your contribution usable
  in GPL projects too, keep it in a separate upstream library under a
  permissive licence and depend on it, rather than writing it directly into
  Acuario.
- When you add a new dependency, add a corresponding entry to
  `THIRD-PARTY-NOTICES.md` in the same pull request, recording the component
  name, its licence, and how its terms are handled (with version and upstream
  URL where relevant).

Calling a hosted third-party API over the network - an LLM provider, for
instance - is network interaction, not linking, and raises no copyleft
question. Vendoring a proprietary client library into the repository is a
different matter and needs checking against that library's terms first.

Attributing code you did not write to yourself, or importing code whose
licence forbids it, is the one class of contribution we cannot accept under
any circumstances - it puts every downstream user of Acuario at risk.

## Reporting security issues

Please do not open a public issue for a security vulnerability in Acuario
itself. Follow the process in `SECURITY.md`.

## Questions

Open a discussion or issue, or write to opensource@dsci.in.
