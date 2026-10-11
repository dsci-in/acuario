"""Acuario Lab - multi-agent security research subsystem.

The lab contains capabilities that have no equivalent in single-agent
ReAct-loop tools:

  agents/
    skeptic.py    - adversarial gate: every finding must survive a refutation
                    attempt before entering the pool (precision)
    critic.py     - reflective post-ReAct pass: "what did you miss?"  (recall)
    orchestrator.py - cross-file investigation planner (cross-file recall)

  sandbox/
    snapshot.py   - Docker-commit checkpoint/rollback for exploit branching
    behavior.py   - real ptrace-based syscall auditing (vs. post-hoc regex)

These modules are imported lazily so the base audit pipeline works without
them; features are opt-in via HuntPoolConfig flags and CLI flags.
"""
