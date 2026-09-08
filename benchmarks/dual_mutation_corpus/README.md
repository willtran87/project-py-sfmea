# Dual mutation-engine qualification corpus

This governed corpus qualifies mutation evidence by executing canonical mutants
through two independently implemented engines. Each observation must retain the
subject and test-suite digests, canonical and engine-local mutant identities,
operator, location, engine version, outcome, timing, and evidence reference.

The bundled case is a deterministic canary, not representative validation. A
qualification campaign must pin both engines, pre-register mapping and exclusion
rules, retain every invalid or discordant mutant, independently adjudicate
equivalence, and correlate results with real defects. Agreement is not truth.
