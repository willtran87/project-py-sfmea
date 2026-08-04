## Summary

Describe the user-visible change and the assurance problem it addresses.

## Evidence

- [ ] `python -m compileall -q src`
- [ ] `python -m ruff check src tests`
- [ ] `python -m pytest -q`
- [ ] Documentation and public schemas updated when contracts changed
- [ ] No repository-under-analysis code is imported or executed during scanning/reporting

## Claim boundaries

List new limitations, unresolved questions, heuristic behavior, or claims that require human
review. Explain any change to artifact formats, integrity, evidence, or analysis-state binding.
