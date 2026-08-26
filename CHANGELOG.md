# Changelog

Notable user-visible changes are recorded here. PySFMEA follows semantic versioning for the
package; public artifact and schema identifiers carry their own explicit compatibility versions.

## Unreleased

- Refresh the generated-test governance diagrams and operator documentation to expose format-1
  declared gates separately from format-2 lifecycle loading, paired execution reconciliation,
  manifest/raw-artifact verification, 15 derived gates, and exact replay. Add a campaign sequence
  view and keep public schema descriptions aligned with the executable evidence contract.
- Reconcile generated-test fault-detection qualification to exact analysis-linked baseline and
  seeded execution manifests plus every retained raw artifact. Add fail-closed evidence-root
  confinement, paired-test/status/manifest checks, standalone build/replay CLI commands, tamper
  regressions, and a dedicated typed evidence subsystem so digest strings alone receive no credit.
- Add format-2 artifact-backed generated-test qualification. Exact bounded analysis, proposal,
  application-receipt, and paired baseline/seeded-fault records now drive derived validity,
  target-binding, execution, stimulus, criteria, fault-detection, and reviewer outcomes with a
  fifteenth evidence gate and exact semantic replay. Refine target-call analysis to ignore unrelated
  helper shadowing while rejecting deferred, uncalled nested-body calls and target-scope rebinding.
- Strengthen governed LLM test implementation with exact import-qualified target binding inside
  the named test, rejecting local lookalikes, wrong modules, rebound aliases, and collection-only
  calls. Add a subject-bound, independently governed test-generation quality corpus and evaluator
  with expected and actual proposal/refusal populations plus validity, execution, stimulus,
  criteria, seeded-fault, reviewer, and unsafe-change gates. Content-seal results and support exact-
  corpus semantic replay. Surface LLM-origin registration and internal
  evidence readiness in the self-contained HTML assurance view while keeping proposal/publication
  receipts explicitly external. Refresh the operator, methodology, confidence-gate, and visual
  documentation with the separate seven-gate per-test and fourteen-gate subject-qualification
  lanes, and reconcile the diagram portfolio with every generated category.
- Add a governed LLM assurance-test generation workflow: bounded source-grounded packets,
  closed proposal validation, three-attempt repair provenance, isolated staging, explicit
  human publication receipts, and seven fail-closed readiness gates covering registration,
  restricted execution, observed failure stimulus, acceptance criteria, and independent evidence
  review. Publish and validate every proposal, staging, receipt, verification, and readiness
  artifact with versioned JSON Schemas; expose the workflow through dedicated CLI commands; add
  provider prompt/version isolation, secret-egress checks, path and source integrity enforcement,
  transactional publication rollback, coverage ratchets, end-to-end tests, and operator guidance.
- Attach resolved internal component references and IDs to every call site, including explicit
  unresolved/ambiguous status, so downstream sequences do not reconstruct site identity from an
  aggregate caller edge. Preserve unresolved interface candidates when another raw name in the
  same component normalizes to the same resolved reference, add `transmit` to the interface-verb
  vocabulary, and prefer exact qualified targets before leaf-name fallback for older analyses.
  Advance the fact cache to format 29 and add shared-reference shadowing, qualified-method, legacy
  fallback, flow, cascade, and ordered-sequence regressions.
- Preserve one source-ordered static sequence across internal calls, unresolved external candidates,
  and unresolved dynamic targets instead of appending interface/dynamic evidence after the internal
  walk. Reconciliation now reports external as well as dynamic interaction counts. Internal-call,
  interprocedural-flow, resilience, and typed-exception resolution use the raw call spelling to
  reject weak lexical/import targets shadowed by parameters, local assignments, or module rebinding
  while retaining stronger receiver-type evidence. Advance
  the fact cache to format 28 and add mixed-order plus direct-call rebinding regressions.
- Resolve decorator-factory applications to a returned repository function or lambda only when the
  factory, its single unconditional direct return, and the returned synchronous undecorated component are all
  unique and unshadowed. Feed the resulting edge into callers, sequences, value flow, and fixed-point
  typed exception cascades with producer/return/target provenance. Module-initialization facts now
  retain module-rebinding evidence so unsafe factory resolution fails closed. Remaining dynamic
  applications become low-confidence `static_dynamic_call` sequence interactions and Mermaid
  participants instead of disappearing from visual output. Advance the fact cache to format 27 and
  add positive cascade plus rebinding-negative and sequence-rendering regressions.
- Close the remaining Python definition-time invocation and lazy-type boundaries. Call-form
  decorators now retain both the factory call and the reverse-order application of its returned
  callable as an explicitly unresolved call-result site, including decorated-object argument and
  rebinding context without double-counting or inventing a target. Python 3.12+ type-alias values
  and generic type-parameter bounds/defaults with scanner-visible behavior become distinct
  `deferred_type_expression` components, with their own calls, failures, cascades, and fingerprints;
  they no longer appear as module/class startup execution. Remove lazy type expressions from
  enclosing startup fingerprints, advance the fact cache to format 26, and add function, class,
  exception-propagation, ownership, ordering, and fingerprint regressions.
- Correct annotation and deferred-expression execution boundaries. Attribute scanner-visible eager
  module, class, parameter, variadic, keyword-only, and return annotation calls to module startup
  or the enclosing callable in Python definition order; never treat local-variable annotations as
  executed calls; and honor explicit `from __future__ import annotations` across module, class,
  function, and nested-definition analysis. Remove deferred lambda bodies and generator filters,
  nested iterables, targets, and elements from enclosing startup fingerprints while retaining their
  eager defaults/outer iterable. Keep generic subscriptions and `A | B` type composition as type
  metadata rather than startup/calculation findings. Advance the fact cache to format 25 and add
  caller, cascade, ordering, future-import, assurance-precision, and fingerprint-sensitivity
  regressions.
- Model scanner-visible class construction in its actual enclosing execution. Top-level class
  decorator expressions/applications, dynamic bases and metaclass keywords, field initializers,
  and method defaults now belong to module initialization in Python order; nested class work stays
  on its enclosing function. Declarative model/exception components retain contract evidence but
  no longer duplicate class-body calls or cascades. Normalize deferred method bodies out of startup
  fingerprints, invalidate stale facts through cache format 24, and add ordering, ownership, and
  exception-propagation regressions.
- Attribute Python function-definition execution to the scope that actually performs it. Decorator
  factory expressions now execute before defaults, bare decorator applications execute afterward
  in reverse order, and nested definitions remain on their enclosing function. Top-level dynamic
  definitions create module-initialization evidence, while the declared callable retains route,
  task, and framework metadata without false decorator call edges or exception cascades. Traverse
  default/decorator expressions for nested lambda and generator discovery, invalidate stale facts
  through cache format 23, and add ordering, context, caller, and exception-propagation regressions.
- Separate deferred Python execution from enclosing-function evidence. Named and inline lambdas
  and generator-expression bodies are now distinct components, so their calls, exceptions,
  sequences, data flow, and failure cascades are not falsely attributed to callable or generator
  construction. Lambda defaults and a generator expression's outermost iterable remain on the
  parent because Python evaluates them immediately; generator filters, nested iterables, and
  yielded elements stay on the deferred component with exact lexical context and yield flow.
  Traverse eager list/set/dict comprehensions in Python's iterable/filter/element order instead of
  AST field order. Honor `include_nested` for the new components, retain immediate expressions when
  nested components are excluded, invalidate stale facts through cache format 22, and add cascade,
  ordering, context, and exclusion regressions.
- Resolve `factory().method()` dispatch when the factory maps to one unique, undecorated,
  synchronous, non-generator repository function with one concrete return annotation. Retain the
  producer component, raw annotation, normalized receiver type, and explicit static-authority
  boundary on the call site, then feed the refined edge into callers, interprocedural data flow,
  exception cascades, sequences, and interface discovery. Nullable annotations remain unresolved
  so a possible `None` dereference is not hidden; `Any`, `Self`, `Never`, `NoReturn`, multi-type or
  indeterminate unions, decorated/async/generator/method factories, local or module rebinding,
  shadowed parameters, and ambiguous producers also remain unresolved. Correct union parsing so `Concrete | Any` cannot be narrowed to the
  concrete member, publish return-type evidence on components, and invalidate stale facts through
  cache format 21.
- Evaluate bounded, exact-built-in ASCII f-strings during safe static control-flow analysis,
  including static expressions, `!s`/`!r`/`!a` conversions, and nested static format
  specifications. This removes calls, raises, sequences, and failure cascades from provably
  impossible formatted-string branches without executing repository code. Dynamic or unsupported
  values, collections, non-ASCII data, locale-sensitive formatting, exceptional formats, excessive
  width/precision, and over-limit results remain conservative. Publish and tamper-validate the new
  format-specification ceiling in `pysfmea-static-control-flow-model-3`, invalidate stale facts
  through cache format 20, and add positive and adversarial regression coverage.
- Resolve unshadowed zero-argument `super().method()` calls to an exact direct base method when
  static single-inheritance evidence is available. Preserve imported-base provenance and feed the
  corrected edge into caller, interprocedural data-flow, exception-cascade, and sequence models.
  Keep arbitrary call-result dispatch such as `factory().method()` explicitly unresolved unless a
  future analyzer supplies receiver-type evidence, rather than collapsing it to a bare method.
  Shadowed `super`, static methods, explicit/dynamic `super(...)`, and multiple inheritance now
  remain explicitly unresolved instead of being flattened to a bare method name and cross-linked
  to unrelated classes. Retain base evidence on method components, invalidate stale facts through
  cache format 19, and add same-file/imported-base positive cases plus adversarial negative cases.
- Make Python call resolution package-aware for `from .module import symbol`,
  `from . import module`, ancestor-relative imports, and function-local relative imports. This
  prevents same-named modules in sibling packages from creating false internal-call, data-flow,
  exception-cascade, and sequence edges while preserving exact callers in each package. Relative
  imports without sufficient source-package context now remain unresolved with their leading dots
  instead of being guessed as top-level modules. Invalidate stale scanner facts and add a
  multi-package positive/negative regression corpus.
- Restore release-gate portability by isolating symbolic-link test seams from Python's
  process-wide `stat` module, copying the complete `pysfmea` package into focused mutation
  sandboxes while mutating only governed targets through Mutmut 3 mangled identifiers, and
  explicitly publishing hidden Chromium quality evidence from `.ci-report`. Canonicalize
  temporary repository fixtures so macOS `/var` and `/private/var` aliases exercise the same
  security-sensitive path identity used by publication and ingestion code. Move CI evidence
  uploads to the immutable Node.js 24-based `actions/upload-artifact` 7.0.1 revision.
- Add safe, non-executing control-flow pruning for literal `if`/conditional expressions,
  `while False`, constant-true loop `else` clauses and unbreakable tails, empty literal `for`
  loops, guaranteed-nonempty literal `for` loops whose first-iteration body cannot fall through,
  boolean short-circuiting, literal comparisons, bounded exact-built-in numeric/sequence
  expressions, exact built-in indexing and slicing, operand-valued boolean expressions, and
  statically selected conditional-expression values. Safely construct bounded tuple/list/set/dict
  displays with deterministic literal unpacking, dictionary union, and exact set algebra,
  plus a non-mutating exact-built-in method allowlist for ASCII string/bytes normalization and
  predicates, sequence queries, set relations, and dictionary lookup;
  resolved `TYPE_CHECKING` guards, literal/singleton/OR/sequence/mapping/capture `match` patterns
  and statically decidable case guards, direct terminal statements, statically selected terminal
  blocks, exhaustive terminal `if/else` or `match` constructs, impossible `try` `else` clauses,
  terminal `finally` blocks, and `try` statements whose normal and handler paths all exit.
  Provably unreachable
  calls, raises, sequences, and downstream failure paths are excluded while unsupported paths
  remain conservative. Publish every decision in count-reconciled
  `pysfmea-static-control-flow-model-2`, validate exact source/component backlinks and evaluator
  limits, preserve it through fact-cache format 17, and expose it through the evidence fabric, canonical diagram, and
  HTML report. Handler outcomes use the same predicate, pattern, empty-loop, and constant-loop
  evaluators, avoiding impossible loop-`else` rethrow, return, or translation dispositions. Reject call-shaped expressions
  from literal evaluation—including `set()` accepted by `ast.literal_eval`—because repository code
  can shadow the apparent constructor.
  Feed nonempty literal iteration into handler and `finally` outcome merging so a guaranteed first
  iteration with only explicit terminal outcomes excludes an unreachable loop `else`; owned
  `break`/`continue`, dynamic iterables, and bodies that may fall through remain conservative.
  Constant folding admits only exact built-in numeric operations, bounded tuple/list/string/byte
  concatenation or repetition, safe literal indexing/slicing, Python-compatible `and`/`or` value
  selection, statically decidable conditional expressions, bounded collection unpacking, dictionary
  union, and set algebra. It fails closed at depth 20, 4,096 integer bits or collection/sequence
  items, exponent 64, and shift 1,024; exact built-in method results share the same ceilings.
  Dynamic receivers or arguments, non-ASCII string method data, starred calls, other or mutating
  methods, exceptional operations, oversized results, and unsupported types retain all alternatives. Publish these
  mandatory limits in format 2 rather than silently
  redefining static-control-flow format 1.
- Deepen typed exception analysis with Python-compatible nearest-`try` and first-handler
  selection, exact built-in inheritance (including the `Exception`/`BaseException` boundary),
  statically declared project exception inheritance, and explicit indeterminate outcomes for
  dynamic or ambiguous types. Propagation edges now distinguish suppression, continuation,
  control-flow exit, rethrow, explicit raise, translation, mixed outcomes, and unresolved handler
  matches; retain match provenance and complete disposition accounting; exclude raises inside
  nested callable declarations from enclosing-handler behavior; and project exact exception
  exposure into components, findings, generated test guidance, cross-reference relationships,
  diagrams, reports, validation, and the fact cache. Add bounded terminal-`finally` records and
  model bare/literal top-level `return`, `break`, and `continue` as suppression and top-level
  explicit `raise` as replacement. Outer terminal finalizers take precedence over inner ones;
  bare terminal `raise` preserves the original exception, evaluated returns and competing
  conditional terminal paths remain conservative, and every edge retains the governing finalizer ID, terminal kind, and
  replacement type. Emit finding exception exposure sparsely so
  unaffected findings do not consume the governed analysis-node budget. Correct dependency finding
  provenance chains to use the resolved content-addressed artifact path rather than a synthetic
  aggregate display label, keeping exact cross-reference verification valid on real repositories.
  Extend the bounded branch-outcome engine to `finally` blocks: sequential `if`, `match`, loop,
  `with`, and nested-`try` alternatives now publish complete outcomes, certainty, and terminal
  basis. Uniform bare/literal returns and control exits suppress the original exception, uniform
  explicit raises replace it, and uniform bare raises preserve it; evaluated returns and mixed,
  fallthrough, truncated, or indeterminate paths remain conservative. Validate the complete
  finalizer projection, expose terminal basis in the evidence fabric, and invalidate stale fact
  caches through format 12. Publish the strengthened programmatic contract as
  `pysfmea-exception-propagation-3` rather than silently redefining format 2.
- Replace candidate-only handler action classification with a bounded branch-aware outcome model.
  Sequential reachability and `if`/`match`/loop/`with`/nested-`try` branch merging now distinguish
  uniform, conditional, and indeterminate handler outcomes; conditional rethrow, translation,
  explicit replacement, and control exit receive separate dispositions. `raise exc` is recognized
  as an original-exception rethrow when `exc` is the active catch binding, while explicit new
  exceptions no longer falsely propagate the original. Handler outcomes and certainty are retained
  in cache, validation, cross-reference entities, report metrics, and tamper-checked propagation
  edges. Statements after a direct terminal exit within analyzed handler/control blocks are
  excluded as syntactically unreachable. Publish the strengthened contract as
  `pysfmea-exception-propagation-2` rather than silently changing the meaning of format 1.
- Add a deterministic `pysfmea-cross-reference-index-1` evidence fabric and
  `sfmea cross-reference` JSON/Markdown exporter. It fuses native AST, Graphify static, and
  imported runtime component relations; projects finding-to-guidance/requirement/hazard/SFTA/
  verification/evidence chains; and turns cross-source discrepancies into bounded, prioritized
  review leads. Finding chains also cross-reference bounded caller cascades, timing budgets, retry
  amplification, transaction/effect/resource semantics, and circuit-breaker models. A canonical
  evidence-fabric diagram and dedicated self-contained HTML view expose
  the same digest-bound relationships without treating corroboration as completeness or compliance.
  Add public artifact/verdict schemas, `sfmea cross-reference-verify`, exact-analysis regeneration,
  checksum-manifested review-package inclusion, semantic package verification, and direct report
  navigation between incomplete chains and their governed findings. Aggregate repetitive SFTA
  reconciliation gaps into counted, sampled review leads while retaining the complete source
  register, and make traceability link ordering cross-process deterministic so fresh-process
  package verification cannot disagree with same-process publication.
  Extend the fabric with one verified semantic-exposure profile per scanned component. Exact
  records from data/alias flow, concurrency, exception propagation, state machines,
  authorization scope, contracts, deployment topology, shared fate, and architecture hierarchy
  now join each finding chain and canonical diagram. Independently derived model intersections
  become bounded aggregate review leads (for example authorization context crossing data flow or
  concurrency touching state transitions), with standalone referential and summary verification.
  Add one verification-readiness profile per finding that cross-references textual test candidates,
  coverage observations, registered implementations, executions, independent reviews, evidence,
  owners, reviewers, lifecycle state, and deterministic next action. Accepted-finding gaps become
  prioritized aggregate leads, while candidate tests and coverage remain explicitly below
  verification-evidence authority. Schemas, exact verification, canonical diagrams, Markdown,
  CLI summaries, review packages, and the self-contained HTML report expose the same contract.
  Cross-reference deterministic quality-gate diagnostics, source-change classification,
  revalidation, finding disposition, and assurance lifecycle through one verified review-governance
  profile per finding. Analysis-scope diagnostics remain separately typed and counted; actionable
  non-review diagnostics become bounded aggregate leads. Stable occurrence-aware identities retain
  exact duplicate diagnostics without conflation, while standalone verification recomputes identity,
  scope partitioning, severity counts, state, next action, and chain copies without treating a
  workflow diagnostic as proof of a software failure.
  Bind the exact scan manifest and adapter ledger into the same fabric, then connect each adapter
  run to every normalized entity it claims to contribute. Add repository-inventory, artifact,
  excluded-region, dependency, contract, and resolved-configuration entities; trace components and
  findings to content-addressed repository or run-manifest inputs; and expose opaque or unaccounted source coverage as bounded
  review leads. Standalone verification reconciles the complete provenance graph and finding-chain
  copies without promoting tool attribution, indexed files, or opaque files to semantic evidence.
  Pre-index adapter-to-finding relations during verification, replacing a quadratic per-chain graph
  scan with a linear pass for large repositories.
  Integrate governed machine suggestions, generated summaries, and the deterministic suggestion
  synthesis comparator into the fabric. Typed links now retain component scope, allowlisted
  evidence, proposed citations, human materialization, summary scope/staleness, and bounded lexical
  duplicate/contradiction/divergence leads. Finding chains, canonical diagrams, Markdown, CLI, and
  self-contained HTML expose the same non-authoritative provenance; standalone verification rejects
  relationship/profile/accounting drift. Grouping comparator candidates by component removes its
  prior quadratic scan across unrelated components.
  Add governed system-context and lifecycle-history projections to the fabric. Resolved context
  fields and values now cross-reference explicit finding mode, state, safe-state, degraded, and
  recovery claims through declared-field and exact normalized matches; unmatched, unresolved, and
  uncataloged claims remain bounded review leads. Ordered analysis and finding-review history
  becomes digest-bound lifecycle-event entities with exact typed subject references and explicitly
  unauthenticated actor labels. Schemas, standalone verification, finding chains, diagrams, CLI,
  Markdown, and the self-contained HTML report expose and reconcile the same records.
  Promote methodology, versioned guidance documents, and exact citation locators to first-class
  digest-bound entities. The complete fabric now carries independently verifiable document →
  citation → finding lineage instead of leaving the document identifier as opaque citation
  metadata; unresolved source identities become review leads, and report/diagram/CLI/schema
  projections expose the same authority-preserving chain.
  Add a self-auditing analysis-output projection ledger. Every top-level scanner section now has a
  digest-bound entity and declared entity-kind/relationship-channel surface, with separate
  semantic, provenance-only, empty, registered-without-projection, and unmapped states. Unknown or
  disconnected outputs become prioritized leads; standalone verification reconciles projection
  identity sets and exact verification binds source digests. Markdown, CLI, schema, diagram, and
  self-contained HTML views expose the same coverage contract.
  Separate declared and material projection percentages, and ignore structural deployment
  placement shells whose node lists are empty, so sparse models produce actionable gaps rather
  than false missing-projection alerts.
  Extend that ledger to every bounded projectable nested record. Stable record entities retain the
  exact section/path/locator digest, conservative identity tokens, complete semantic target-set
  digests, and bounded graph witnesses; standalone verification recomputes every join and exact
  verification regenerates it from the analysis. Unresolved and bound-omitted records become
  high-priority leads with a separate record coverage percentage. Promote all Graphify relations,
  runtime imports/spans/edges, and scanner warnings to first-class cross-reference entities, and
  retain source component/reference identity on resilience effects and retry paths. CLI, Markdown,
  schemas, diagrams, and the self-contained HTML report expose the same contract. Publish the
  complete JSON fabric in deterministic compact form so large verified repositories retain every
  witness while staying inside the 200 MB ingestion envelope.

- Qualify deterministic generated semantics, not detection keys alone. Golden corpora can now bind
  exact failure modes, triggers, causes, local effects, recommended actions, assurance methods,
  citations, direct citations, adapter provenance, confidence, and screening priority to an exact
  source/component/rule identity. Evaluation reports case- and claim-level accuracy, missing cases,
  field-specific mismatches, and per-field/per-rule metrics; the CLI fails visibly on drift.
  Campaigns expose semantic output as a required feature with global and per-repository thresholds,
  public schemas, and a dedicated self-contained report view. The maintained corpus gates ten
  representative semantic cases and 78 exact claims while explicitly excluding reviewer-owned
  system effects, ratings, approval, risk acceptance, runtime proof, and certification.
- Make detected-control qualification false-positive-aware. Golden corpora can declare a bounded
  exhaustive `control_scope` independently of finding/call scopes; positive `control_cases` must
  fall inside it, while all other scoped components form the explicit negative population.
  Evaluation, CLI output, campaign aggregation, schemas, and the self-contained qualification
  report disclose evaluated/positive/negative component counts and fail on missing or unexpected
  controls. Campaigns can require a minimum negative population in every control-bearing
  repository, preventing positive-only cohorts from receiving eligibility. The maintained corpus
  now gates four breaker-role records against three semantic
  near-misses, and breaker recognition no longer treats generic electrical-circuit terminology or
  state assignment alone as admission-control evidence.
- Expand the strict MyPy release gate from a selected 28-module ratchet to the complete
  `pysfmea` package plus release-gate scripts. Normalize the assurance obligation/register
  interfaces, eliminate cross-scope inference ambiguity in the scanner and validators, type
  bounded XML execution evidence with maintained `defusedxml` stubs, and require all 61 package
  modules to remain strict-clean.
- Add governed, multi-repository scanner qualification campaigns. Closed manifests bind retained
  analyses, independently labeled corpora, and exact evaluation results; the builder regenerates
  every evaluation before aggregating micro finding, call-resolution, and control-detection
  metrics by rule, framework, and domain. Public manifest/result/verdict schemas and
  `qualification-build`/`qualification-verify` commands make incomplete evidence, tampering,
  path escape, and missing feature populations fail visibly without claiming certification.
  `program-init` can consume a completely reconciled campaign directly, projecting exact
  program-relative evaluation artifacts, corpus/result digests, counts, and independent-review
  identities into validation cohorts without manual transcription. Add a responsive,
  keyboard-navigable, print-aware self-contained qualification report with blocker-first gates,
  repository/framework/domain/rule views, exact artifact provenance, embedded complete evidence,
  staged publication verification, and a public standalone/exact-result verifier schema.
- Add `scan --read-only` for immutable-checkout operation. It requires analysis publication outside
  the scanned repository, disables implicit in-repository fact-cache writes, permits an explicit
  external cache, records the mutation policy, and is regression-tested against an exact target
  filesystem snapshot.
- Replace duplicated report-package schema allowlists with one dependency-free public schema
  filename registry, preventing packaged-schema drift across catalog generation and review-package
  verification.
- Give the Chromium report gate supported default limits of 50 MiB, 10 seconds, and 256 MiB of
  measured JavaScript heap, and retain the effective budgets and their authority in its receipt.
  Browser/UI contract failures now publish a failed machine-readable receipt with a bounded error
  summary instead of terminating with a raw Playwright traceback. Reports now render the requested
  section first, materialize each remaining section once on demand, preserve deep-link behavior,
  and prepare all sections for Print/PDF. Format 4 adds canonical receipt integrity, exact report
  byte/digest bindings, initial readiness and boot timing, and reconciled per-section render state
  and duration. Public receipt/verdict schemas and
  `sfmea report-browser-verify` provide bounded standalone semantic and exact-report verification.
- Bind synthesis-apply receipts to the exact final governed-analysis bytes and publish the staged
  receipt/result pair through a coordinated rollback-capable replacement primitive. This protects
  ordinary publication failures while explicitly retaining the host/process crash window as a
  verification requirement rather than claiming unsupported multi-file filesystem atomicity. Add
  optional non-overwriting exact source snapshots plus public receipt-verification schema and
  `synthesis-apply-verify` integrity-only/complete modes that reconcile source, sealed workspace,
  result, applied/deferred accounting, and resulting suggestion statuses.
- Publish public JSON Schema contracts for accessibility qualification, human-controlled
  synthesis, exact-commit pull-request analysis, and the process plugin SDK. Add standalone
  `pr-verify` and `plugin-run-verify` commands with artifact, regeneration, report, analysis,
  manifest, and process-boundary checks. Synthesis apply now emits a content-addressed receipt
  bound to the source analysis, sealed workspace, and resulting analysis.
- Complete the remaining product-maturity backlog. Reports now support baseline-scoped saved views
  and bounded share links, and browser qualification exercises persistence and restoration. Add a
  WCAG-mapped automated ruleset plus exact-report manual keyboard, zoom/reflow, display-preference,
  and NVDA/JAWS/VoiceOver evidence. Add deterministic LLM duplicate/contradiction/divergence leads
  and a sealed side-by-side human synthesis workflow. Add safe exact-commit `sfmea pr-analyze`
  orchestration. Publish the semantic-versioned `pysfmea.sdk` 1.0 process protocol, compatibility
  validation, bounded host, isolation disclosure, CLI, and reference plugin. E071, E075, E080,
  E081, E084, and E087 advance to implemented; none is claimed independently validated.
- Add a maintained, versioned `pysfmea-service-threat-model-1` with stable threat/residual-risk
  IDs, mapped controls, owners, treatments, review triggers, deployment minimums, and explicit
  acceptance authorities. `sfmea threat-model` exports content-addressed JSON or Markdown. E095
  advances to implemented without claiming a penetration test, formal proof, deployment
  authorization, enterprise identity integration, or automatic risk acceptance.
- Publish a supported Ubuntu/Windows/macOS × CPython 3.11-3.14 matrix with exact JUnit-bound,
  content-addressed platform receipts. Add a retained scanner performance job with runtime and
  traced-Python-allocation budgets, plus per-view Chromium JavaScript-heap measurement and an
  enforced report heap budget. E091 and E093 advance to implemented without claiming untested
  deployment compatibility or total native/GPU/OS memory coverage.
- Extend `pysfmea-golden-corpus-1` with optional detected-control cases and corpus-governance
  metadata. Evaluation now reports per-rule precision/recall, empirical precision by confidence
  label, monotonic-label diagnostics, and control recall/precision by kind. Add fail-closed
  `sfmea evaluate-compare` for same-corpus, named, independently approved before/after rule-change
  evidence with explicit recall-regression gates. E008-E010 advance to implemented without
  applying rule edits, authenticating independence claims, approving releases, or proving runtime
  control effectiveness.
- Add provenance-bearing `pysfmea-deployment-topology-1`, automatic
  `pysfmea-shared-fate-analysis-1`, and deterministic
  `pysfmea-architecture-hierarchy-1`. Supported repository deployment declarations now produce
  bounded nodes/edges and review-required component placements; multi-component shared resources
  become common-cause leads; and supplied trace links aggregate through nested subsystem and source
  paths. Semantic validation, component backlinks, workbench observations, and three offline HTML
  diagrams advance E033, E034, and E064 to implemented without claiming observed deployment,
  correlated-failure probability, independence, or architecture approval.
- Expand governed contract ingestion and add `pysfmea-contract-semantics-1` for OpenAPI, AsyncAPI,
  protobuf, GraphQL, JSON Schema, and Avro. Request/response/error/message/type shapes reconcile
  with Python routes, conflicting definitions are content-addressed, and declared-version pairs
  expose bounded breaking-change candidates. E031-E032 advance to implemented without claiming
  runtime serialization, generated-client behavior, deployed reachability, or version-policy proof.
- Add `pysfmea-authorization-scope-flow-1`, projecting identity, tenant, role/permission,
  scope/claim, and credential dimensions onto exact interprocedural argument edges and correlating
  observed decorator/call guards. Semantic validation reconciles counts and component indexes;
  E029 advances to implemented without claiming guard dominance, authorization correctness, tenant
  isolation, least privilege, or token validity.
- Add `pysfmea-resilience-semantics-1`, integrating bounded transaction lifecycle and consistency
  risks, fixed-point side-effect/idempotency summaries, literal timing-budget constraints, nested
  retry amplification, class-scoped breaker semantics, and explicit/unresolved resource growth.
  Exact links, counts, paths, and component indexes are validated; E022-E027 advance to implemented
  without claiming runtime atomicity, exactly-once behavior, latency compliance, breaker
  effectiveness, or symbolic resource-complexity proof.
- Add `pysfmea-state-machine-model-1`, connecting conventional state/status/phase/mode assignments
  to stable target-state nodes and lexical `if`/`while` guards with exact component indexes and
  semantic validation. E021 advances to implemented without claiming formal reachability,
  exclusivity, liveness, indirect-mutation coverage, or completeness.
- Add `pysfmea-exception-propagation-1`: bounded typed raise and lexical-handler records retain
  chaining, rethrow, translation, suppression/control-flow exit, and logging candidates, while a
  fixed point projects caught versus escaping types across resolved internal calls. Exact counts,
  omissions, and component indexes are validated; E020 advances to implemented without claiming
  complete inheritance, dynamic alias, runtime-reachability, ExceptionGroup, or path proof.
- Add `pysfmea-concurrency-model-1`, a bounded component-linked inventory of task spawn,
  join/wait, cancellation/timeout, synchronization, and awaited-completion operations with lexical,
  await-before-next-operation, and conservative spawn-to-later-join relations. Counts and indexes
  reconcile under semantic validation; E019 advances to implemented without claiming scheduler,
  task-identity, happens-before, deadlock, or race proof.
- Add bounded order-aware local alias and object-flow facts, including expanded origins,
  producer-call provenance, attribute/container writes, component binding, and typed receiver alias
  resolution. The analysis reconciles all embedded/omitted records and validates relationships;
  E017 advances to implemented without claiming path-sensitive heap or taint soundness.
- Add bounded interprocedural value-flow analysis for internal Python calls. Caller expressions
  are bound to callee parameters, return/yield expressions are linked back to assignment,
  argument, attribute, container, and return contexts, component records carry edge indexes, and
  a canonical `data_flow` diagram is available in JSON and the self-contained HTML report. Fact
  cache format 2 prevents reuse of older incomplete facts. E016 advances to implemented while the
  model remains explicitly path-insensitive and independently unvalidated.
- Add human-adjudicated finding consolidation to the exact-bound activation workflow. Complete
  multi-finding candidates can be consolidated, retained separately, or deferred for information;
  application creates a canonical review group without removing findings or propagating member
  dispositions, evidence conclusions, citations, or risk acceptance. Rehashed candidate changes
  fail exact regeneration, the HTML report exposes applied groups, enhancement workbench format 7
  describes the executable workflow, and E012 advances to implemented while remaining
  independently unvalidated.
- Add `sfmea evidence-onboard`, a single non-executing evidence-ingestion workflow for discovered
  or explicit coverage.py JSON, repeated runtime traces, and obligation-bound external execution
  manifests. Plan mode runs the complete bounded semantic import path on an isolated copy; apply
  mode publishes a regenerated-manifest analysis, an exactly verified assurance queue, and a
  source/result-bound receipt. New public receipt/verdict schemas ship in review packages, and
  E001 advances from partial to implemented without claiming evidence sufficiency or independent
  validation.
- Advance executable assurance scaffolds to format 7 with deterministic, bounded Hypothesis
  strategies derived from retained signatures; positive and negative producer/consumer contract
  cases tied to exact candidate contract digests; explicit unresolved-binding cases; and
  fail-visible project adapters that require stimulus proof, evidence references, and every
  oracle/acceptance-criterion result. A separate synthesized-design digest is exactly regenerated
  during verification, six starting files are content-addressed and lifecycle protected, and new
  public scaffold/verdict schemas ship in review packages. Generated tests remain unreviewed
  starting points rather than evidence. E046 and E050 therefore advance from planned to
  implemented while remaining unvalidated.
- Added a governed SFTA authoring workflow with one entry per hazard, explicit
  retain/defer/replace decisions, named approvals, semantic gate/reference/cycle validation,
  exact-analysis sealing and verification, transactional application receipts, four public JSON
  Schemas, report history, documentation, CLI coverage, and CI artifacts.
- Added bounded qualitative minimal cut-set calculation for exact definition-digest-approved SFTA
  trees. AND/OR/VOTE/INHIBIT expansion performs superset absorption, retains undeveloped/external/
  conditioning flags, invalidates approval after tree edits, and returns no partial result when
  logic or count/width/operation bounds are exceeded. No probability or independence is inferred.
- Added a governed configuration-authoring workflow that converts named guidance,
  architecture, and interface reviews into a new validated sibling `sfmea.toml`. Drafts and
  sealed inputs bind to both exact analysis state and exact configuration content; application
  preserves the source, relative paths, and reviewer authority boundaries. Project citation
  mappings and stable interface dispositions now survive rescans without becoming independent
  approval or runtime evidence.

### Outcome-driven enhancement closure

- Advance the enhancement workbench to format 6 with exhaustive, disjoint `planned`, `partial`,
  `implemented`, and `validated` product maturity for E001-E095. Each outcome now carries its
  implementation/test evidence, limitation, maturity basis, next action, and authority boundary;
  standalone verification rejects rehashed semantic overclaims. Projection presence no longer
  establishes implementation, and internal regression tests cannot establish independent
  validation.
- Add the closed-loop `activate-init`, `activate-decide`, `activate-verify`, and `activate-apply`
  and `activate-assign` workflow. It provides bounded static test attribution, one integrity-bound campaign for finding,
  calibration, guidance, SFTA, architecture, and interface work, named/rationalized decision
  recording, exact-state refusal, transactional analysis publication, and a public apply receipt.
- Add exact-workspace-bound bulk activation export/import with duplicate, subject, decision, date,
  and staleness validation plus a content-addressed transactional import receipt.
- Add public schemas for the activation workspace, verifier verdict, and apply receipt, and expose
  retained activation progress plus the complete E001-E095 outcome register in the HTML report.
- Advance the enhancement workbench to format 5 with an exact `E001`-`E095` product-outcome
  register, measurable repository scorecard, and explicit analysis-fidelity, sequence/SFTA,
  assurance-automation, architecture/interface, evidence, reporting, LLM, and qualification
  projections. Product capability is kept separate from project evidence and named approval.
- Add `sfmea enhance-evidence-preflight`, a bounded read-only repository inspection that validates
  coverage JSON, discovers tests/configuration/contracts, reports runtime/test attribution state,
  and emits inert remediation argv without executing target code.
- Add `--profile engineering|compact|management` to HTML reporting. Compact and management modes
  enforce deterministic 500- and 250-record projections while preserving analysis binding and
  explicit truncation accounting.

### Scalable governed discovery and reporting

- Compose imported FastAPI/Flask routers registered through bounded literal tables, tuple
  unpacking, static branches, and loops without importing or executing repository code. Retain
  registration source, confidence, local prefix, mount prefix, and effective route provenance.
- Resolve conventional TypeScript/JavaScript request wrappers and named base-path constants across
  files, keep web-test endpoint literals as test evidence rather than deployed-client candidates,
  and reconcile HTTP methods once per path so compatible routes do not produce false mismatch
  leads.
- Add human-disposition calibration by rule, proximity-based architecture mapping proposals that
  require confirmation, and the complete non-certifying diagnostic scorecard and action list to
  the self-contained HTML report.
- Resolve fact-cache output paths against the scanned repository, preventing nested
  `.artifacts/.artifacts` paths when configuration is stored with analysis artifacts.
- Exercise responsive report navigation through the actual mobile menu in the Chromium quality
  gate, explicitly scroll long desktop navigation before activation, and reject duplicate IDs,
  unnamed buttons, unlabeled controls, missing image alternatives, or missing core landmarks.
- Add `sfmea enhance`, a public schema-backed enhancement workbench covering all 56 backlog items
  through evidence-acquisition recipes, root-cause clusters, representative-review safeguards,
  prioritized assurance portfolios, mapping/interface queues, static system-surface models, and a
  bounded self-contained HTML workspace.
- Advance the enhancement workbench to format 2 with an append-only 76-item real-repository
  hardening register, measurable acceptance criteria, exact artifact-freshness bindings,
  high-volume precision-risk projections, and live readiness targets. Empty rule-review samples
  now report null acceptance/rejection rates instead of misleading 100 percent values.
- Advance the enhancement workbench to format 3 with an append-only 82-item post-hardening
  register, bounded exact-regeneration verification, separate freshness/completeness/sufficiency
  health, review-only evidence-scope patches, deterministic calibration campaigns, metric
  provenance, report-scale planning, governed targets, and source/test-backed product attestations.
- Advance the workbench to format 4 with an append-only 102-item real-run resolution register,
  assignable review and calibration campaigns, guided evidence onboarding, precision and
  specialization plans, architecture/interface activation, temporal-resilience campaigns,
  guidance-closure queues, phase performance ratchets, report-delivery modes, and explicit LLM
  and independent-qualification governance.
- Discover conventional imported Axios instances, base symbols, interceptors, methods, and source
  lines so cross-file client/server reconciliation handles another common production pattern.

- Separate semantic exclusions from explicit evidence-only test and JS/TS boundary scopes. The
  scanner can now attribute excluded test sources and reconcile excluded frontend boundaries
  without generating components from either scope; diagnostics report likely scope conflicts and
  machine-readable configuration suggestions.
- Replace repeated SFTA bottom-up validation messages with one count-and-sample diagnostic backed
  by the complete reconciliation register. Add warning/per-rule budgets, family batch estimates,
  cross-priority queue reservations, and a non-certifying domain qualification scorecard.
- Use a single AST-grounded test-symbol index instead of repeated textual searches, summarize
  assertion/negative/parameterized/property/timing/concurrency/fault-injection signals, and discover
  conventional root coverage JSON with explicit selection provenance.
- Compose literal Python router prefixes and same-file web-client base URLs, recover bounded fetch
  methods, emit method/path compatibility review leads, and generate navigable cross-stack static
  sequence candidates in JSON and HTML.
- Add a bounded, integrity-checked, atomically published persistent Python fact cache with exact
  source/runtime/version invalidation, truthful run-manifest reuse metrics, and cold/warm benchmark
  evidence. Whole-repository call resolution and finding generation remain freshly recomputed.
- Add deterministic bounded `.json.gz` analysis publication/loading and bounded per-component and
  total human review-queue projections while preserving the complete candidate register.
- Index JavaScript and TypeScript imports, exports, external packages, endpoint templates, and base
  URLs as confidence-labeled language-boundary evidence instead of treating every frontend file as
  opaque.
- Add project-specific external-call, receiver, and method hints without promoting heuristic
  candidates to resolved interfaces.
- Require explicit named applicability decisions for selected guidance profiles, preserve those
  decisions through canonical persistence, validate missing decisions, and expose their state in
  the self-contained report.
- Add a Chromium CI gate for the generated self-contained report and expose language-boundary,
  guidance-applicability, and cache provenance metrics in the report.

## 0.59.0 - 2026-08-05

### Executable fault injection and quality ratchets

- Add an opt-in, schema-backed transactional program-HTML publication receipt for CI. It records
  publication phase and prior-destination preservation, separates verified-but-not-ready from
  publication failure through exit codes, sanitizes failure details, and blocks source-program
  overwrite. Program-report verdicts now expose the SHA-256 of the exact received HTML bytes for
  downstream archival and review binding, and `program-report-verify --expect-sha256` can enforce
  that approved digest after transport or restoration without conflating an unavailable file with
  a completed mismatch check. `program-report-verify --output` now publishes durable verdict JSON
  atomically, avoids shell-redirection encoding/truncation hazards, protects report/program
  sources, and detects concurrent receipt replacement. Private receipt staging is also strictly
  parsed and canonically matched to the exact requested verdict before identity/size/byte rechecks
  and replacement. A closed runtime verdict contract now rejects contradictory caller-supplied
  checks, bindings, status, validity, and publication state before staging.

- Add three governed built-in fault-injection plugins for dependency exceptions/timeouts,
  malformed or degraded return values, and controlled failure/recovery sequences.
- Generate content-bound, non-executable starter plans from assurance obligations; require
  explicit callable/patch/fault/outcome bindings and reject false-pass paths where the injected
  dependency was never exercised.
- Add CLI discovery, plan export, and exact obligation-binding verification while retaining the
  existing approved-sandbox and independent evidence-review boundary.
- Add validated plan completion and deterministic pytest-bridge commands; ready plans now use a
  closed contract, mandatory exact provenance binding, content integrity, denied networking,
  disabled scanner execution, and an approved-sandbox execution marker.
- Support dotted synchronous and asynchronous subjects, controlled failure/recovery sequences,
  per-invocation elapsed-time evidence, and optional minimum/maximum timing oracles.
- Add branch-coverage, strict incremental typing, Hypothesis property tests, focused mutation,
  critical-module coverage ratchets, Bandit source scanning, dependency-vulnerability gates,
  CycloneDX dependency SBOM evidence, and automated dependency update checks to CI.
- Replace untrusted JUnit parsing with `defusedxml` and eliminate temporarily world-writable
  evidence staging by running the container with the invoking unprivileged host identity where
  bind-mount ownership is meaningful.
- Extract stable typed interfaces, deterministic assurance-planning policy, and pure sandbox
  command policy from the largest orchestration modules.
- Preserve structured static call sites with lexical control context and await state; label
  ambiguous internal resolution and unresolved external-interface candidates by confidence in
  sequence and canonical interface projections.
- Add conservative annotation-, import-, and constructor-assignment-aware receiver resolution,
  retain its provenance, preserve nested Python call evaluation order, and exercise a real
  internal cascade in the golden corpus.
- Record valid, unavailable, and invalid runtime timing explicitly on imported spans and edges,
  with a 90% runtime-module coverage ratchet and focused mutation targets.
- Reconcile bounded static and observed sequence relations in JSON, Mermaid, canonical diagrams,
  and HTML while explicitly distinguishing corroboration from reachability or causal proof.
- Separate direct guidance coverage from supporting/contextual citation coverage in traceability
  JSON and HTML, including each finding's strongest relationship and rules lacking direct support.
- Add the current FAA AC 450.141-1A Appendix B.1.2/Table B-1 taxonomy locator and direct
  commercial-space mappings for functional, calculation, data, interface, logic, and timing
  SFMEA screening; retain AC 20-115D lifecycle mappings as contextual.
- Add per-mapping governance records and digests, locator-summary digests, integrity metrics, and
  an explicit distinction between maintainer curation and independent regulatory approval.
- Expand the checked-in golden repository to 75 source-aware cases across framework-style routes,
  tasks, async behavior, data models, control flow, typed receivers, nested-call order, and an
  internal cascade while retaining the independent-validation
  limitation.
- Add eight exhaustive call-resolution labels with overall and per-provenance precision/recall;
  exact line/order, await-state, and control-context identity prevents repeated call sites from
  collapsing, and missing or unexpected labeled calls now fail `sfmea evaluate`.
- Add closed runtime instrumentation manifests and expected-versus-observed coverage for scenario,
  producer, clock, sampling, dropped-span, expected-component, and expected parent-child
  relationship declarations.
- Add source-revision-bound organizational mapping reviews with content digests, distinct named
  producer/reviewer identities, approval/rejection decisions, authority, expiry, rationale, and a
  deterministic effective-approval audit against the persisted analysis timestamp.
- Add bounded utilities for scanner performance evidence, clean-result validation-cohort records,
  separately gated failure-mode/call-resolution cohort metrics, and content-addressed independently
  labeled LLM quality metrics.
- Verify scan-manifest and resolved-input digests during normal validation, cross-bind every
  reproducibility claim to the governed analysis, retain explicit portable-root handling, and
  expose the verdict in HTML. Rehashed false input, baseline, timestamp, guidance, adapter, or
  static-execution claims now remain invalid outside package verification too. The shared
  integrity module is enforced by strict typing and a 95% branch-coverage ratchet.
- Grant organizational mapping-review approval credit only when the persisted scan timestamp is
  protected by valid manifest content and timestamp bindings.
- Preserve expected-side and actual-side match counts, verifier version, and the canonical
  evaluation-result digest in converted validation cohorts; admit imperfect but structurally
  reconciled measurements, support explicit
  count-backed-cohort policy, and gate/report micro-averaged failure-mode and call-resolution
  recall/precision alongside legacy-compatible macro metrics.
- Bind converted cohorts to the retained evaluation JSON by exact byte digest and program-relative
  artifact reference. Program verification consumes that artifact through bounded,
  identity-stable strict JSON ingestion and cross-checks its canonical digest, corpus, verifier,
  counts, rates, missing/unexpected cases, and call-resolution projection before granting credit.
- Preserve LLM decision and claim counts, bind the retained labeled corpus by exact bytes, and
  replay its closed sample contract during program verification. Unsupported-claim aggregation now
  uses total claims rather than sample-count weighting, with explicit legacy aggregation status.
- Add `pysfmea-llm-quality-corpus-2` with an exact provider/model/prompt subject. Converter and
  program verification reject subject substitution; version-1 corpora remain replayable but cannot
  satisfy the new default subject-binding gate.
- Reject duplicate validation and LLM corpus declarations even when they use different record IDs.
  Program metrics, repository coverage, cases, samples, and claims now credit each validation
  corpus digest once and each replayed LLM semantic fingerprint once. LLM fingerprints ignore
  descriptive metadata, byte formatting, and sample order while retaining subject and decisions;
  verdicts report declared, credited, duplicate, and fingerprinted evidence counts.
- Add a compact visual guide with end-to-end, discovery, cascade, finding-lifecycle,
  evidence-credit, and multi-repository diagrams plus review and output matrices.
- Make system-assurance HTML reports independently inspectable through embedded exact-verdict,
  payload, program, and whole-document digests; add bounded standalone verification and optional
  exact path-portable program/verdict regeneration, a CLI command, a public verdict schema, and a
  program-module branch-coverage ratchet.
- Verify program HTML on a private stage before publication, recheck its regular-file identity and
  rendered digest after verification, and preserve prior output across verifier, staged-mutation,
  destination-race, and replacement failures. Place the shared publisher under strict typing and
  an 85% branch-coverage ratchet.
- Close the embedded program-verdict contract through nested record/type/bound checks, reconcile
  finding levels with declared counts and validity, and prevent a different internally consistent
  verdict from satisfying staged publication.
- Close the remaining nested program-verdict projections: require the exact producer check set and
  exact summary, relationship, validation, and LLM fields; reconcile repository/relationship/
  evidence totals, temporal/resilience configuration, cohort and artifact credit, LLM aggregation
  and claim totals; expose those shapes in the public schema; and retain a separate minimal closed
  form for safe early input rejections.
- Enforce that contract uniformly before direct Markdown, JSON, and HTML rendering or publication;
  semantically verify private JSON stages, exact-byte verify Markdown stages, preserve prior
  destinations on rejection, and give derived verdicts a projection-scaled node budget without
  widening the assurance-program input boundary.
- Reconcile relationship claims with projected evidence: derive repository-binding success from
  exact totals, bound trusted credit by completed evidence, require supported timing and recovery
  to carry linked within-deadline measurements, require timing violations to show an overrun, and
  prevent passing relationship checks from masking invalid endpoints or violated contracts. Add
  equivalent state-specific conditions to the public verdict schema.
- Derive every full program-verdict check from its producer error namespace and bind invalid
  endpoint, deadline-overrun, and circuit-breaker-violation projections to their exact
  relationship-scoped findings. Rebalanced counts and validity can no longer conceal an
  unexplained check failure or move an error between assurance domains.
- Restrict verdict findings to producer-owned namespaces; enforce overrun-to-state implications,
  validation population/metric availability, and exact LLM aggregation/claim-rate reconciliation
  so internally balanced reports cannot relabel or manufacture assurance evidence.
- Make governance approval credit fail closed at the record level and expose declared, validated,
  and credited program-approval totals. Invalid fields, subjects, identities, decisions, or
  timestamps remain findings but cannot satisfy a required role or named approval gate. Required
  roles are bounded identifiers and cannot duplicate after case normalization.
- Require one authoritative program-level decision per normalized role. Duplicate, repeated, or
  mixed decisions become explicit role-scoped conflicts, receive no approval credit, and must
  reconcile exactly between verdict summaries and findings.
- Reject approval credit when the offset-bearing decision timestamp predates creation of the sealed
  assurance program, using deterministic artifact timestamps rather than the verifier host clock.
- Deduplicate external evidence by a content-addressed semantic-claim fingerprint and expose exact
  verified/credited/duplicate totals. Replayed claims cannot inflate relationship support, while
  malformed evidence reference arrays now fail and disqualify credit in the evidence domain.

## 0.58.0 - 2026-08-05

### Governed system assurance programs

- Add `program-init`, `program-seal`, and `program-verify` for content-addressed,
  multi-repository assurance programs bound to exact governed analyses and baselines.
- Validate cross-repository component relationships, deadlines, timeouts, retries, ordering,
  clock semantics, and observed timing evidence without presenting static topology as causality.
- Add provider-neutral external requirements and evidence records with source/content digests,
  artifact hashes, bounded consumption, subject validation, and producer/reviewer independence.
- Aggregate independently reviewed validation cohorts and configurable recall/precision gates;
  separately aggregate model/prompt-specific grounding, citation, unsupported-claim, and sample
  metrics for optional LLM use.
- Enforce named program approval, required roles, known approval subjects, and independent
  evidence review while leaving authentication, authorization, and legal signature to enterprise
  controls.
- Add self-contained searchable HTML, Markdown, and JSON program-verification reports plus public
  JSON Schema contracts. Current review packages now contain 16 schemas and 44 checked artifacts;
  genuine older schema sets remain verifiable.
- Credit timing and resilience only from completed, digest-verified evidence; failed evidence now
  blocks readiness, while unrun and inconclusive records remain visible without claim credit.
- Add explicit circuit-breaker opening, half-open, and bounded-recovery contracts with
  fault-evidence verification and independent timing/resilience states.
- Require repository-qualified finding/hazard references, timezone-qualified program/source/
  approval timestamps, closed nested records, independent validation/LLM producer-reviewer
  identities, distinct program-level approval authorities for every required role, and unresolved
  required-role rejection blocking.
- Add an accessible bounded repository-topology visual, trusted-evidence accounting,
  timing/resilience tables, report navigation, severity filtering, Markdown escaping, and a
  bounded finding envelope.

## 0.57.65 - 2026-08-05

### Consistent safe inventory accounting across outputs

- Use one repository-inventory summary projection for HTML, coverage JSON/Markdown, system
  inventory Markdown, and human/JSON CLI summaries.
- Add repository files, regions, semantic-analysis depth, opaque/unresolved totals, snapshot
  provenance, and `reconciled`/`recomputed`/`unavailable` state to coverage and inventory views.
- Override stale artifact totals in `sfmea summary` with record-derived values while retaining the
  governed analysis unchanged and keeping validation/handoff errors explicit.
- Version-gate regenerated inventory and coverage review views so current packages require the
  richer accounting while genuine pre-0.57.65 packages remain exactly verifiable.
- Add a concise operator workflow covering timestamped artifacts, scan-to-handoff commands,
  repository-accounting states, executable assurance tests, evidence boundaries, and exact
  artifact verification; document GitHub Actions publishing authorization for contributors.

## 0.57.64 - 2026-08-05

### Reconciled inventory reporting and handoff enforcement

- Centralize safe repository-inventory summary derivation and compared-field policy for validation
  and report projection so the two consumption paths cannot drift, including non-empty semantic
  coverage while preserving historical zero-file `null` compatibility.
- Render only record-derived inventory metrics in self-contained HTML reports; inconsistent stored
  summaries are visibly labeled `recomputed`, while structurally unusable records withhold counts
  as `unavailable` instead of displaying untrusted values.
- Preserve exact governed analysis and validation findings while distinguishing a clean
  `reconciled` summary from repaired presentation data inside report integrity.
- Prove workflow handoff remains blocked by inventory-summary validation errors and provide the
  existing validation remediation command.

## 0.57.63 - 2026-08-05

### Repository provenance validation and reporting polish

- Derive repository inventory summaries through one shared implementation and reconcile file,
  region, status, kind, snapshot-source, and opaque/unresolved counts during quality validation.
- Reject missing or unknown snapshot provenance with bounded, actionable validation findings while
  keeping historical analyses loadable for explicit rescan and repair.
- Explain reused, independently captured, and unavailable snapshots directly in the self-contained
  HTML coverage view and document the programmatic inventory compatibility boundary.
- Refresh documentation navigation, release adapter-version checks, guidance/requirements audit
  identity, and the tool's own SFMEA verification record.

## 0.57.62 - 2026-08-05

### Coverage snapshot and repository-provenance unification

- Load optional coverage JSON before repository baseline construction and reuse the exact accepted
  bytes for coverage attribution, settings provenance, immutable run-manifest binding, and
  in-repository inventory hashing.
- Prevent a coverage path replacement after normalization from making component line/branch
  evidence describe different bytes than repository coverage or the baseline identity.
- Preserve semantically partial coverage snapshots as content-addressed repository evidence while
  retaining explicit unsafe-path, malformed-record, and duplicate-path warnings.
- Keep external coverage inputs outside repository artifact accounting while retaining their exact
  byte count and SHA-256 in scan settings and the run manifest.
- Expose `coverage_evidence_snapshot` through inventory entries, summary counts, and the HTML
  provenance visual; upgrade repository discoverer provenance to v6 and coverage.py JSON evidence
  provenance to v2 with replacement, external-boundary, zero-reread, wheel, and compatibility tests.

## 0.57.61 - 2026-08-05

### Unified supporting-evidence snapshots

- Publish accepted dependency-manifest and interface-contract byte snapshots into the scan-local
  repository evidence registry and reuse them for repository inventory size/digest evidence.
- Prevent a dependency or contract path replacement after parsing from making repository coverage
  describe different bytes than the manifest claims, extracted operations/data types, baseline,
  or immutable run manifest.
- Expose `dependency_manifest_snapshot` and `interface_contract_snapshot` provenance through each
  inventory entry, summary counts, and the self-contained HTML snapshot-provenance visualization.
- Preserve all existing dependency/contract per-file, discovery, aggregate, structure, semantic,
  link, containment, and identity limits without adding repository reads.
- Upgrade repository discoverer provenance to v5, dependency inventory to v4, and local contract
  analysis to v3; add replacement-race, zero-reread, provenance, installed-wheel, and historical
  package compatibility regressions.

## 0.57.60 - 2026-08-05

### Run-bound single-snapshot test evidence

- Capture each eligible textual test-evidence file once before baseline construction and reuse the
  same immutable bytes for PEP 263 decoding, component test-reference attribution, and repository
  inventory hashing.
- Record accepted/rejected test-evidence counts, accepted bytes, and a canonical snapshot-set
  SHA-256 in the repository baseline; bind that digest into the immutable run manifest and overall
  source baseline identity.
- Apply configured and hidden/default directory exclusions consistently to test-reference indexing,
  and expose outside-repository, link/non-file, identity-race, file-limit, and aggregate-limit
  rejection as bounded evidence rather than silent omission.
- Add inventory snapshot-source summary counts and a dedicated provenance visualization to the
  self-contained HTML coverage view.
- Upgrade repository-discoverer capability provenance to v4 and add replacement-race, zero-reread,
  exclusion-scope, manifest-binding, visual-report, installed-wheel, and historical-package tests.

## 0.57.59 - 2026-08-05

### Identity-stable repository inventory

- Reuse each accepted Python analysis snapshot for repository-inventory size and digest evidence,
  preventing a later path replacement from making the inventory describe different source bytes
  than the AST findings and source-snapshot baseline.
- Route every other hashed artifact through the shared regular-file, non-link,
  inspected/opened/final identity-stable boundary while preserving the 20 MB per-artifact and
  500 MB aggregate consumption budgets.
- Expose `snapshot_source` on every inventory entry so consumers can distinguish reused analysis
  evidence, independent identity-stable inventory evidence, and unavailable snapshots.
- Retain bounded bytes-consumed accounting on rejected snapshots, make identity races explicit
  unresolved evidence, and add source-replacement, zero-reread, artifact-race, installed-wheel,
  and historical-package compatibility regressions.
- Upgrade repository-discoverer capability provenance to v3.

## 0.57.58 - 2026-08-05

### Single-snapshot Python source analysis

- Route Python source and textual test evidence through the shared exact-byte, regular-file,
  non-link, inspected/opened/final identity-stable ingestion boundary.
- Capture each selected source once and reuse those immutable bytes for PEP 263 decoding, AST
  parsing, included-test indexing, and repository baseline hashing, preventing a concurrent edit
  from binding findings to a different source baseline.
- Record accepted/rejected source counts, total accepted bytes, and a canonical source-snapshot-set
  SHA-256 in the baseline and bind that digest into the immutable run manifest.
- Preserve explicit warnings and digest-bound rejected records when a source cannot be safely read;
  syntax or encoding failures remain distinct from file-identity failures.
- Upgrade AST parser capability provenance to v2 and add exact-read-count, identity-race,
  provenance, encoding, limit, installed-wheel, and historical-package regressions.

## 0.57.57 - 2026-08-05

### Exact-snapshot dependency manifest provenance

- Route pyproject, requirements/constraints include chains, and supported lockfiles through the
  shared exact-byte, regular-file, non-link, inspected/opened/final identity-stable boundary.
- Preserve the existing conservative contract: supported declarations are parsed only where their
  format is explicitly understood, while opaque lockfile formats remain content-addressed evidence
  rather than sources of speculative dependency claims.
- Add explicit `evidence_type`, accepted byte count, and SHA-256 fields to every manifest inventory
  record while retaining the compatible `sha256:` specification representation.
- Bind the richer inventory into the repository baseline, dependency component fingerprint,
  immutable run manifest, and v3 dependency-adapter provenance ledger.
- Add exact-provenance, recursive-include, per-file/aggregate limit, identity-replacement,
  revalidation, and installed-wheel regressions.

## 0.57.56 - 2026-08-05

### Strict custom-diagram provenance and import budgets

- Route custom report diagrams and standalone diagram-bundle verification through the shared
  exact-byte, regular-file, non-link, inspected/opened/final identity-stable JSON boundary.
- Reject duplicate keys, `NaN`/`Infinity`, numeric overflow, malformed UTF-8, and excessive JSON
  structure under explicit 5 MB/100-level/250,000-node per-file limits.
- Bound each report invocation to 50 custom diagram files and 25 MB of accepted source bytes in
  addition to the existing 50-diagram, 2,000-node, and 5,000-edge model limits.
- Attach the exact accepted source byte count and SHA-256 to every imported diagram so the report's
  integrity-protected visual narrative remains attributable to one file snapshot.
- Add ambiguity, numeric-overflow, structure, identity-replacement, file-count, aggregate-byte,
  provenance, and installed-wheel regression coverage.

## 0.57.55 - 2026-08-05

### Identity-stable interface-contract evidence

- Extract a reusable exact-byte bounded file snapshot boundary that rejects links/non-files and
  reconciles inspected, opened, and final file identity before returning accepted bytes.
- Route OpenAPI, JSON Schema, YAML, and protobuf contract evidence through that shared boundary
  before it can create contract components or compatibility failure modes.
- Strictly decode JSON contracts with duplicate-key and non-finite-number rejection plus explicit
  100-level/1,000,000-node limits while retaining malformed contracts as visible, unparsed
  inventory records with deterministic warnings.
- Record the accepted byte count beside each contract SHA-256; the complete contract inventory,
  including this provenance, remains bound into the immutable run manifest.
- Add exact-snapshot, byte-limit, ambiguity, numeric-overflow, structure-exhaustion,
  identity-replacement, and provenance regressions.

## 0.57.54 - 2026-08-05

### Exact-byte coverage evidence provenance

- Route coverage.py JSON through the shared exact-byte, regular-file, non-link,
  inspected/opened/final identity-stable ingestion boundary before line or branch evidence can
  influence a component.
- Reject duplicate object keys, non-finite or overflowed numbers, malformed UTF-8, and excessive
  JSON depth or node count under explicit 100 MB/100-level/2,000,000-node limits.
- Bound file-record traversal to 100,000 entries and path processing to 4,096 characters while
  preserving aggregate warnings for unsafe paths, malformed coordinates, and normalized aliases.
- Record the exact accepted coverage byte count, SHA-256 digest, supplied file count, and accepted
  file count in scan settings, and bind that digest into the immutable run manifest.
- Add adversarial coverage ambiguity, overflow, structure, identity-race, file/path-limit, and
  end-to-end provenance regressions while retaining compatible historical package verification.

## 0.57.53 - 2026-08-05

### Strict guidance and runtime-evidence provenance

- Add an exact-byte governed JSON document result so callers can decode, validate, hash, and retain
  provenance from one inspected/opened/final identity-stable file snapshot without a second read.
- Route organizational guidance packs through a 5 MB/100-level/250,000-node strict boundary before
  source, locator, applicability, or rule-mapping data can influence finding citations.
- Route simple and OTLP runtime traces through a 100 MB/100-level/2,000,000-node strict boundary
  before observed spans, cascade edges, timing fields, history, or summary state are derived.
- Reject duplicate keys, `NaN`/`Infinity`, finite-syntax numeric overflow, links/non-files,
  concurrent replacement, and decoded-structure exhaustion while preserving exact accepted-byte
  provenance hashes and transactional runtime rollback.
- Add adversarial guidance/runtime regressions and a maintained tool-SFMEA runtime-evidence failure
  mode covering incomplete, ambiguous, stale, or hostile observations.

## 0.57.52 - 2026-08-05

### Identity-stable strict signature verification

- Add a reusable strict decoder for already-captured JSON bytes, giving ZIP members and other
  bounded streams the same duplicate-key, finite-number, UTF-8, depth, and node rules as files.
- Strictly decode detached signature envelopes under a 1 MB/20-level/10,000-node boundary before
  envelope validation, canonicalization, key comparison, or Ed25519 verification.
- Strictly decode the independently reread signed package manifest under its existing 10 MB limit
  plus a 100-level/250,000-node structure boundary before constructing the signed subject.
- Reconcile inspected, opened, and final identities for private keys, public keys, detached
  signatures, and directory manifests, preventing path replacement during bounded consumption.
- Isolate signing file-identity comparisons from unrelated verifier fault injection and add
  duplicate/non-finite/overflow, structure-limit, signature-race, and public-key-race regressions.

## 0.57.51 - 2026-08-05

### Strict assurance and execution evidence ingestion

- Route assurance work queues, scaffold manifests, retirement records, imported execution-evidence
  manifests, and recorded execution manifests through the shared bounded, identity-stable JSON
  boundary before lifecycle, integrity, baseline, or artifact decisions are made.
- Reject duplicate object keys, `NaN`/`Infinity`, and finite-syntax numeric overflow such as
  `1e9999`, preventing ambiguous or platform-dependent evidence from changing assurance status.
- Apply explicit 100-level and caller-scaled node ceilings before canonical hashing or deterministic
  projection, while retaining existing byte limits and transactional evidence-import rollback.
- Harden each generated standalone pytest scaffold with its own strict JSON decoder and iterative
  structure guard, so exported tests fail collection safely without importing PySFMEA.
- Add adversarial queue, scaffold, and execution-evidence tests for ambiguity, numeric overflow,
  structure exhaustion, inspected/opened/final identity changes, and link refusal.

## 0.57.50 - 2026-08-05

### Strict identity-stable governed JSON verification

- Add one reusable governed-JSON ingestion boundary with regular non-link enforcement, bounded
  binary consumption, inspected/opened/final identity reconciliation, and strict UTF-8 decoding.
- Reject duplicate object keys and non-finite `NaN`/`Infinity` values before semantic validation
  or canonical hashing so ambiguous JSON cannot be normalized into an apparently valid artifact.
- Apply iterative decoded-structure limits with caller-selected depth/node ceilings, preventing
  deeply nested or high-cardinality inputs from reaching recursive digest and projection logic.
- Route public failure-catalog file verification through a 1 MB, 50-level, 100,000-node boundary
  while retaining schema-valid structured rejection verdicts and stable source identity.
- Route every allowed offline schema-bundle file through a 2 MB, 100-level, 250,000-node boundary
  before root-object, identity, catalog, and canonical-digest reconciliation.
- Add exact UTF-8 round-trip, byte/depth/node, duplicate/non-finite, non-file/link, safe-open/final
  identity, catalog CLI, and schema-bundle regression coverage.

## 0.57.49 - 2026-08-05

### Race-safe assurance and contract publication

- Route executable assurance-register JSON/CSV/Markdown and focused work-queue JSON through the
  shared bounded, final-link-safe, prior-preserving single-file publisher.
- Preserve the exact UTF-8-BOM assurance CSV contract while refusing non-file destinations,
  synchronizing staging bytes, and cleaning residue after a rejected atomic replacement.
- Move individual offline JSON Schema exports onto the same publication boundary without changing
  schema identity, canonical content, CLI behavior, or schema-bundle directory semantics.
- Add an opaque retained-destination state so a caller can validate an existing or absent output
  and require that exact state at staging and atomic replacement boundaries.
- Apply retained-state publication to the public failure catalog, preserving its refusal to
  replace unknown files and preventing a newly appeared or concurrently edited destination from
  being overwritten after catalog-envelope validation.
- Add assurance, schema, prior-preservation, exact BOM, non-file, replacement-failure, cleanup,
  and absent-to-present destination-race regressions.

## 0.57.48 - 2026-08-05

### Uniform bounded artifact publication

- Add one reusable 256 MiB single-file publication boundary that preserves final-path identity,
  rejects symbolic-link and non-file destinations, stages beside the destination, flushes and
  synchronizes bytes, and refuses a concurrently changed destination before atomic replacement.
- Route CSV/Markdown worksheets, inventory/audit/guidance views, architecture/sequence/
  traceability/coverage exports, SFTA, SARIF/CycloneDX JSON, canonical diagram bundles, and the
  self-contained HTML report through the shared prior-preserving publisher.
- Preserve exact format behavior, including UTF-8-BOM spreadsheet exports and portable CSV
  newlines, while bounding the complete encoded artifact before destination preparation.
- Isolate the signing replacement seam so a simulated signature-publication failure cannot
  disable independent package-projection regeneration through a process-wide mock.
- Add adversarial size, link, concurrent-change, failed-replacement, staging-cleanup, and exact
  encoding coverage plus cross-export/package/signing regression tests.

## 0.57.47 - 2026-08-05

### Bounded content-addressed golden-corpus evaluation

- Replace unbounded, link-following CLI evaluation-file reads with a 20 MB consumption boundary
  that requires a regular non-link file and reconciles inspected, opened, consumed, and final
  identity.
- Strictly decode UTF-8 corpus JSON with duplicate-key and non-finite-number rejection plus
  iterative 20-level/500,000-node limits before semantic evaluation.
- Define the `pysfmea-golden-corpus-1` closed contract with bounded metadata, 100,000 cases, 100
  unique scope patterns, exact string fields, supported schema identity, and duplicate-case
  rejection for file and programmatic callers.
- Bound active evaluation candidates at 500,000 and replace repeated corpus/candidate scans with
  source/component/rule indexes while preserving ambiguity refusal and exact-key semantics.
- Emit deterministic `pysfmea-evaluation-result-1` verifier provenance and a canonical corpus
  SHA-256 digest with explicit case/scope counts.
- Register the bounded golden-corpus verifier in the adapter catalog and extend PySFMEA's own tool
  SFMEA with malformed, stale, or adversarial evaluation-baseline failure handling.
- Add malformed UTF-8/JSON, duplicate/non-finite, link/non-file, forced-small byte/depth/node/
  case/candidate, identity-change, closed-contract, CLI, installed-wheel, and historical-package
  compatibility coverage.

## 0.57.46 - 2026-08-05

### Bounded transactional model-assisted discovery

- Bound OpenAI-compatible requests at 3 MB and responses at 10 MB, validate endpoint/model/key
  metadata, and strictly decode outer and nested UTF-8 JSON with duplicate-key and non-finite
  number rejection.
- Apply iterative 50-level/100,000-node response limits to network and custom providers before
  hashing, validation, or governed-state mutation.
- Replace permissive suggestion parsing with an exact output field set, bounded text/list/identity
  values, evidence/citation allowlists, and an explicit 25-suggestion per-component ceiling.
- Bound grounded summary packets and responses through the same provider contract, require exact
  summary fields, and retain the canonical response hash alongside provider and prompt provenance.
- Stage suggestions across every requested component and commit only after all provider responses
  validate, so a later rejection leaves suggestions, history, and summary state unchanged.
- Roll back the complete governed analysis when accepted-suggestion materialization fails after a
  partial mutation, preserving both the proposal and the pre-review worksheet state.
- Publish version-2 LLM adapter capabilities and prompt/evidence/suggestion contract version 3;
  no provider-generated content gains engineering authority or automatic acceptance.
- Add duplicate, request/response size, depth, unknown-field, suggestion-count, multi-packet
  rollback, materialization-rollback, summary-bound, installed-wheel, and historical-package
  compatibility coverage.

## 0.57.45 - 2026-08-05

### Transactional bounded PDF report publication

- Preserve the caller's final PDF path identity and reject symbolic-link, directory, and other
  non-regular destinations without following them to an unintended target.
- Verify browser output through a regular non-link file descriptor, cap both verification and
  publication at 250 MB, and reconcile inspected, opened, consumed, and final source identity.
- Stream the verified renderer snapshot into a random private sibling, flush it to stable storage,
  and independently verify its PDF header, trailer, size, and identity before publication.
- Revalidate an existing or absent destination immediately before atomic replacement so a
  concurrent writer is preserved and reported rather than silently overwritten.
- Preserve the previous PDF and remove private staging residue on invalid/oversized renderer
  output, identity drift, destination races, and atomic replacement failures.
- Reconcile Windows path/descriptor creation-time precision when comparing governed-analysis file
  snapshots, while retaining file identity, exact size, and modification-time checks and the
  stricter metadata-change-time comparison on POSIX.
- Add forced-small size, malformed output, linked/non-file destination, opened-identity,
  destination-race, replacement-failure, installed-wheel, and historical-package compatibility
  coverage without changing the PDF command or report contract.

## 0.57.44 - 2026-08-04

### Bounded transactional governed-analysis persistence

- Replace unbounded `json.load` analysis ingestion with a 100 MB consumption-time binary boundary
  that rejects symbolic links/non-files and reconciles inspected, opened, and final file identity.
- Decode strict UTF-8 JSON with duplicate-key and non-finite-number rejection, then apply a shared
  iterative 100-level/2,000,000-node limit before migrations or derived-state materialization.
- Reuse the same structure primitive in review-package verification so persisted and packaged
  analyses cannot drift onto different JSON-complexity contracts.
- Replace unbounded no-op-save reconciliation and reviewer ETag `read_bytes` hashing with the same
  bounded identity-stable analysis reader/streaming hasher.
- Keep the final analysis path unresolved, reject linked/non-file destinations, serialize UTF-8
  output through the 100 MB limit, and revalidate destination identity and metadata immediately
  before atomic replacement.
- Preserve prior content and remove staging residue on size, destination-race, revision-conflict,
  and replacement failures without changing analysis schema or package formats.
- Add forced-small byte/depth/node/hash/output, invalid-UTF-8/JSON, duplicate/non-finite, link,
  directory, opened-identity, destination-race, replacement-failure, installed-wheel, and
  historical-package compatibility coverage.

## 0.57.43 - 2026-08-04

### Bounded snapshot-safe package authentication

- Replace precheck-only, unbounded private/public key and detached-signature reads with regular-file,
  symbolic-link-safe, consumption-time bounded reads that revalidate inspected/opened identity.
- Parse signature envelopes as strict bounded UTF-8 JSON, bound signer labels and passphrases, and
  return stable key/input failures without exposing cryptography or filesystem exception details.
- Read directory and ZIP manifests through a 10 MB boundary and reconcile their exact byte digest
  with the freshly verified package before constructing or accepting a signed subject.
- Treat caller-supplied package-verification results as advisory and always perform fresh integrity
  verification, preventing stale or fabricated verdicts from authenticating changed package bytes.
- Derive signed manifest digests from the successful verification snapshot and reconcile exact ZIP
  bytes through a 550 MB identity-checked streaming rehash instead of unbounded artifact hashing.
- Revalidate signature-destination identity at the publication boundary, atomically replace only
  the inspected destination, preserve prior content on failure/race, and remove staging residue.
- Add forced-small key/signature/manifest/passphrase, invalid-UTF-8, identity-change, stale-verdict,
  replacement-failure, installed-wheel, and historical-package compatibility coverage.

## 0.57.42 - 2026-08-04

### Bounded identity-preserving project configuration

- Replace unbounded `tomllib.load` configuration parsing with a regular-file,
  symbolic-link-safe binary read capped at 5 MB, revalidate inspected/opened file identity before
  consumption, and apply explicit bounded UTF-8 TOML validation.
- Preserve the final path identity of configured coverage JSON and organizational guidance packs
  while normalizing relative paths, so downstream link-safety checks cannot be bypassed by early
  path resolution.
- Return stable configuration read/encoding/size failures without leaking raw filesystem details;
  semantic schema validation remains specific and fail-closed after bounded parsing succeeds.
- Make configuration-template publication final-link-safe and atomic, revalidate destination type
  at the mutation boundary, preserve an existing file on replacement failure, and remove staging
  residue on every rejected publication.
- Add forced-small byte, invalid-UTF-8/TOML, directory/link, downstream-identity, injected atomic
  replacement failure, workflow-status, and installed-package regression coverage.

## 0.57.41 - 2026-08-04

### Consumption-bounded repository inventory hashing

- Replace repository artifact size prechecks plus unbounded `read_bytes` hashing with regular-file
  stream reads capped at 20 MB per artifact and 500 MB actually consumed across the inventory.
- Refuse symbolic links and non-regular filesystem artifacts before opening them, and replace raw
  filesystem exception details with stable unresolved accounting.
- Continue safe metadata and semantic accounting after aggregate hash exhaustion, but add a
  digest-protected unresolved region and set the inventory truncation signal so reports and
  validation cannot present the inventory as complete.
- Bound excluded/opaque directory-region accounting at 100,000 records in addition to the existing
  100,000-file ceiling, while preserving deterministic inventory hashes and status summaries.
- Publish version-2 repository, dependency, and contract adapter descriptors whose capabilities now
  declare the implemented bounded-ingestion and fail-soft semantics.
- Add forced-small per-file/aggregate/region limits, exact-hash, link/non-regular refusal, inventory
  integrity, and installed-package regression coverage without changing inventory schema versions.

## 0.57.40 - 2026-08-04

### Bounded type-safe interface-contract analysis

- Replace interface-contract size prechecks plus unbounded byte reads with regular-file,
  symbolic-link-safe consumption-time reads capped at 20 MB per file, 1,000 discovered files, and
  100 MB in aggregate across OpenAPI/Swagger, JSON Schema, YAML, and protobuf inputs.
- Reject final links, non-files, and resolved repository escapes with stable warnings while
  retaining continued analysis of safe contracts and the rest of the repository.
- Decode contract text as strict UTF-8, handle malformed JSON and unexpected scalar/container
  shapes without tracebacks, and retain the exact accepted-byte digest even when semantic
  extraction is unavailable.
- Bound extracted operations and data types to 500 distinct values per category during traversal,
  emitting explicit truncation evidence instead of building an unbounded intermediate list.
- Add forced-small per-file/discovery/aggregate/entity limits, invalid-UTF-8, scalar-root, link,
  exact-digest, and installed-package regression coverage without changing analysis formats.

## 0.57.39 - 2026-08-04

### Bounded dependency-manifest evidence ingestion

- Replace unbounded and repeated dependency-manifest reads with cached regular-file,
  symbolic-link-safe binary reads capped at 20 MB per file, 1,000 attempted files, and 100 MB in
  aggregate across pyproject, requirements/constraints include chains, and supported lockfiles.
- Hash and parse the exact same accepted bytes so dependency evidence cannot change between a
  manifest digest pass and its semantic extraction pass; resolved aliases reuse one snapshot.
- Normalize included-manifest paths before containment checks, reject final links and repository
  escapes, and stop further ingestion after aggregate exhaustion with stable warnings.
- Decode requirements as strict UTF-8 and validate supported pyproject dependency container shapes,
  retaining the accepted manifest hash while refusing malformed dependency claims.
- Add forced-small byte/file/aggregate limits, link, traversal, invalid-UTF-8, malformed-TOML-shape,
  exact-hash, and continued-analysis regression coverage without changing analysis formats.

## 0.57.38 - 2026-08-04

### Bounded Python source and test-evidence ingestion

- Replace unbounded Python source and test-file text reads with a shared regular-file,
  symbolic-link-safe, consumption-time 20 MB reader that honors PEP 263 encoding declarations.
- Reject in-repository source links consistently with the repository inventory and surface stable
  boundary, size, and encoding warnings without aborting analysis of the remaining repository.
- Cap selected Python source discovery at 100,000 files and the test-reference index at 10,000
  files and 100 MB, reporting the exact limit when deterministic indexing stops.
- Reuse the source byte boundary during repository baseline calculation so a rejected source file
  cannot be consumed unbounded by a later scan phase.
- Add forced-small file/aggregate limits, non-UTF-8 declared encoding, unsupported encoding,
  internal-link, inventory-accounting, and continued-analysis regression coverage.

## 0.57.37 - 2026-08-04

### Bounded path-safe coverage evidence ingestion

- Replace resolved-path plus unbounded coverage JSON loading with a final-link-safe,
  consumption-time 100 MB bounded binary read and explicit UTF-8 JSON object validation.
- Reject repository escapes, parent traversal, empty paths, and duplicate normalized file keys;
  absolute coverage paths are retained only when they resolve beneath the analyzed repository.
- Normalize line and branch evidence to typed coordinates before analysis, retaining coverage.py's
  signed branch destinations while requiring positive source lines, so malformed records cannot
  crash a scan or be mistaken for observed execution.
- Preserve the first valid normalized record and expose aggregate unsafe, malformed, and duplicate
  counts through stable `CoverageError` warnings while the remainder of the scan continues.
- Add forced-small limit, invalid-UTF-8/root/link, path-traversal, duplicate-key, malformed-record,
  and end-to-end scan regression coverage without changing the analysis schema.

## 0.57.36 - 2026-08-04

### Transactional bounded runtime-trace ingestion

- Replace runtime trace resolution plus unbounded byte buffering with a final-link-safe,
  consumption-time 100 MB bounded binary read and explicit UTF-8 JSON root validation.
- Replace permissive recursive span traversal with a type-safe iterative simple/OTLP walker and
  enforce the existing 50,000-span limit before governed state changes.
- Bound nested runtime attribute normalization to 32 levels and validate human labels, malformed
  runtime/history containers, empty traces, and unsupported scalar roots with stable errors.
- Defer all runtime-evidence, history, and summary mutation until normalization and edge derivation
  succeed; restore the complete analysis snapshot if final summary refresh fails.
- Add forced-small byte/span/depth limits, invalid-UTF-8/root/link/label/empty-trace inputs, and
  injected summary-failure rollback coverage without changing runtime evidence record formats.

## 0.57.35 - 2026-08-04

### Transactional bounded external evidence ingestion

- Replace external execution-manifest size prechecks plus unbounded text reads with a regular-file,
  symbolic-link-safe, consumption-time bounded UTF-8 JSON object reader.
- Hash external artifacts under per-file and aggregate consumed-byte limits, then copy and hash each
  stream through an independent bound; reject changed content/size and clean private staging.
- Apply the same bounded, link-safe manifest and artifact verification when managed evidence is
  later adjudicated, preventing review from consuming mutated oversized records.
- Defer imported test registration until evidence validation and publication succeed; roll back the
  complete analysis snapshot and published evidence directory if governed recording fails.
- Add forced-small-limit, invalid-UTF-8, manifest/artifact link, bounded-copy failure, managed-review
  bound, staging cleanup, and analysis/filesystem rollback regression coverage.

## 0.57.34 - 2026-08-04

### Safe standalone scaffold collection

- Replace the generated pytest module's unbounded collection-time manifest text read with a
  self-contained 64 MiB consumption-time bounded binary read.
- Require a regular non-symbolic-link manifest, decode exact consumed bytes as UTF-8 JSON, and
  reject malformed encoding, excessive nesting, non-object roots, and unsupported scaffold formats
  with stable operator-facing collection failures.
- Preserve canonical manifest integrity verification and additionally require a non-empty,
  object-shaped obligation list before pytest parameterization.
- Add execution-level forced-small-limit, invalid-UTF-8, root-shape, symbolic-link, integrity, and
  obligation-shape regression coverage for the emitted test module.

## 0.57.33 - 2026-08-04

### Race-resistant scaffold lifecycle operations

- Refactor scaffold verification internally to return the exact bounded manifest object whose
  integrity, binding, selection, queue identity, and generated-file state were checked, while
  keeping the public verification response unchanged.
- Carry that verified snapshot into guarded refresh and archive instead of independently consuming
  lifecycle parameters from a later manifest read.
- Revalidate the queue at the publication/mutation boundary and compare its manifest identity with
  the initial snapshot, refusing concurrent replacement even when both manifests are independently
  valid.
- Preserve the original queue and remove staged output on refresh races; leave archive sources and
  retirement state untouched on archive races; add deterministic race-injection regression tests.

## 0.57.32 - 2026-08-04

### Bounded assurance-scaffold verification

- Replace assurance-manifest and retirement-record size prechecks plus unbounded text reads with
  exact consumption-time bounded UTF-8 JSON ingestion across verification, guarded refresh, and
  archival.
- Stream generated pytest/README SHA-256 verification under an independent byte limit instead of
  buffering entire files, while retaining informational treatment of expected implementation edits.
- Require every consumed scaffold artifact to be a regular non-symbolic-link file and detect a
  broken retirement link as an invalid present record rather than silently treating it as absent;
  refresh/archive retain final-path identity and refuse broken-link destinations or records.
- Add forced-small-limit, invalid-UTF-8, oversized generated-file/retirement-record, and
  broken-link-equivalent regression coverage without changing public scaffold formats.

## 0.57.31 - 2026-08-04

### Consumption-bounded offline schema verification

- Replace offline schema-bundle entry size prechecks plus unbounded text reads with one bounded
  binary read per catalog/schema file, closing concurrent-growth bypasses at the public-contract
  verification boundary.
- Explicitly decode bounded bytes as UTF-8 JSON and preserve the existing closed-object and exact
  catalog identity/digest reconciliation after safe ingestion.
- Keep missing, malformed, oversized, symbolic-link, and non-file entries as schema-valid
  `schema-bundle-verification` rejections with stable file-level error locations.
- Add default-limit, forced-small-limit, invalid-UTF-8, mocked/real symbolic-link, public-schema,
  and atomic export regression coverage without changing bundle contents or profile counts.

## 0.57.30 - 2026-08-04

### Hardened organizational guidance ingestion

- Replace organizational-guidance size prechecks plus unbounded byte reads with one
  consumption-time bounded read, preventing concurrent growth from bypassing the five-megabyte
  trust boundary used by citation discovery.
- Require every configured pack to be a regular non-symbolic-link file and explicitly decode it as
  UTF-8 JSON before schema, locator, applicability, and mapping validation.
- Continue hashing the exact bytes that passed bounded ingestion so pack provenance remains bound
  to the content actually used to generate finding citations and package projections.
- Add directory, invalid-UTF-8, oversized, mocked/real symbolic-link, exact-byte-count, and digest
  regression coverage without changing the organizational pack schema.

## 0.57.29 - 2026-08-04

### Bounded, link-safe engineering notes

- Replace report-notes size prechecks plus unbounded text reads with one consumption-time bounded
  binary read, closing concurrent-growth bypasses for both HTML and PDF report generation.
- Require notes to be a regular non-symbolic-link file and valid UTF-8 before any report content is
  built; missing, directory, linked, malformed, and oversized inputs fail closed.
- Preserve universal newline semantics by canonicalizing CRLF and CR notes to LF after decoding,
  keeping report content stable and portable across producer platforms.
- Keep JSON report publication transactional for real notes-input failures: return a sanitized
  schema-valid generation rejection, remove staging residue, and preserve any prior report.
- Add regular, non-regular, invalid-encoding, oversized, symbolic-link, canonical-newline, and
  prior-destination regression coverage.

## 0.57.28 - 2026-08-04

### Safe report destinations and unified bounded diagram ingestion

- Refuse symbolic-link and non-regular HTML report destinations before loading or generation in
  both human and JSON modes, preserving the link, its target, directories, and governed analysis.
- Keep the final report path unresolved during atomic replacement so a link can never redirect the
  verified staged artifact to a different file; a link introduced after validation is replaced as
  a directory entry rather than followed.
- Make structured destination rejections use the existing schema-valid
  `report.invalid_destination` receipt with explicit input-validation and prior-preservation state.
- Unify diagram verification and custom report-diagram imports on one symbolic-link-safe,
  consumption-bounded binary JSON reader, closing the remaining precheck/unbounded-read path.
- Add directory, symbolic-link target-preservation, human/JSON behavior, oversized import, and
  diagram-link regression coverage.

## 0.57.27 - 2026-08-04

### Attributable verifier receipts and bounded diagram consumption

- Add exact `verifier.name` and `verifier.version` provenance to every current HTML-report,
  diagram-bundle, and assurance-work-queue verification verdict, including structured rejection
  envelopes, so stored CI evidence identifies the implementation that issued it.
- Publish the shared verifier-provenance shape in all three public JSON schemas while retaining
  compatibility with genuine older v1 verdicts that predate the additive field.
- Replace diagram verification's size precheck plus unbounded text read with one bounded binary
  read at consumption time, preventing concurrent file growth from bypassing the availability
  boundary.
- Add success, rejection, public-schema, and oversized-stream regression coverage.

## 0.57.26 - 2026-08-04

### Transactional verified HTML report publication

- Make `sfmea report ANALYSIS --json` generate into a private sibling, verify complete document
  integrity and exact analysis binding there, and atomically publish only after a valid verdict.
- Preserve an existing destination byte-for-byte and remove staging residue when analysis loading,
  generation, verification, or final publication fails.
- Emit schema-valid, sanitized JSON for every structured-mode failure phase, including invalid
  destinations, missing or malformed analysis, generator failures, verifier failures, and atomic
  replacement failures; JSON mode never exposes unexpected exception detail on stderr.
- Add explicit `published/complete` and `not_published` receipt state, phase, prior-destination
  observation, and preservation status with schema constraints that reject contradictory claims.
- Refuse to use the governed analysis JSON itself as the HTML destination.

## 0.57.25 - 2026-08-04

### Verified HTML report generation receipts

- Add `sfmea report ANALYSIS --json` to generate the self-contained HTML report, immediately verify
  its complete document/payload integrity and exact governed-analysis binding, and emit the public
  `html-report-verification` verdict without human progress noise.
- Return nonzero with a schema-valid, sanitized stdout verdict when post-generation verification
  cannot complete; unexpected verifier details are not copied into CI output.
- Replace report verifier size prechecks plus unbounded reads with a single consumption-time
  bounded binary read, closing file-growth races at the availability boundary.
- Preserve existing human report output and standalone `report-verify` behavior.
- Add matched generation-receipt, path binding, injected verifier failure, stderr isolation,
  schema validation, and bounded-read coverage.

## 0.57.24 - 2026-08-04

### Verified export receipts and stronger target recognition

- Make `publication-catalog --output FILE --json` emit the schema-backed catalog-verification
  verdict for the exact exported path, giving CI one atomic export-and-receipt operation.
- Require a forced-refresh target to pass format, integrity-metadata, and complete structural
  envelope checks; a file that merely spoofs the catalog format no longer qualifies.
- Strengthen failure-entry structural checks across closed fields, scalar types, phase arrays,
  uniqueness, and allowed phase vocabulary before exact taxonomy comparison.
- Preserve the ability to repair structurally recognized drifted catalogs whose digest or exact
  content is invalid, while continuing to refuse unrelated or malformed targets.
- Add JSON export-receipt, format-spoofing, malformed nested value, and path-binding coverage.

## 0.57.23 - 2026-08-04

### Atomic publication catalog export

- Add `sfmea publication-catalog --output FILE` for deterministic UTF-8 catalog export without
  shell redirection, including parent-directory creation and atomic sibling replacement.
- Protect existing files by default; `--force` replaces only a regular, recognized publication
  catalog and refuses symbolic links, directories, malformed JSON, and unrelated files.
- Verify staged catalog content before publication, remove temporary residue on failure, and leave
  the previous catalog byte-for-byte unchanged when atomic replacement fails.
- Reject conflicting `--verify`/`--output` modes and `--force` without an output destination.
- Add export, refresh, unrelated-file preservation, option-validation, and injected replacement
  failure coverage.

## 0.57.22 - 2026-08-04

### Bounded publication catalog verification

- Add `sfmea publication-catalog --verify FILE` with concise human output, nonzero rejection
  status, and schema-backed `--json` verdicts for CI and offline evidence capture.
- Verify bounded regular UTF-8 JSON input, format, integrity metadata, structure, canonical digest,
  and exact equality with the taxonomy shipped by the verifier using stable error codes.
- Publish `publication-failure-catalog-verification` as the fourteenth public schema and embed it
  in current review packages, expanding the governed package inventory to 42 files.
- Preserve the former thirteen-schema package profile as an explicit supported compatibility
  generation alongside earlier profiles.
- Add success, drift, and unavailable-input verifier coverage plus exact verdict/schema and
  current/legacy package checks.

## 0.57.21 - 2026-08-04

### Self-describing catalog integrity

- Declare `algorithm: sha256` and `canonicalization: json-sort-keys-compact-utf8` directly in the
  publication failure catalog so consumers can recompute its content address without prose-only
  knowledge.
- Bind failed receipts to the same semantics through `publication.catalog_algorithm` and
  `publication.catalog_canonicalization` alongside the catalog digest.
- Include the integrity semantics in the canonical catalog payload, so changing either declaration
  also changes the content address.
- Prohibit integrity declarations on published receipts and add negative coverage for missing,
  unsupported, and independently altered metadata.

## 0.57.20 - 2026-08-04

### Content-addressed publication taxonomy

- Add a deterministic `content_sha256` to `publication-catalog --json`, computed over the
  canonical catalog document without the digest field.
- Add the matching `publication.catalog_sha256` to every not-published receipt so archived
  results bind to the exact remediation taxonomy rather than only its format family.
- Constrain both digest fields to the catalog derived from the immutable runtime taxonomy and
  expose the digest in human catalog output for operational verification.
- Prohibit catalog digests on published receipts and add negative coverage for missing,
  mismatched, or independently altered digest claims.

## 0.57.19 - 2026-08-04

### Self-identifying publication failure receipts

- Add the canonical `publication.failure_rule_id` directly to every not-published receipt so
  automation can correlate the primary failure with findings without traversing diagnostic text.
- Add `publication.catalog_format` so stored receipts retain the exact taxonomy contract used to
  interpret their code, action, and retry policy.
- Bind catalog format and rule identity to failure code, phase, action, retry policy, and the
  matching error finding in the review-package verification schema.
- Prohibit catalog and failure-rule metadata on successful and post-publication-verification
  receipts, and add negative coverage for missing or mismatched identities.

## 0.57.18 - 2026-08-04

### Explicit publication retry safety

- Add a catalog-defined `publication.retry_policy` to every not-published receipt so orchestration
  can distinguish retry-after-remediation from failures requiring manual diagnostics.
- Classify input, destination, and generation failures as `after_remediation`; classify internal
  failures as `manual_diagnostics` to prevent blind retry loops.
- Bind retry policy exactly to failure code, phase, next action, and stable finding in both the
  receipt schema and publication-failure catalog schema.
- Prohibit retry policy on successful and post-publication-verification receipts.
- Show retry policy in human catalog output and add negative coverage for missing, mismatched, and
  published-state retry claims.

## 0.57.17 - 2026-08-04

### Discoverable publication failure catalog

- Add `sfmea publication-catalog` with concise human output and schema-validated `--json` output
  for failure codes, stable rule IDs, valid phases, safe messages, and remediation actions.
- Publish a new `publication-failure-catalog` JSON Schema and embed the exact catalog as an
  annotation in the review-package verification schema for offline integration discovery.
- Expand current review packages to 13 content-addressed public schemas and 41 verified artifacts.
- Preserve the former 12-schema profile as an explicit supported compatibility generation.
- Add exact catalog-schema coverage, CLI human/JSON coverage, annotation parity, package/archive
  inventory checks, and current/previous profile verification.

## 0.57.16 - 2026-08-04

### Single-source publication remediation contract

- Centralize publication failure code, rule ID, valid phases, path-safe message, and remediation
  action in one immutable catalog shared by runtime classification and JSON Schema generation.
- Add `publication.next_action` to every not-published receipt, giving automation an explicit
  remediation command category without interpreting human text.
- Enforce exact failure-code/phase/next-action/finding relationships and prohibit both failure
  metadata fields on published receipts.
- Validate taxonomy uniqueness, phase membership, rule naming, and remediation completeness at
  module load so future contract drift fails immediately.
- Add schema-catalog parity and negative coverage for mismatched remediation actions and
  published receipts that improperly claim an action.

## 0.57.15 - 2026-08-04

### Enforceable publication failure taxonomy

- Add a first-class `publication.failure_code` to every not-published package receipt so
  automation does not need to traverse findings or parse messages for the primary outcome.
- Constrain analysis-load failures to analysis input categories and generation failures to
  destination/generation categories, with internal failure valid in either phase.
- Require each failure code to have a matching error-level finding with the corresponding stable
  `package.publication.*` rule ID.
- Prohibit `failure_code` on successful and post-publication-verification receipts.
- Add negative schema coverage for published failure claims and failure-code/finding mismatches.

## 0.57.14 - 2026-08-04

### Provenanced, path-safe automation diagnostics

- Add required `verifier` name/version provenance to every package verification and publication
  verdict, including early failures that cannot read an analysis or create an artifact.
- Replace the generic pre-publication failure rule with stable categories for missing, unreadable,
  or invalid analysis input; unavailable destinations; rejected generation; and internal failure.
- Remove raw exception text from JSON publication findings so local paths, operating-system
  details, and sensitive internal messages are not copied into CI logs or orchestration records.
- Preserve remediation value through bounded category-specific messages, publication phase, output
  identity, and nonzero exit status.
- Add schema and CLI coverage for verifier provenance, malformed JSON, permission failures,
  destination conflict, and internal failure redaction.

## 0.57.13 - 2026-08-04

### Content-addressed package receipts

- Add `manifest_sha256` to successful directory and ZIP verification verdicts, binding a
  detached receipt to the exact manifest that commits the complete package file set.
- Define both `manifest_sha256` and `archive_sha256` in the public verification schema; require
  every valid verdict to carry a manifest digest and every valid ZIP verdict to carry its archive
  digest.
- Compute the manifest digest from the same bounded byte snapshot used for JSON parsing, avoiding
  an identity/parsing time-of-check gap.
- Require error and warning counts to agree qualitatively with their finding arrays, rejecting
  zero-count verdicts that contain that finding level and positive-count verdicts that omit it.
- Add digest recomputation and negative schema coverage for missing identities and contradictory
  finding/count claims.

## 0.57.12 - 2026-08-04

### Core verification verdict consistency

- Added universal JSON Schema invariants connecting `valid`, `checked_files`, and the error count
  for package verification and publication receipts.
- Require every valid verdict to report at least one checked file and zero errors.
- Require every invalid verdict to report at least one error, preventing schema-valid rejection
  envelopes that provide no machine-readable failure signal.
- Added isolated negative coverage for error-count and checked-file contradictions while keeping
  publication-state contradiction tests independently coherent.

## 0.57.11 - 2026-08-04

### Publication receipt consistency invariants

- Added JSON Schema cross-field constraints tying receipt validity, checked-file count,
  publication status, and publication phase into one coherent claim.
- Require valid receipts to be `published/complete`.
- Require not-published receipts to be invalid, report zero checked files, and use only the
  `analysis_load` or `generation` phase; require post-publication rejection to be
  invalid and `published/post_publication_verification`.
- Added negative schema coverage for four contradictory receipt combinations while retaining
  valid current receipts and publication-free standalone verifier compatibility.

## 0.57.10 - 2026-08-04

### Explicit package publication state

- Added an optional schema-defined `publication` object to package receipts so automation can
  distinguish `published` from `not_published` without interpreting messages or filesystem state.
- Classify receipt phases as `analysis_load`, `generation`, `complete`, or
  `post_publication_verification`.
- Mark post-publication verification rejection as published-but-invalid, while input and
  generation failures explicitly confirm that no new package was published.
- Added exact phase/state assertions for successful directory/ZIP output, missing input,
  destination conflict, sanitized runtime failure, and injected post-publication rejection.

## 0.57.9 - 2026-08-04

### Always-structured package automation failures

- Extended `sfmea package --json` to emit the public review-package verification envelope when
  publication fails before an artifact exists, instead of switching to plaintext stderr.
- Represent missing analyses, malformed JSON, destination conflicts, filesystem failures, and
  internal publication rejection with `package.publication_failed`, zero checked files, the
  requested container/path, and a remediation-oriented notice.
- Preserve actionable bounded messages for expected input/operational failures while sanitizing
  unexpected `RuntimeError` details.
- Added schema-validation coverage for missing input, existing-destination conflict, sanitized
  runtime failure, successful directory/ZIP receipts, and injected post-publication rejection.

## 0.57.8 - 2026-08-04

### Machine-readable package publication receipt

- Added `sfmea package --json` for directory and ZIP outputs, emitting the stable public
  `pysfmea-review-package-verification-1` verdict after publication.
- Keep JSON mode free of human progress text so CI and orchestration systems can parse exactly
  one schema-backed document without console scraping.
- Return a nonzero status if the post-publication verification receipt is invalid, retaining the
  same structured diagnostic envelope used by `sfmea verify-package --json`.
- Added directory/ZIP CLI coverage that validates each receipt against the published JSON Schema
  and checks container identity, artifact count, capabilities, and resolved package path.

## 0.57.7 - 2026-08-04

### Fail-closed package publication

- Run the independent package verifier against the complete staging directory before any new or
  replacement review package becomes visible at its destination.
- Withhold internally inconsistent generated packages with a concise, bounded list of verifier
  rule IDs instead of publishing artifacts that the same release rejects.
- Preserve an existing package byte-for-byte when a forced refresh fails its internal gate, and
  remove the rejected staging directory without modifying the caller's analysis.
- Added fault-injection coverage for rejection, cleanup, source immutability, and atomic prior-
  destination preservation.

## 0.57.6 - 2026-08-04

### Intuitive review-archive output

- Infer ZIP publication from a case-insensitive `.zip` output suffix, preventing the CLI from
  silently creating a directory whose name looks like an archive.
- Preserve `--zip` for the default archive destination while making it optional when `-o`
  already communicates the requested container type.
- Updated command help and workflow documentation to describe suffix-based dispatch.
- Added an end-to-end CLI regression that creates a `.ZIP` output and independently verifies
  it as a valid ZIP review package.

## 0.57.5 - 2026-08-04

### Frozen package-analysis snapshot

- Materialize deterministic assurance state on the package's deep-copied analysis before the
  first artifact is written, so every projection observes one settled snapshot.
- Repair absent or malformed derived assurance containers during packaging without modifying
  the caller's governed working analysis.
- Keep `analysis.json`, its manifest state digest, the full assurance register, and the focused
  work queue semantically aligned instead of allowing package generation order to create an
  internally invalid package.
- Added regression coverage proving both repaired cases produce verifier-valid packages whose
  declared analysis-state digest exactly matches the packaged analysis.

## 0.57.4 - 2026-08-04

### Total semantic-verifier fault containment

- Extended the early analysis contract to validate resolved project analysis/risk/quality
  configuration, fault-tree references, hazard-link string lists, finding/guidance citation
  identifiers, guidance profile mappings, and projection-critical provenance collections.
- Reuse the production configuration normalizer at the package boundary so malformed scalar
  policy values and fault-tree semantics are rejected before deterministic regeneration.
- Added a final public verifier exception boundary that converts an unforeseen semantic failure
  into a sanitized `package.semantic_verification_aborted` verdict without exposing internal
  exception text or returning a traceback.
- Added targeted leaf-value mutation tests for every previously uncaught path plus a forced
  internal-failure test proving the public JSON verdict remains schema-valid and sanitized.

## 0.57.3 - 2026-08-04

### Fail-closed package analysis contract

- Added a lightweight, backward-compatible core-container contract before package semantic
  projection, covering projection-critical objects, arrays, object collections, finding
  subrecords, runtime evidence, assurance records, fault-tree nodes, and provenance views.
- Invalid but checksum-consistent analysis content is withheld from every projector and returns
  `package.analysis_contract_invalid` plus bounded, path-specific machine-readable errors.
- Prevented uncaught type errors for malformed items, context, project, assurance, SFTA,
  guidance, runtime evidence, summaries, inventory, adapter runs, and system-context content.
- Extended the public `analysis_structure` verdict with an exact `core_contract` check while
  preserving the explicit distinction between availability protection and schema/engineering
  validity.
- Added direct contract-mutation coverage and an end-to-end adversarial package test whose
  checksum and governed-state digest are recomputed after inserting a malformed finding.

## 0.57.2 - 2026-08-04

### Exact SFTA selector semantics

- Corrected ID-only SFTA event selectors so an explicit `finding_ids` list links only those
  active findings instead of treating absent glob selectors as match-all wildcards.
- Defined mixed selector behavior as the union of exact finding IDs and pattern matches, with
  component and failure-mode globs applied conjunctively when both are configured.
- Resolve ID-only correlations through an index without scanning every finding, and reuse that
  index during hazard-link reconciliation to remove avoidable quadratic lookups.
- Replay the historical ID-wildcard behavior across SFTA, validation, and validation-bearing
  worksheet regeneration only when verifying packages that declare a pre-0.57.2 producer,
  preserving genuine older evidence without weakening new projections.
- Added regression coverage for unknown IDs, exact ID-only selection, mixed selector algebra,
  the ID-only fast path, cross-version SFTA/diagnostic verification, and worksheet parity.

## 0.57.1 - 2026-08-04

### Bounded analysis verification

- Added an iterative, machine-readable `analysis_structure` verdict that reports observed JSON
  node count and depth before governed-state hashing or artifact regeneration.
- Reject analysis snapshots above the 100-level or 2,000,000-node verification limits, including
  packages whose analysis checksum and governed-state digest were recomputed after tampering.
- Convert parser recursion failures into stable invalid-package findings instead of allowing an
  unhandled verification failure.
- Reuse one isolated analysis snapshot across all ten reviewer-view regenerations, eliminating
  repeated full-analysis copies while retaining side-effect isolation from the caller.
- Exposed structural metrics through human/JSON CLI output, the public verification schema, and
  workflow status, with adversarial depth/node and clean-package regression coverage.

## 0.57.0 - 2026-08-04

### Package provenance reconciliation

- Added `package_provenance_projection_v1` for the package-time audit manifest and reviewer
  README, with exact analysis-derived review/execution inventories plus explicit timestamp and
  baseline consistency checks.
- Unified outer-manifest, audit-manifest, CycloneDX, and README generation timestamps and made
  audit regeneration producer-version aware for future verifier upgrades.
- Added semantic rejection of forged audit decisions even when both the audit record's internal
  digest and the outer package checksum are recomputed.
- Made review-view and README reconciliation portable across LF/CRLF platforms by comparing
  canonical UTF-8 text while retaining exact transferred-byte verification in `manifest.json`.
- Preserved v0.56.1 and earlier capability contracts and exposed the nested provenance verdict
  through CLI, JSON Schema, workflow status, directory/ZIP verification, and release guidance.

## 0.56.1 - 2026-08-04

### Cross-version interchange verification

- Fixed exact SARIF and CycloneDX reconciliation so a newer verifier regenerates embedded tool
  metadata with the package's declared producer version rather than its own installed version.
- Strengthened compatibility coverage with a genuine v0.55 fixture whose embedded interchange
  versions and manifest hashes are rewritten consistently, preserving tamper detection without
  rejecting valid historical packages.
- Corrected new SARIF driver information URIs to the public `willtran87/project-py-sfmea`
  repository while retaining the historical URI during exact verification of older producers
  and preserving the explicit candidate-not-defect semantics.

## 0.56.0 - 2026-08-04

### Reviewer-view reconciliation

- Added the `review_views_projection_v1` package capability for ten human-review artifacts:
  worksheet CSV/Markdown, inventory, architecture, traceability, coverage, audit history,
  guidance CSV, and assurance CSV/Markdown.
- Package verification now regenerates those views in an isolated temporary workspace and
  compares exact bytes, rejecting rewritten reviewer-facing conclusions even when manifest
  hashes are recomputed.
- Exposed the five grouped projection checks plus artifact, finding, and component counts
  through human/JSON CLI output, workflow status, and the public verification schema.
- Preserved v0.55 and earlier capability contracts and added current, legacy, directory, ZIP,
  schema, workflow, and forged-checksum coverage.

## 0.55.0 - 2026-08-04

### SARIF and CycloneDX reconciliation

- Added the `interchange_artifacts_projection_v1` package capability for the SARIF finding
  exchange and CycloneDX declared-component inventory.
- Package verification now regenerates both artifacts from packaged analysis, checks exact
  projections and shared baseline identity, and rejects rewritten interchange content even
  when manifest hashes are recomputed.
- Unified the package manifest, README, and CycloneDX generation timestamp so current package
  exports are reproducible from a single auditable time declaration.
- Exposed SARIF-result and CycloneDX-component counts through human/JSON CLI output, workflow
  status, and the public package-verification schema while preserving v0.54 and older contracts.

## 0.54.0 - 2026-08-04

### Execution-evidence catalog reconciliation

- Added the `evidence_catalog_projection_v1` package capability for recorded assurance
  executions and evidence-artifact inventory.
- Package verification now checks the exact catalog projection, analysis-baseline binding,
  execution inventory, and evidence-artifact inventory. Forged evidence records remain invalid
  when manifest hashes are recomputed.
- Exposed execution/artifact counts and the four-check verdict through human/JSON CLI output,
  workflow status, and the public package-verification schema.
- Preserved v0.53 and earlier capability contracts and added current, legacy, forged-checksum,
  schema, directory, ZIP, and workflow coverage.

## 0.53.0 - 2026-08-04

### SFTA projection reconciliation

- Added the `sfta_projection_v1` package capability for the complete top-down Software Fault
  Tree model and its flat reconciliation-gap register.
- Package verification now regenerates both artifacts from packaged analysis, checks exact model
  and CSV-row projections, and reconciles model/gap counts. Rewritten SFTA content remains invalid
  when manifest hashes are recomputed.
- Review-package export now operates on a detached analysis snapshot and materializes SFTA once,
  preventing export-time mutation of a library caller's governed analysis.
- Exposed tree/gap counts and the three-check verdict through human/JSON CLI output, workflow
  status, and the public package-verification schema while preserving v0.52 and older packages.

## 0.52.0 - 2026-08-04

### Guidance-traceability reconciliation

- Added the `guidance_traceability_projection_v1` package capability for the complete guidance
  trace and standalone citation catalog.
- Package verification now regenerates both JSON artifacts from packaged analysis and checks
  their cross-artifact consistency. Rewriting citation evidence and recomputing its manifest
  checksum no longer produces a valid current package.
- Exposed citation and finding-link counts plus the three-check verdict through human/JSON CLI
  output, workflow status, and the public package-verification schema.
- Preserved v0.51 and earlier capability contracts and added current, legacy, forged-checksum,
  schema, directory, ZIP, and workflow coverage.

### Save determinism

- No-op saves now preserve `summary.last_saved_at` and byte identity across clock boundaries,
  while any substantive governed-analysis change still advances the saved timestamp.
- Added a forced-time regression so this behavior no longer depends on two operations occurring
  within the same second.

## 0.51.0 - 2026-08-04

### Bounded directory-package verification

- Applied the review-package entry, per-file, and cumulative-size limits to directory inputs as
  well as ZIP inputs.
- Replaced whole-file checksum buffering with bounded streaming SHA-256 calculation and enforced
  limits again during manifest, analysis, schema, diagnostic, queue, and register JSON parsing.
- Replaced recursive traversal of unexpected directory trees with bounded root enumeration and
  explicit flat-layout rejection.
- Added adversarial coverage for excessive manifest entries, oversized declarations, and nested
  directory content while preserving current and legacy package compatibility.

## 0.50.0 - 2026-08-04

### Analysis-diagnostic reconciliation

- Added the versioned `analysis_diagnostics_projection_v1` package capability for the summary,
  validation findings, resolved system context, repository inventory, and adapter-run ledger.
- Package verification now regenerates all five diagnostic views from packaged `analysis.json`.
  Validation timestamps remain provenance metadata; validation counts and findings reconcile
  exactly.
- Rewriting any diagnostic JSON artifact and updating its manifest checksum no longer produces
  a valid current package. The nested verdict is available in human/JSON verifier output,
  workflow status, and the public package-verdict schema.
- Preserved pre-0.50 package compatibility and added current directory, ZIP, forged-checksum,
  schema, workflow, and installed-wheel coverage.

## 0.49.0 - 2026-08-04

### Assurance-register reconciliation

- Added the `assurance_register_projection` package capability and exact regeneration of the
  full JSON assurance register from packaged analysis.
- Package verification now checks register structure, deterministic non-queue content, the
  embedded queue's integrity/binding, and byte-identical consistency between embedded and
  standalone work queues.
- Rewriting `assurance-register.json` and updating its manifest checksum no longer produces a
  valid current package. Register results are exposed in human/JSON output, workflow status,
  and the public package-verdict schema.

### Cross-version correctness

- Queue semantic reconciliation now excludes producer-version provenance and its dependent
  content digest while continuing to verify both independently. Compatible format-2 queues
  therefore remain valid after a PySFMEA upgrade instead of being reported as stale solely due
  to the installed verifier version.
- Preserved legacy packages that predate register-projection declarations and added
  cross-version, forged-register, embedded/standalone consistency, ZIP, schema, and workflow
  coverage.

## 0.48.0 - 2026-08-04

### Explicit package capabilities

- Added the manifest capability `assurance_work_queue_projection` to make the focused queue
  contract discoverable without inferring behavior solely from exporter versions or filenames.
- Current exporter or analysis-generator provenance requires a complete supported capability
  declaration; missing, duplicate, unknown, and incomplete declarations fail package verification.
- Added capabilities to human/JSON verifier output and workflow package diagnostics.

### Contract and ZIP polish

- Expanded the public manifest and package-verdict schemas with capability metadata and the
  complete nested assurance-work-queue verification envelope.
- Replaced temporary extraction paths in ZIP queue verdicts with stable logical references of
  the form `PACKAGE.zip!/assurance-work.json`.
- Preserved verification of older packages without capability declarations and added current,
  legacy, malformed-declaration, schema, directory, ZIP, and workflow regression coverage.

## 0.47.0 - 2026-08-04

### Review-package assurance handoff

- Promoted `assurance-work.json` to a first-class artifact in every new directory and ZIP
  review package, alongside the complete assurance register and its public schemas.
- Extended `sfmea verify-package` to verify the queue's internal digest and exact deterministic
  projection against packaged `analysis.json`. Rewriting the queue and recomputing both its
  digest and manifest checksum no longer produces a valid package.
- Exposed the queue verdict in human/JSON package verification and in `sfmea status` package
  integrity diagnostics. Current packages contain 40 governed files and twelve schemas.

### Compatibility and verification

- Preserved 0.46-and-earlier package profiles that predate the standalone queue. Current
  exporter or analysis-generator provenance requires the artifact, preventing silent omission
  from new packages.
- Added directory, ZIP, portable, forged-checksum, legacy-core, workflow, and installed-wheel
  coverage for the package-to-hardening-queue handoff.

## 0.46.0 - 2026-08-04

### Assurance work-queue integrity

- Upgraded focused automation backlogs to `pysfmea-assurance-work-queue-2`, with explicit
  generator provenance, baseline/schema/analysis-state binding, and a canonical SHA-256
  content digest.
- Added `sfmea assurance-work-verify QUEUE [--analysis ANALYSIS] [--json]`. Standalone
  verification detects accidental changes; analysis-bound verification also detects stale
  queues and rejects semantically altered queues even when their content digest is recomputed.
- Published the machine-readable `assurance-work-queue-verification` verdict contract and
  embedded all twelve public contracts in 39-file review packages.

### Compatibility and verification

- Preserved complete historical four-, six-, eight-, nine-, ten-, and eleven-schema package
  profiles, plus schema-less format-1 packages.
- Added bounded-file, malformed-input, tamper, forged-digest, stale-binding, CLI, schema, and
  installed-artifact coverage for the work-queue verification path.

## 0.45.0 - 2026-08-04

### Added

- Added `sfmea assurance ANALYSIS --format work-json` for a focused, independently consumable
  `pysfmea-assurance-work-queue-1` artifact without the full obligation register.
- Published a closed Draft 2020-12 `assurance-work-queue` contract covering work states,
  blockers, automation eligibility, latest execution status, summary counts, and next actions.
- Embedded the new contract as the eleventh content-addressed schema in standalone schema
  bundles and review packages.

### Compatibility and verification

- Preserved verification of complete historical four-, six-, eight-, nine-, and ten-schema
  profiles, plus schema-less format-1 packages.
- Added clean export equivalence, real generated-queue schema validation, package-profile, and
  installed-distribution coverage.

## 0.44.0 - 2026-08-04

### Added

- Added a deterministic assurance work queue that classifies every accepted finding as a
  contract gap, definition required, plan review required, ready for implementation, ready
  for execution, execution/evidence remediation, evidence review, verification review, or
  resolved.
- Each work item carries its finding and obligation IDs, priority, component, blockers,
  automation eligibility, latest execution state, and a stable next-action ID.

### Reporting and usability

- JSON assurance exports now include the complete versioned work queue; CSV and Markdown add
  work state, blockers, automation eligibility, and next-action columns.
- The self-contained HTML report and local reviewer annotate bounded obligations with the same
  derived work state without modifying the governed assurance contract.
- Lifecycle progress now reports implementation-ready, execution-ready, actionable, and
  state-distribution totals for CI and portfolio dashboards.

## 0.43.0 - 2026-08-04

### Added

- Published a self-contained Draft 2020-12 `workflow-status` contract for the complete
  `sfmea status --json` envelope, lifecycle stages, handoff gates, evidence, summaries, and
  remediation actions.
- Embedded the workflow contract as the tenth content-addressed schema in new review packages
  and standalone offline schema bundles.

### Compatibility and verification

- Preserved independent verification of historical complete four-, six-, eight-, and
  nine-schema package profiles as well as schema-less format-1 packages.
- Added contract validation against a real generated status result and semantic tests ensuring
  every blocked gate resolves to a supplied workflow action.

## 0.42.0 - 2026-08-04

### Added

- Added an explicit eight-gate handoff checklist to `sfmea status`, covering repository
  readiness, analysis availability, validation, finding review, revalidation, assurance
  planning, report currency, and review-package currency.
- Each gate now carries a stable ID, pass/block state, concise detail, concrete evidence,
  and a remediation action ID that resolves to the ordered workflow actions.

### Safety and usability

- Handoff readiness is derived from the complete gate set, preventing one lifecycle stage
  from hiding other simultaneous blockers.
- Human output presents a scannable pass/block checklist; JSON exposes the same evidence and
  summary for CI policy without changing the existing workflow-status format identifier.

## 0.41.0 - 2026-08-04

### Added

- Added `sfmea schema --bundle DIRECTORY` for atomic export of the complete offline contract
  catalog and all nine content-addressed schemas.
- Added `sfmea schema --verify-bundle DIRECTORY [--json]` for bounded, standalone verification
  of catalog completeness, schema identity, canonical digests, entry types, and file contents.

### Safety and usability

- Bundle refresh requires `--force`, accepts only a recognized generated file set, refuses
  symbolic links, directories, and reviewer-added files, and publishes through verified staging.
- Human verification output is concise while JSON output retains the stable public
  `pysfmea-schema-bundle-verification-1` contract and meaningful exit codes.

## 0.40.0 - 2026-08-04

### Added

- Published a closed Draft 2020-12 contract for detached Ed25519 signature envelopes,
  statements, package subjects, key fingerprints, and signature encoding.
- Embedded the signature contract as the ninth content-addressed schema in new review packages.
- Preserved complete 0.37, 0.38, and 0.39 schema profiles alongside schema-less format-1
  compatibility.

### Verification

- Signing tests validate real generated envelopes against the public contract before exercising
  trusted-key verification, wrong-key rejection, mutation detection, and replay protection.

## 0.39.0 - 2026-08-04

### Added

- Made the public contract chain self-describing with schemas for `schema-catalog.json` and
  `pysfmea-schema-bundle-verification-1` success/rejection verdicts.
- Expanded new review packages to carry eight content-addressed public schemas while retaining
  compatibility with older complete four- and six-schema, plus schema-less, format-1 packages.

### Verification

- Contract tests now validate the generated catalog plus successful and rejected schema-bundle
  verdicts against their own published Draft 2020-12 schemas.

## 0.38.0 - 2026-08-04

### Added

- Published self-contained JSON Schema contracts for the review-package manifest and the
  stable `verify-package --json` success/rejection verdict envelope.
- Added an explicit `pysfmea-review-package-verification-1` discriminator to every package
  verification result, including early archive and manifest failures.
- Embedded the expanded six-contract, content-addressed schema set in new review packages.

### Verification

- Package tests validate real exported manifests and verifier verdicts against the public
  Draft 2020-12 contracts and retain schema-less format-1 compatibility coverage.

## 0.37.0 - 2026-08-04

### Added

- Governed review directories and ZIP archives now carry the exact offline schema catalog and
  all four public diagram/verifier contracts.
- Package verification cross-checks schema file completeness, catalog identities, canonical
  content digests, and manifest catalog metadata; workflow status exposes the bounded verdict.

### Compatibility

- Existing `pysfmea-review-package-1` artifacts without embedded schemas remain verifiable.
  Schema files are treated as a complete declared extension, so partial bundles fail closed.

## 0.36.0 - 2026-08-04

### Added

- Standalone, bounded HTML report and canonical diagram-bundle verification commands.
- Independent payload and normalized whole-document integrity for current HTML reports.
- Analysis-state binding, downgrade protection, structured failure verdicts, and explicit
  requested/checked/failed/unchecked verification states.
- Content-addressed JSON Schema Draft 2020-12 catalog and atomic schema export command.
- Linux/Windows CI across Python 3.11–3.14, distribution builds, clean-wheel smoke tests,
  dependency updates, contributor guidance, security policy, and release checklist.

### Changed

- Workflow status now reuses the standalone HTML verifier instead of maintaining a separate
  payload-only implementation.
- Diagram and report verifier outputs now share stable automation semantics and safety notices.
- Unchanged assurance/SFTA derivations retain their provenance timestamps, making identical
  atomic saves byte-stable and preventing false external-change reloads in the review server.

## 0.31.0 - 2026-08-04

- Added bounded failure-propagation projection controls, trace navigation, assurance context,
  state-bound diagram bundles, atomic publication, and extensive workflow/report refinements.
