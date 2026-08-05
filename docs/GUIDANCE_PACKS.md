# Organizational guidance packs

PySFMEA can merge licensed or internal organizational standards into the same
source → locator → rule → finding traceability used by its built-in public guidance.
The document itself is not copied into the analysis. The pack contains controlled
metadata, short organization-authored summaries, exact locators, and rule mappings.

Add one or more pack paths to `sfmea.toml`:

```toml
[analysis]
guidance_profiles = ["core_sfmea"]
guidance_packs = ["standards/company-software-assurance.json"]
```

Paths are resolved relative to `sfmea.toml`. Each pack must be a regular, non-symbolic-link UTF-8
JSON file. PySFMEA reads at most five megabytes from one inspected/opened/final identity-stable
stream and rejects duplicate keys, non-finite values, numeric overflow, malformed UTF-8, depth over
100 levels, or more than 250,000 decoded nodes. It schema-checks that bounded content, hashes the
exact consumed bytes, and adds the pack as an automatically active `org.*` profile. IDs may not
collide with built-in or other pack records. Pack provenance,
source-record digests, catalog digest, profile selection digest, and per-finding
mapping IDs are preserved in JSON, CSV, HTML, run-manifest, and review-package output.

## Pack schema

```json
{
  "schema_version": "pysfmea-organizational-guidance-pack-1",
  "profile": {
    "id": "org.company_software_assurance",
    "title": "Company Software Assurance Standard",
    "status": "approved_internal",
    "applicability": "Projects that formally adopt CSA-100.",
    "risk_semantics": "Use the approved project risk matrix.",
    "verification_semantics": "Controls require independent objective evidence.",
    "tailoring": "Record the approved tailoring decision and authority.",
    "compliance_claim": false
  },
  "sources": [
    {
      "id": "ORG-CSA-100",
      "publisher": "Company Engineering",
      "title": "Software Assurance Standard",
      "version": "4.1",
      "status": "approved",
      "published_at": "2026-07-01",
      "url": "https://controlled.example/CSA-100",
      "official_source": "Controlled document system record CSA-100",
      "scope": "Safety- and mission-critical software",
      "use": "Failure analysis and verification planning",
      "access": "licensed_internal",
      "quote_policy": "Do not reproduce controlled text; locator summaries only."
    }
  ],
  "citations": [
    {
      "id": "ORG-CIT-CSA-OMISSION",
      "source_id": "ORG-CSA-100",
      "locator": {
        "section": "7.3.2",
        "heading": "Omission failures"
      },
      "summary": "Review required functions for omitted behavior."
    }
  ],
  "rule_mappings": [
    {
      "id": "ORG-MAP-CSA-OMISSION",
      "rule_selector": "functional.omission",
      "citation_id": "ORG-CIT-CSA-OMISSION",
      "relationship": "failure_taxonomy",
      "strength": "direct"
    }
  ]
}
```

Rule selectors use the same exact or wildcard matching as built-in mappings. Allowed
relationships and strengths are closed vocabularies and are validated. A pack cannot
set `compliance_claim` to true: applicability, tailoring, conformance, waiver, and
acceptance remain governed human decisions outside scanner inference.

The pack SHA-256 proves which bounded JSON bytes were used. If the organization is permitted
to retain a document digest, it may add an `artifact` object to a source record; the
pack should still avoid excerpts that violate its license or quote policy.
