"""Public guidance and the software failure vocabulary used by PySFMEA."""

from __future__ import annotations


GUIDANCE_SOURCES = [
    {
        "title": "NASA Software Engineering Handbook: SW Failure Modes and Effects Analysis",
        "url": "https://swehb.nasa.gov/spaces/SWEHBVD/pages/102695706/8.05+-+SW+Failure+Modes+and+Effects+Analysis",
        "use": "Bottom-up SFMEA process; software data, event, interface, timing, and propagation failure modes.",
    },
    {
        "title": "FAA Guide to Reusable Launch and Reentry Vehicle Software and Computing System Safety",
        "url": "https://www.faa.gov/sites/faa.gov/files/regulations_policies/faa_regulations/commercial_space/Guide-Software-Comp-Sys-Safety-RLV-Reentry.pdf",
        "use": "Software-specific FMEA procedure, failure classifications, effects, controls, and worksheet examples.",
    },
    {
        "title": "IEC 60812:2018 Failure modes and effects analysis (FMEA and FMECA)",
        "url": "https://webstore.iec.ch/en/publication/26359",
        "use": "General FMEA framework applicable to software and interfaces. The full standard is not bundled.",
    },
]


METHODOLOGY_NOTICE = (
    "Scanner output is a set of candidate failure modes, not an approved FMEA. "
    "Severity must be based on the credible end effect. Occurrence and detection, "
    "when used, require project-defined scales and evidence. Complexity, dependency "
    "count, and test-file presence are screening signals and are not substituted for "
    "S/O/D ratings. Qualified people must review scope, effects, controls, ratings, "
    "actions, and residual risk."
)


REVIEW_CHECKLIST = [
    "Confirm the component's intended function and requirement.",
    "Decide whether the candidate is a credible failure mode in the defined scope.",
    "Trace local effect to the next-higher level and the system/end effect.",
    "Identify specific causes, including data, logic, interface, timing, and state faults.",
    "Record existing prevention and detection controls with objective evidence.",
    "Apply the project's documented rating scales; do not infer severity from code metrics.",
    "Define actions, owners, verification evidence, and closure criteria.",
    "After a design change, rescan and confirm that no new failure path was introduced.",
]


DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "site-packages",
    "dist",
    "build",
    "__pycache__",
}
