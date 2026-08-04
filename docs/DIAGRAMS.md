# Canonical diagram model

PySFMEA uses a renderer-neutral JSON model so generated and project-supplied
diagrams can be validated, transported, rendered in the standalone report, and
processed by other tools without depending on Mermaid, Graphviz, or a hosted
service.

## Generate diagram models

```powershell
sfmea diagram sfmea-analysis.json -o diagrams.json
sfmea diagram sfmea-analysis.json --type failure_propagation -o propagation.json
```

The output is a `pysfmea-diagram-bundle-1` object containing project provenance
and one or more `pysfmea-diagram-1` diagrams. Supported generated categories are:

- `architecture`
- `interface_flow`
- `traceability`
- `failure_propagation`
- `control_coverage`
- `sequence`

Generated architecture, propagation, control, and sequence views are explicitly
bounded and record their limits or truncation state in the diagram notice and
metadata.

## Include custom diagrams in a report

```powershell
sfmea report sfmea-analysis.json `
  --diagram workflow-states.json `
  --diagram deployment-flow.json `
  -o sfmea-report.html
```

Each file may contain one diagram, an array of diagrams, or a bundle with a
top-level `diagrams` array. Custom diagram IDs must not collide with generated or
other imported diagram IDs.

## Diagram schema

```json
{
  "schema_version": "pysfmea-diagram-1",
  "id": "workflow-state-machine",
  "title": "Workflow state machine",
  "type": "state",
  "description": "Execution lifecycle and terminal states.",
  "notice": "Transitions are project-supplied and require review.",
  "nodes": [
    {
      "id": "draft",
      "label": "Draft",
      "kind": "state",
      "group": "Lifecycle",
      "description": "Configuration is editable.",
      "source": "SRS-14",
      "tags": ["non-terminal"],
      "metrics": {"terminal": false},
      "layer": 0,
      "order": 0
    },
    {
      "id": "running",
      "label": "Running",
      "kind": "state",
      "group": "Lifecycle",
      "layer": 1,
      "order": 1
    }
  ],
  "edges": [
    {
      "id": "start",
      "source": "draft",
      "target": "running",
      "label": "start",
      "kind": "transition",
      "evidence": "SRS-14.2",
      "description": "A validated request starts execution.",
      "order": 0,
      "cycle": false
    }
  ],
  "metadata": {
    "owner": "Systems engineering"
  }
}
```

### Diagram fields

| Field | Required | Meaning |
|---|---|---|
| `id` | Yes | Stable identifier unique within the report |
| `title` | Yes | Human-readable diagram title |
| `type` | Yes | Layout and semantic hint |
| `description` | No | Scope and intended interpretation |
| `notice` | No | Limitation, provenance, or truncation statement |
| `nodes` | Yes | Bounded array of typed elements |
| `edges` | Yes | Bounded array of directed relationships |
| `metadata` | No | Scalar or bounded scalar-array provenance |

Supported diagram types are `directed_graph`, `flow`, `sequence`,
`traceability`, `cause_effect`, and `state`. These types select a layout strategy;
node and edge `kind` values remain project-extensible.

### Node fields

`id`, `label`, and `kind` are required. `group`, `description`, `source`, `tags`,
and scalar `metrics` supply evidence and drill-down details. Optional integer
`layer` and `order` values guide deterministic layout. When layers are omitted,
the report derives a bounded directed layout from the edges.

### Edge fields

`source` and `target` must reference existing node IDs. `id`, `kind`, `label`,
`evidence`, `description`, `order`, and `cycle` describe the relationship.
Sequence diagrams use edge order for message placement. Other diagrams use edge
direction for layered layout and propagation.

## Validation and security boundaries

- Diagram IDs are restricted to stable alphanumeric identifiers with dot,
  underscore, colon, and hyphen separators.
- Duplicate nodes, duplicate edges, dangling references, unsupported types,
  malformed metadata, and invalid layer/order values are rejected.
- A diagram can contain at most 2,000 nodes and 5,000 edges.
- At most 50 custom diagrams are accepted, and each input file is limited to
  5 MB.
- Imported text is embedded as escaped JSON and rendered using DOM text nodes.
- Diagrams cannot add scripts, styles, HTML, URLs, event handlers, or remote
  resources to the report.

These controls protect the report renderer and keep diagrams reviewable. They do
not establish that an imported relationship is true, complete, approved, or
supported by adequate engineering evidence.
