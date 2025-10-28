# Attack Vector Insight Schema

This document defines the structured schema the agent uses to capture attack vectors once it has gathered enough context about a target. The schema is intentionally JSON-friendly so it can be produced programmatically (`attack_vectors.json`) and consumed by downstream tooling.

## Top-level document

| Field | Type | Description |
| --- | --- | --- |
| `schema_version` | string | Semantic version for the schema. Currently `"1.0"`. |
| `generated_at` | string (ISO8601) | Timestamp when the catalog was built. |
| `catalog_stats` | object | Summary metrics about the data set. |
| `catalog_stats.total_hosts_observed` | integer | Count of hosts in the historical port inventory. |
| `catalog_stats.hosts_with_vectors` | integer | Hosts that currently have at least one inferred attack vector. |
| `vector_entries` | array | Ordered list (descending priority) of host-level attack vector assessments. |

## `vector_entries[]`

| Field | Type | Description |
| --- | --- | --- |
| `target` | string | IP or hostname of the assessed host. |
| `last_seen` | string (ISO8601) | When this host was last confirmed during scanning. |
| `risk_score` | number | Calculated risk score derived from discovered ports. |
| `risk_factors` | object | Buckets of ports contributing to the score (e.g., `high_value_ports`, `web_ports`). |
| `open_tcp_ports` | array<int> | TCP ports observed as open. |
| `open_udp_ports` | array<int> | UDP ports observed as open. |
| `services` | object | Mapping of port numbers to the identified service name. |
| `overall_priority` | number | Combined priority metric (risk + weighted severity/likelihood of matched vectors). |
| `vectors` | array | Detailed attack vector hypotheses for this host. |

## `vector_entries[].vectors[]`

| Field | Type | Description |
| --- | --- | --- |
| `vector_id` | string | Stable identifier for the hypothesis (e.g., `remote_desktop_exposure`). |
| `title` | string | Human-friendly name of the potential attack vector. |
| `severity` | string | Severity classification (`low`, `medium`, `high`, `critical`). |
| `likelihood` | string | Likelihood bucket derived from matching confidence (`low`, `medium`, `high`). |
| `confidence` | number | Numeric score in range [0, 1] representing match strength. |
| `description` | string | Summary of why this vector matters. |
| `attack_path` | array<string> | Ordered steps outlining how an attacker could progress. |
| `prerequisites` | array<string> | Conditions or resources required to attempt the attack. |
| `recommended_mitigations` | array<string> | Defensive actions to reduce or remove the risk. |
| `evidence` | object | Structured indicators (matched ports, services, risk score contributions). |

## Evidence object details

The `evidence` object is a flexible map containing the following optional keys:

* `tcp_ports`: array<int> — The TCP ports that triggered the match.
* `udp_ports`: array<int> — The UDP ports that triggered the match.
* `service_keywords`: array<string> — Service keywords observed that align with the attack vector.
* `risk_score`: number — The aggregated host risk score when it influenced the match.

Additional evidence keys may be added in backwards-compatible ways as new heuristics become available.

## Usage workflow

1. `parse_open_ports_enhanced` updates `PORT_HISTORY` with structured host data.
2. `refresh_attack_vector_catalog` builds the catalog using `ATTACK_VECTOR_LIBRARY` heuristics and writes `attack_vectors.json`.
3. Downstream consumers read `attack_vectors.json` (which conforms to this schema) to prioritize response, remediation, or deeper assessments.

This schema keeps the agent focused on efficiently identifying meaningful attack surfaces without prescribing exploitation steps.
