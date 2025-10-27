# Nmap Agent Project Design

## Overview
Simple LLM agent loop calling Nmap functions via manifest. Code in one file <50 lines. Rich manifest handles parsing/summarization.

## ASCII Architecture
```text
+----------------+      +----------------+
| Manifest Store |<-----| Manifest Loader|
| (nmap_manifest.json) | | load_manifest()|
+----------------+      +----------------+
        ^                        |
        |                        v
        |                +--------------------------+
        |                |   Local LLM Agent        |
        |                | (system prompt includes  |
        |                |  prompt_manifest + rules)|
        |                +-----------+--------------+
        |                            |
        |              decides next   |  (emit structured call JSON)
        |              action /call   v
        |                +-------------------------+
        |                |  LLM Output (call JSON)  |
        |                |  {"call": "...", args:{}}|
        |                +-----------+-------------+
        |                            |
        |                            v
        |                +------------------------------+
        |                | Adapter / Executor           |
        |                |  execute(fn_name, args)      |
        |                |  - run nmap w/ structured o/p|
        |                |  - parse XML -> canonical    |
        |                |  - return ScanResultSummary  |
        |                +--------------+---------------+
                                       |
                       compact ScanResultSummary
                                       v
                        +--------------+---------------+
                        | Return -> LLM (summary JSON) |
                        +--------------+---------------+
                                       |
            LLM ingests summary and reasons -> loop back
```

## Components

### Manifest Store (`nmap_manifest.json`)
- JSON with functions, verbosity levels, fields, examples.
- Handles parsing/summarization richness.

### Manifest Loader (`load_manifest()`)
- Loads manifest.
- Generates `prompt_manifest` for LLM.

### Local LLM Agent
- System prompt: `prompt_manifest` + rules.
- Outputs JSON: `{"call":"<function_name>","args":{...}}`.
- Rules: Default to "summary"; use "minimal" for repeats; "detailed" for new/low-confidence.

### Adapter / Executor
- Runs Nmap.
- Parses XML to canonical fields.
- Returns `ScanResultSummary` JSON.

### State Management
- Simple in-memory or basic file tracking for history.

### Logs
- Output to terminal and single txt file.

## ScanResultSummary Example
```json
{
  "scan_id": "scan-17",
  "target": "host_01",
  "host_up": true,
  "open_ports": [80,22],
  "services": {"80":"http","22":"ssh"},
  "notes": "host up; new_ports:[80]"
}
```

## Minimal Example Round-Trip
1. LLM: `{"call":"top_ports_scan","args":{"target":"host_01","verbosity":"summary"}}`
2. Adapter: Runs Nmap, parses, returns summary.
3. LLM: Receives summary, loops.

## Next Steps
- Create Python code in one file <200 lines.
- Enhance speed
