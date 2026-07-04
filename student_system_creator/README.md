# CodeKG Query Interface Specification

This document describes how CodeKG queries should be constructed, what response structure they return, which query types are currently supported, and how it extract source-code evidence from the returned result.

This document is focused only on the query interface. It does not describe how the knowledge graph is built, how labels are stored, or how final vulnerability classification is evaluated.

---

## 1. Query Format

The system accepts **function-call-style queries**.

```text
semantic_facts(target_function="rndr_quote")
security_context(target_function="rndr_quote", call_depth=2, data_depth=4)
variable_flow(target_function="rndr_quote", symbol="text")
```


Each query type maps to a deterministic retrieval function over the precomputed CodeKG. The query engine does not execute the C/C++ program. It only retrieves graph-based source-code evidence.

---

## 2. Important Response Object

The important returned object is:

```text
result
```

A typical `result` has the following structure:

```json
{
  "kind": "semantic_facts",
  "args": {
    "target_function": "rndr_quote"
  },
  "node_count": 18,
  "edge_count": 22,
  "subgraph": {
    "nodes": [...],
    "edges": [...]
  }
}
```

The most important field is:

```text
result.subgraph.nodes
```

The `edges` field can be useful for understanding graph relationships, but the strongest source-code evidence is usually inside the returned nodes.

---

## 3. Source-Code Evidence in Nodes

Each node may contain source-code evidence.

Example:

```json
{
  "id": "stmt:...",
  "type": "Statement",
  "label": "Statement@264",
  "file": "ext/redcarpet/html.c",
  "function": "rndr_quote",
  "line_start": 264,
  "line_end": 264,
  "code": "escape_html(ob, text->data, text->size);",
  "attrs": {...}
}
```

The most relevant fields are:

| Field | Meaning |
|---|---|
| `type` | The kind of graph node, for example `Statement`, `Condition`, `Function`, or `SemanticFact` |
| `label` | A short label for the node |
| `file` | Source file where the code appears |
| `function` | Function associated with the node |
| `line_start` | First source-code line for this evidence |
| `line_end` | Last source-code line for this evidence |
| `code` | Source-code snippet or full function body |
| `attrs` | Additional metadata, especially for semantic facts |

The most important field is:

```text
code
```

---

## 4. How to Read Code Evidence

There are three common forms of returned code evidence.

### 4.1 Function Node Code

A `Function` node may contain a full multi-line function body.

Example:

```text
252 | static int
253 | rndr_quote(struct buf *ob, const struct buf *text, void *opaque)
254 | {
255 |     if (!text || !text->size)
256 |         return 0;
...
270 | }
```

The number before `|` is the original source-code line number.

For example:

```text
256 | return 0;
```

means:

```text
file: ext/redcarpet/html.c
line: 256
code: return 0;
```

This is important because the full function body often contains the clearest evidence for control flow, checks, returns, pointer use, and risky operations.

---

### 4.2 Statement or Fact Node Code

A `Statement`, `Condition`, `Assignment`, or `ReturnStatement` node usually contains a smaller code snippet.

Example:

```json
{
  "type": "Condition",
  "line_start": 256,
  "line_end": 256,
  "code": "if (!text || !text->size)"
}
```


### 4.3 SemanticFact Nodes

A `SemanticFact` node is not a raw source statement. It is an annotation created by the KG layer.

Example:

```json
{
  "type": "SemanticFact",
  "label": "null_check",
  "line_start": 256,
  "code": "if (!text || !text->size)",
  "attrs": {
    "rule_name": "null_check",
    "fact_type": "null_check",
    "detail": "Conditional expression resembles a null check.",
    "source_node_id": "stmt:..."
  }
}
```

This means:

```text
The system detected a semantic fact called null_check at line 256.
The corresponding code is: if (!text || !text->size)
```


---

## 5. Supported Query Types

The current system supports the following query types:

1. `function_context`
2. `semantic_facts`
3. `variable_flow`
4. `call_neighborhood`
5. `callers`
6. `callees`
7. `risk_slice`
8. `security_context`
9. `vulnerability_context`
10. `evidence_slice`
11. `file_context`
12. `shortest_path`

Each query type is described below.

---

## 5.1 `function_context`

### Query

```text
function_context(target_function="rndr_quote", depth=2)
```

### Parameters

| Parameter | Required | Default | Meaning |
|---|---:|---:|---|
| `target_function` | Yes | — | Function to inspect |
| `depth` | No | `2` | How far to expand the graph neighborhood |

### What It Does

Finds the target function node and retrieves a general graph neighborhood around it.

This gives broad context around the function, including nearby graph-connected nodes.

### Main Evidence to Inspect

```text
result.subgraph.nodes[*].code
```

Use this query when a broad first view of the function is needed.

---

## 5.2 `semantic_facts`

### Query

```text
semantic_facts(target_function="rndr_quote")
```

### Parameters

| Parameter | Required | Default | Meaning |
|---|---:|---:|---|
| `target_function` | Yes | — | Function whose semantic facts should be retrieved |

There are no additional required parameters.

### What It Does

Finds semantic annotations associated with the target function.

These facts may include:

```text
null_check
bounds_check
pointer_dereference
error_return
```

---

## 5.3 `variable_flow`

### Query

```text
variable_flow(target_function="rndr_quote", symbol="text", depth=3)
```

### Parameters

| Parameter | Required | Default | Meaning |
|---|---:|---:|---|
| `target_function` | Yes | — | Function where the symbol is inspected |
| `symbol` | Yes | — | Variable, parameter, global, or field name |
| `depth` | No | `3` | How far to expand data-related graph edges |

### What It Does

Finds variable-like nodes matching `symbol` in the target function, then follows data-related graph edges around that symbol.

In above case:
Find the graph node for the parameter text, then retrieve nearby data-flow/code evidence showing where text is used, checked, dereferenced, or passed into other calls.

It can retrieve evidence such as:

```text
where the symbol appears
where the symbol is used
where the symbol is defined
which statements reference the symbol
which semantic facts are connected to the symbol
```

### Main Evidence to Inspect

Relevant returned node types include:

```text
FunctionParameter
LocalVariable
GlobalVariable
Field
Statement
Assignment
Condition
SemanticFact
```

Use this query when the analysis depends on a specific variable, pointer, buffer, size, length, or field.

---

## 5.4 `call_neighborhood`

### Query

```text
call_neighborhood(target_function="rndr_quote", direction="both", depth=2)
```

### Parameters

| Parameter | Required | Default | Meaning |
|---|---:|---:|---|
| `target_function` | Yes | — | Function to inspect |
| `direction` | No | `"both"` | `"in"`, `"out"`, or `"both"` |
| `depth` | No | `2` | Call-graph expansion depth |

### What It Does

Retrieves call-related graph neighbors.

Use:

```text
direction="out"
```

to inspect functions called by the target.

Use:

```text
direction="in"
```

to inspect functions that call the target.

Use:

```text
direction="both"
```

to inspect both callers and callees.

---

## 5.5 `callers`

### Query

```text
callers(target_function="rndr_quote")
```

### Parameters

| Parameter | Required | Default | Meaning |
|---|---:|---:|---|
| `target_function` | Yes | — | Function whose callers should be retrieved |

### What It Does

Retrieves functions that call the target function.



---

## 5.6 `callees`

### Query

```text
callees(target_function="rndr_quote")
```

### Parameters

| Parameter | Required | Default | Meaning |
|---|---:|---:|---|
| `target_function` | Yes | — | Function whose callees should be retrieved |

### What It Does

Retrieves functions called by the target function.

---

## 5.7 `risk_slice`

### Query

```text
risk_slice(target_function="rndr_quote", risk_terms=["pointer", "bounds", "array"])
```

### Parameters

| Parameter | Required | Default | Meaning |
|---|---:|---:|---|
| `target_function` | Yes | — | Function to inspect |
| `risk_terms` | No | Default risk terms | Security-relevant terms used to filter evidence |

Default risk terms include:

```text
pointer
array
bounds
size
copy
read
write
allocation
free
null
return
```

### What It Does

Retrieves a focused security-relevant slice of the target function.

It includes function-body evidence and keeps nodes that are likely useful for vulnerability inspection, such as:

```text
statements
assignments
return statements
conditions
calls
variables
```


---

## 5.8 `security_context`

### Query

```text
security_context(
  target_function="rndr_quote",
  call_depth=2,
  data_depth=4,
  include_callers=true,
  include_headers=true,
  include_globals=true,
  include_joern=true,
  max_nodes=500
)
```

### Parameters

| Parameter | Required | Default | Meaning |
|---|---:|---:|---|
| `target_function` | Yes | — | Function to inspect |
| `call_depth` | No | `2` | How far to follow in-project callees |
| `data_depth` | No | `4` | How far to expand data-flow evidence |
| `include_callers` | No | `true` | Include functions that call the target |
| `include_headers` | No | `true` | Include header/type/macro/file context |
| `include_globals` | No | `true` | Include global variables connected to the function |
| `include_joern` | No | `true` | Include bounded Joern CPG overlay nodes |
| `joern_limit` | No | `160` | Maximum Joern overlay nodes |
| `joern_edge_limit` | No | `500` | Maximum Joern overlay edges |
| `max_nodes` | No | `500` | Maximum nodes retained in the returned result |
| `risk_terms` | No | Default risk terms | Terms used to prioritize security evidence |

### What It Does

This is the most complete retrieval query.

It finds the target function and retrieves:

```text
function body
variables
statements
semantic facts
globals
callers
callees
data-flow neighborhood
optional Joern overlay nodes
```


### Main Evidence to Inspect

This query can return many nodes. Focus on:

```text
result.subgraph.nodes[*].code
```

---

## 5.9 `vulnerability_context`

### Query

```text
vulnerability_context(target_function="rndr_quote", max_nodes=500)
```

### Parameters

Same as `security_context`.

### What It Does

In the current implementation, this query is an alias for `security_context`.

It retrieves the same kind of vulnerability-relevant evidence.

The naming is only given different, so that LLM can decide for the same calling, what is the intent of it ? like checking security or finding evidence, or finding vulnerability context.

---

## 5.10 `evidence_slice`

### Query

```text
evidence_slice(target_function="rndr_quote", max_nodes=500)
```

### Parameters

Same as `security_context`.

### What It Does

In the current implementation, this query is an alias for `security_context`.

It retrieves the same kind of evidence-oriented context.


---

## 5.11 `file_context`

### Query

```text
file_context(file="ext/redcarpet/html.c", depth=2)
```

### Parameters

| Parameter | Required | Default | Meaning |
|---|---:|---:|---|
| `file` | Yes | — | Source file path or file-path suffix |
| `depth` | No | `2` | Graph expansion depth |

### What It Does

Finds the file node and retrieves a graph neighborhood around the file.

This query is useful when the vulnerability may depend on file-level definitions, macros, types, includes, or globals.

---

## 5.12 `shortest_path`

### Query

```text
shortest_path(source_node="node_a", target_node="node_b")
```

### Parameters

| Parameter | Required | Default | Meaning |
|---|---:|---:|---|
| `source_node` | Yes | — | Source graph node id |
| `target_node` | Yes | — | Target graph node id |

### What It Does

Finds a short graph path between two known node ids.

This query is useful only after specific node ids from previous query results are known.

### Main Evidence to Inspect

Look at:

```text
result.subgraph.nodes
result.subgraph.edges
```

Use this query to track a compact relationship between two already-known nodes.

---