# Sariel

**Sariel is a proactive cybersecurity attack-path platform that models, predicts, and explains how adversaries move through your environment—before they do.**

---

## High-Level Architecture

```mermaid
flowchart LR
    A[Data Sources] --> B[Ingestion Layer]
    B --> C[Normalization Engine]
    C --> D[Neo4j Graph]
    D --> E[Context Builder]
    E --> F[AI Attack Mapper]
    F --> G[Validation Layer]
    G --> H[Suggested Edges]
    H --> I[Analyst Review]
    I --> J[Confirmed Attack Paths]
```

---

## Attack Path Flow

```mermaid
flowchart LR
    A[Compromise Initial Host] --> B[Exploit or Access]
    B --> C[Credential Discovery]
    C --> D[Lateral Movement]
    D --> E[Privilege Escalation]
    E --> F[Target System]
```

---

## Graph Model

```mermaid
graph TD
    A[Asset] -->|HAS_VULN| V[Vulnerability]
    A -->|EXPOSES_SERVICE| S[Service]
    A -->|MEMBER_OF| I[Identity]
    A -->|RUNS_SERVICE| S
    A -->|SUGGESTS_LATERAL_MOVE| B[Asset]
```

---

## AI Mapping Pipeline

```mermaid
flowchart LR
    A[Neo4j Graph] --> B[Context Builder]
    B --> C[LLM Reasoning]
    C --> D[Structured JSON]
    D --> E[Validator]
    E --> F[SUGGESTS_* Edges]
```

---

## Confidence Model

```mermaid
flowchart TD
    A[AI Confidence] --> D[Final Score]
    B[Graph Evidence] --> D
    C[Exploitability Data] --> D
    E[Environment Signals] --> D
```

---

## Example Attack Path

```mermaid
flowchart LR
    G[Genetec-06] --> S[SMB Exposure]
    S --> T[CH-TYLER-SQL-01]
    T --> L[Log4j Vulnerability]
    L --> GIS[GIS-GEO-ARC-01]
```

---

## Vision

Security teams should know the attacker’s path **before the attacker takes it.**
