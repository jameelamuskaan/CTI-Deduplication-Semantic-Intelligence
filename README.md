# CTI Sentinel: Cyber Threat Intelligence Deduplication and Semantic Intelligence Sharing

A standalone **Java Swing** desktop application that finds duplicate and related Cyber Threat Intelligence (CTI) records from different providers, without wrongly merging distinct campaigns. Built for **CS213 Advanced JAVA Programming** (SRM University–AP).

> **Scope note:** this version is standalone and **in-memory**. It does not connect to JDBC, SQLite or MySQL, and data resets when the application closes. The evaluation uses a tiny seeded synthetic example to demonstrate the workflow. It is **not** a benchmark result and is not evidence of performance on live threat feeds.

---

## Why this project

Different providers often describe the same threat in different words, formats and indicator styles. Analysts then read the same intelligence many times. Merging blindly is also risky, because two different campaigns can reuse the same infrastructure. CTI Sentinel scores record pairs using several kinds of evidence and merges only when the evidence is strong, while keeping the source of every record.

## Features

- Dark cybersecurity-analyst interface with sidebar navigation
- Dashboard with KPI cards, a classification bar chart and a provider donut chart
- In-memory CTI record management: add, search, sort and export to CSV
- Defanged-text normalisation (for example `hxxp://evil[.]com`) and basic IOC extraction
- Hybrid similarity scoring that combines:
  - TF-IDF cosine similarity
  - IOC Jaccard overlap
  - entity agreement
  - exact-text match
- Concurrent pairwise scoring with `ExecutorService`
- Classification of each pair as **DUPLICATE**, **RELATED** or **UNRELATED**
- **Entity-conflict guard:** pairs that name conflicting actors or malware are not labelled DUPLICATE
- Analyst review and **non-destructive merge history** with IOC source provenance
- Synthetic demonstration evaluation

## How it works

```
Records -> Normalise text and IOCs -> Pairwise scoring (thread pool)
        -> Classify (DUPLICATE / RELATED / UNRELATED)
        -> Analyst review -> Non-destructive merge with provenance
```

1. **Normalise:** defanged indicators are restored to plain text, and IOCs (such as IPs, domains and hashes) are extracted.
2. **Score:** each record pair gets a combined score from TF-IDF cosine, IOC Jaccard, entity agreement and exact-text match. Pairs are scored in parallel.
3. **Classify:** the score decides DUPLICATE, RELATED or UNRELATED. If both records name entities and the entities conflict, the pair cannot become DUPLICATE.
4. **Review and merge:** the analyst accepts or rejects. A merge keeps both source records and logs where each IOC came from.

## Java concepts demonstrated

| Concept | Where it appears |
| --- | --- |
| GUI | Swing (sidebar, dashboard, charts, tables, dialogs) |
| Multithreading | `ExecutorService` for concurrent pairwise scoring |
| Collections | Maps and sets for term vectors, IOCs and entities |
| Streams | Filtering, sorting and grouping of records and results |
| File I/O | CSV export |
| OOP | Record and result classes, classification logic |

## Requirements

- JDK 21 or later (tested with JDK 21)
- Optional: VS Code with the *Extension Pack for Java*. Command-line build works without it.

## Build and run

From the repository folder.

**Windows (PowerShell):**

```powershell
javac -encoding UTF-8 -d out src\CtiAdvancedApp.java
java -cp out CtiAdvancedApp
```

**macOS / Linux:**

```bash
javac -encoding UTF-8 -d out src/CtiAdvancedApp.java
java -cp out CtiAdvancedApp
```

You can also run `run.bat` on Windows, or open `src/CtiAdvancedApp.java` in VS Code and press **Run**.

## Repository structure

```
CTI-Deduplication-Semantic-Intelligence/
├── src/
│   └── CtiAdvancedApp.java    # application source
├── .vscode/                   # VS Code settings
├── run.bat                    # Windows build-and-run script
├── SELF_TESTS.txt             # self-test notes
├── .gitignore
└── README.md
```

## Screenshots

Add screenshots to a `docs/screenshots/` folder and link them here.

| Screen | Preview |
| --- | --- |
| Dashboard | `![Dashboard](docs/screenshots/dashboard.png)` |
| Record management | `![Records](docs/screenshots/records.png)` |
| Analyst review and merge | `![Review](docs/screenshots/review.png)` |

## Limitations

- Data is held in memory only and is lost when the application closes.
- The evaluation ground truth is deliberately limited to the seeded R001/R002 duplicate pair, so the numbers are for demonstration only.
- Similarity is mostly lexical, so records that describe the same event with very different wording can be missed.
- The IOC extractor is basic and covers only common indicator types.

## Future work

- Persist data with JDBC (SQLite or MySQL)
- Import STIX 2.1 JSON (MITRE ATT&CK) and APTnotes reports
- Add Sentence-BERT embeddings as an extra similarity signal
- Evaluate on a larger annotated pair set with precision, recall, F1 and false-merge rate
- Export merged intelligence back to STIX with provenance preserved

## Safety and data

This repository is a source-code demonstration. Do not add real threat-feed credentials, private reports or sensitive indicators. Indicators are treated as plain text and are never resolved, opened or executed.
