# CTI Sentinel — Advanced Java Demonstration

A standalone Swing desktop prototype for **CTI Deduplication and Semantic Intelligence Sharing**.

## Requirements
- JDK 21 or later (tested with JDK 21; also suitable for JDK 27)
- VS Code with Extension Pack for Java (optional; command-line build works)

## Run in VS Code terminal (PowerShell)
From this folder:

```powershell
javac -encoding UTF-8 -d out src\CtiAdvancedApp.java
java -cp out CtiAdvancedApp
```

Or open `src/CtiAdvancedApp.java` and use Run.

## Features
- Dark cybersecurity analyst interface with sidebar navigation
- Dashboard KPI cards, classification bar chart and provider donut chart
- In-memory CTI record management, search, sorting and CSV export
- Defanged-text normalisation and basic IOC extraction
- TF-IDF cosine, IOC Jaccard, entity agreement and exact-text hybrid scoring
- Concurrent pairwise scoring using ExecutorService
- DUPLICATE / RELATED / UNRELATED classification and entity conflict guard
- Analyst review and non-destructive merge history with IOC source provenance
- Synthetic demonstration evaluation

## Important scope note
This version is **standalone and in-memory**. It does not connect to JDBC, SQLite or MySQL, and data resets when the application closes. Evaluation uses a tiny seeded synthetic example and is for demonstrating the workflow only; it is not a benchmark result or evidence of performance on live threat feeds. The evaluation ground truth is deliberately limited to the seeded R001/R002 duplicate pair.

## GitHub
The repository is safe to publish as a source-code demonstration. Do not add real threat feed credentials, private reports, or sensitive indicators.
