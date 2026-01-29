# SSH Security Monitoring & Analysis Pipeline (Archived)

## ⚠️ Project Status: Archived

This repository has been **archived** and is no longer under active development.

The functionality, concepts, and architecture described here have been **fully implemented and integrated into the Modular MOTD Health System**, which is now the **canonical and actively maintained project**.

👉 **Active Project:**
[https://github.com/mccrudd3n/Modular-MOTD-Health-System](https://github.com/mccrudd3n/Modular-MOTD-Health-System)

---

## Overview (Historical)

This project originally provided a robust, multi-stage system for monitoring, archiving, enriching, and reporting SSH login attempts on Linux servers. It was designed for:

* Security monitoring
* Data science workflows
* LLM- and ML-ready data pipelines

The system combined automated log collection with threat analysis and reporting, forming the foundation for what is now implemented in the MOTD Health System.

---

## Original Architecture

The pipeline followed a **three-stage architecture**, which has since been adapted and expanded within the MOTD project.

### Stage 1 – Data Collection

A lightweight Bash-based collector monitored SSH authentication logs and extracted:

* Timestamps
* Usernames (including invalid users)
* Source IP addresses
* Authentication results

Events were stored as structured **JSONL** files for long-term analysis.

---

### Stage 2 – Data Enrichment

A Python-based enrichment layer augmented raw SSH events with:

* ASN and organization data
* GeoIP location data
* Reverse DNS lookups
* Threat heuristics

Outputs were generated in **JSONL** and **Parquet** formats suitable for ML pipelines.

---

### Stage 3 – Security Reporting

Reporting components generated:

* Human-readable security summaries
* Structured JSON metrics
* Attack statistics and top offending IPs
* Configurable security scores

Optional integrations included Telegram notifications and dashboard ingestion.

---

## Key Features (Now in MOTD)

All of the following capabilities now exist **within the Modular MOTD Health System**, often in expanded or optimized form:

* Automated collection and archiving of SSH and system logs
* Detection of failed logins, invalid users, and brute-force attempts
* IP enrichment using ASN, GeoIP, and reverse DNS
* LLM- and ML-ready structured datasets
* Daily security overview reporting (text and JSON)
* Optional log rotation, pruning, and archival
* Configurable thresholds for scoring and alerting
* Fully decoupled, modular, and scalable design

---

## Migration Note

If you are:

* Looking to deploy SSH monitoring
* Interested in MOTD-based system health reporting
* Building security telemetry for automation or ML

➡️ **Use the Modular MOTD Health System instead of this repository.**

This repository remains available **for historical reference only**.