SSH Security Monitoring & Analysis Pipeline
Overview

This project provides a robust, multi-stage system to monitor, archive, enrich, and report SSH login attempts on Linux servers. It is designed for data science, security monitoring, and LLM-ready data pipelines, combining automated log collection with threat analysis.

The pipeline follows a three-stage architecture:

Stage 1 – Data Collection:
Lightweight Bash script collects SSH authentication events, including timestamps, usernames, source IPs, and results, saving them as structured JSONL files for long-term storage and analysis.

Stage 2 – Data Enrichment:
Python script enriches the raw data with intelligence such as ASN, GeoIP, reverse DNS lookups, and threat heuristics. Outputs machine-learning-ready datasets in JSONL and Parquet formats.

Stage 3 – Security Reporting:
Generates human-readable security reports and structured JSON summaries, including attack metrics, top attacking IPs, and security scores. Can integrate with Telegram notifications or dashboards.

Features

Collects and archives SSH logs and system logs automatically

Tracks failed login attempts, invalid users, and brute-force attacks

Enriches IPs with ASN, GeoIP, and reverse DNS lookups

Produces LLM- and ML-ready structured datasets

Generates daily security overview reports (TXT + JSON)

Optional automation for log rotation, deletion, and archiving

Configurable thresholds for security scoring

Fully decoupled pipeline for performance and scalability

Test