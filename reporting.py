import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Tuple, Optional


# -------------------------------
# Dataclasses for clean structure
# -------------------------------
@dataclass
class AttackMetrics:
    total_attempts: int
    failed_logins: int
    ufw_total: int
    fail2ban_total: int
    log_size_mb: float
    journal_size_mb: float
    archive_count: int
    archive_size: str


@dataclass
class DetectionThresholds:
    high_attack_threshold: int
    moderate_attack_threshold: int
    large_log_threshold: int
    large_journal_threshold: int


@dataclass
class ReportContext:
    ssh_data: List[Dict]
    sorted_ips: List[Tuple[str, int]]
    ufw_blocks: List[str]
    fail2ban_bans: List[str]
    actions_taken: List[str]
    largest_logs: List[str]
    database_path: str
    report_dir: str
    report_file: str


# -------------------------------
# Helper: Determine threat severity
# -------------------------------
def classify_severity(metrics: AttackMetrics, t: DetectionThresholds) -> str:
    if (metrics.total_attempts >= t.high_attack_threshold or
        metrics.log_size_mb >= t.large_log_threshold or
        metrics.journal_size_mb >= t.large_journal_threshold):
        return "High"

    if metrics.total_attempts >= t.moderate_attack_threshold:
        return "Moderate"

    return "Low"


# -------------------------------
# Main Report Generator
# -------------------------------
def generate_report(
    metrics: AttackMetrics,
    ctx: ReportContext,
    thresholds: DetectionThresholds
):
    try:
        Path(ctx.report_dir).mkdir(parents=True, exist_ok=True)

        severity = classify_severity(metrics, thresholds)

        # -------------------------------
        # Human-readable report assembly
        # -------------------------------
        report_lines = [
            f"*Security Report – {Path(ctx.report_file).stem.split('_')[0]}*",
            "---",
            f"*Threat Level*: {severity}",
            "No significant threats detected." if severity == "Low" else "Monitor closely.",
            "\n*Key Metrics*",
            f"- SSH Attempts: {metrics.total_attempts}",
            f"- Firewall Blocks: {metrics.ufw_total}",
            f"- Fail2Ban Bans: {metrics.fail2ban_total}",
            f"- Failed Logins: {metrics.failed_logins}",
            "\n*Recent Fail2Ban Blocks*"
        ]

        # Fail2ban recent
        if ctx.fail2ban_bans:
            for ban in ctx.fail2ban_bans[:3]:
                ip, timestamp = ban.split(" at ")
                date = timestamp.split()[0]
                report_lines.append(f"- {ip} ({date})")
        else:
            report_lines.append("- None")

        # Top IPs
        report_lines.append("\n*Top Blocked IPs*")

        if ctx.sorted_ips:
            for ip, attempts in ctx.sorted_ips[:5]:
                report_lines.append(f"- {ip}: {attempts} attempts")
        else:
            report_lines.append("- No IP data available")

        report_lines.extend([
            "\n*Log Status*",
            f"- Log Size: {metrics.log_size_mb} MB",
            f"- Journal Size: {metrics.journal_size_mb} MB",
            f"- Archives: {metrics.archive_count} ({metrics.archive_size})",
            "\n*Actions Taken*",
            f"- {ctx.actions_taken[-1] if ctx.actions_taken else 'None'}",
            "\n*Note:*",
            "Use /logs for details.",
            "Use /start for new report."
        ])

        # -------------------------------
        # Write human-readable report
        -------------------------------
        with open(ctx.report_file, "w") as f:
            f.write("\n".join(report_lines))

        # -------------------------------
        # Write machine-readable JSON
        -------------------------------
        json_path = ctx.report_file.replace(".txt", ".json")

        enriched_json = {
            "severity": severity,
            "metrics": metrics.__dict__,
            "ip_summary": [
                {"ip": ip, "attempts": attempts} for ip, attempts in ctx.sorted_ips
            ],
            "fail2ban_recent": ctx.fail2ban_bans,
            "largest_logs": ctx.largest_logs,
            "actions_taken": ctx.actions_taken,
            "database_used": ctx.database_path,
        }

        with open(json_path, "w") as jf:
            json.dump(enriched_json, jf, indent=4)

        logging.info(f"Report generated: {ctx.report_file}")
        logging.info(f"Machine-readable file: {json_path}")

    except Exception as e:
        logging.error(f"Report generation failed: {e}")
