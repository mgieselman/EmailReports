# Configuration Reference

All configuration is via environment variables (Azure Function App Settings).

## Required

| Variable | Description |
|----------|-------------|
| `AZURE_TENANT_ID` | Entra tenant ID |
| `AZURE_CLIENT_ID` | App registration client ID |
| `AZURE_CLIENT_SECRET` | Client secret (use a [Key Vault reference](https://learn.microsoft.com/en-us/azure/app-service/app-service-key-vault-references)) |
| `REPORT_MAILBOX` | Shared mailbox address (e.g., `emailreports@yourdomain.com`) |

## Report Processing

| Variable | Default | Description |
|----------|---------|-------------|
| `DMARC_ALIAS` | *(blank)* | Alias that receives DMARC reports (e.g., `dmarc-reports@yourdomain.com`). Both blank = fallback mode (try both parsers) |
| `TLSRPT_ALIAS` | *(blank)* | Alias that receives TLS-RPT reports (e.g., `tls-reports@yourdomain.com`) |
| `MAIL_FOLDER` | *(blank = Inbox)* | Read from this folder instead of Inbox |
| `TIMER_SCHEDULE_CRON` | `0 */30 * * * *` | How often to check for new reports ([NCRONTAB format](https://learn.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer#ncrontab-expressions)) |
| `DELETE_AFTER_DAYS` | `-1` | Delete read messages after N days. `0` = delete immediately after processing, `-1` = never delete |
| `MOVE_PROCESSED_TO` | *(blank)* | Move processed messages to this folder (e.g., `Processed`). Ignored when `DELETE_AFTER_DAYS=0` |

## Alert Channels

All alert channels are optional. Configure one or more:

| Variable | Default | Description |
|----------|---------|-------------|
| `TEAMS_WEBHOOK_URL` | *(blank)* | Teams incoming webhook URL. Blank to disable |
| `GENERIC_WEBHOOK_URL` | *(blank)* | HTTP POST endpoint. Sends JSON with `title`, `severity`, `body`, `timestamp`. Works with Slack, Discord, n8n, Power Automate |
| `ALERT_EMAIL_ENABLED` | `false` | Set to `true` to enable email alerts via Graph sendMail |
| `ALERT_EMAIL_FROM` | — | Sender address (must be the shared mailbox or an alias on it) |
| `ALERT_EMAIL_TO` | — | Recipient address for alerts |

## Weekly Summary

| Variable | Default | Description |
|----------|---------|-------------|
| `SUMMARY_ENABLED` | `false` | Set to `true` to enable the periodic summary email |
| `SUMMARY_SCHEDULE_CRON` | `0 0 9 * * 1` | When to send the summary (default: Monday 9am UTC) |
| `SUMMARY_DAYS` | `7` | Lookback period in days |

The summary includes:
- Total DMARC and TLS-RPT reports received
- Pass/fail rates for both protocols with week-over-week trend indicators
- Top reporting sources ranked by volume with per-org failure breakdown
- DMARC policy distribution (none/quarantine/reject) with rollout context
- Aggregated DMARC failure details grouped by reporting organization
- Aggregated TLS-RPT failure details
- Top failure sources
- Total attachment volume processed

See [Report Interpretation Guide](report-interpretation.md) for how to read and act on these reports.

Summary data is stored in Azure Table Storage using the function app's system-assigned managed identity. When `AzureWebJobsStorage__accountName` is set, `storage.py` authenticates via `DefaultAzureCredential`. For local development, set `AzureWebJobsStorage` to a connection string instead.

## Abuse Reporting

When enabled, the system automatically sends abuse reports to hosting providers whose servers are used to spoof your domain. Reports are sent when DMARC records show confirmed spoofing (SPF=fail, DKIM=fail, disposition=reject).

| Variable | Default | Description |
|----------|---------|-------------|
| `ABUSE_REPORTING_ENABLED` | `false` | Set to `true` to enable automated abuse reports |

When enabled:
- Two emails are sent per offending IP: a plain-text abuse report and an ARF (RFC 5965) formatted report
- The abuse contact is looked up dynamically via RDAP for each source IP
- Reports are deduplicated — each source IP is reported at most once per week
- Emails are sent from `postmaster@{domain}` where domain is the spoofed domain from the DMARC report
- The original DMARC aggregate report XML is attached as evidence
- The weekly summary includes a count of abuse reports sent

**Prerequisite:** The `postmaster@` address must be an alias on the shared mailbox (or a mailbox the app registration has `Mail.Send` permission for).

## Configuration Interactions

- **`DELETE_AFTER_DAYS=0` + `MOVE_PROCESSED_TO`**: Immediate delete takes priority. Messages are deleted, not moved.
- **`DELETE_AFTER_DAYS=30` + `MOVE_PROCESSED_TO=Processed`**: Messages are moved to "Processed" after parsing, then deleted from "Processed" after 30 days.
- **`DMARC_ALIAS` and `TLSRPT_ALIAS` both blank**: All messages are parsed with both parsers (fallback mode).
- **`SUMMARY_ENABLED=true` with no report data**: Summary is silently skipped if no reports were processed in the lookback period.
- **`ABUSE_REPORTING_ENABLED=true`**: Abuse reports are sent after normal alert delivery. Failures in abuse reporting do not affect normal alert processing.
