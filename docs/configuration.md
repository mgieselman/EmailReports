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
- Pass/fail rates for both protocols
- Top reporting sources ranked by volume
- DMARC policy distribution (none/quarantine/reject)
- Top failure sources
- Total attachment volume processed

Summary data is stored in Azure Table Storage (using the same storage account as the function runtime — no additional cost).

## Configuration Interactions

- **`DELETE_AFTER_DAYS=0` + `MOVE_PROCESSED_TO`**: Immediate delete takes priority. Messages are deleted, not moved.
- **`DELETE_AFTER_DAYS=30` + `MOVE_PROCESSED_TO=Processed`**: Messages are moved to "Processed" after parsing, then deleted from "Processed" after 30 days.
- **`DMARC_ALIAS` and `TLSRPT_ALIAS` both blank**: All messages are parsed with both parsers (fallback mode).
- **`SUMMARY_ENABLED=true` with no report data**: Summary is silently skipped if no reports were processed in the lookback period.
