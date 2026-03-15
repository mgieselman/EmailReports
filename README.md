# Email Reports — DMARC & TLS-RPT Processor

Azure Function (Python v2, timer-triggered) that reads DMARC aggregate (RUA) and TLS-RPT reports from Microsoft 365 mailboxes via Graph API, parses them, and sends alerts to Teams and/or email.

## Prerequisites

- Python 3.11+
- Azure Functions Core Tools v4
- An Azure subscription (Consumption plan is fine)
- Microsoft 365 tenant with mailboxes for receiving reports

## Entra ID App Registration

1. Go to **Azure Portal → Entra ID → App registrations → New registration**
2. Name: `EmailReports-Function` (or similar)
3. Supported account type: **Single tenant**
4. Under **API permissions → Add a permission → Microsoft Graph → Application permissions**:
   - `Mail.Read` — read mail in all mailboxes (or use admin-scoped to specific mailboxes)
   - `Mail.ReadWrite` — needed to mark messages as read
   - `Mail.Send` — only if using the email alert feature
5. Click **Grant admin consent**
6. Under **Certificates & secrets**, create a new client secret and note the value

### Scoping to specific mailboxes (recommended)

Use an Exchange Online application access policy to restrict the app to only the report mailboxes:

```powershell
# Connect to Exchange Online
Connect-ExchangeOnline

# Create a mail-enabled security group containing only the report mailboxes
New-ApplicationAccessPolicy `
  -AppId "<your-client-id>" `
  -PolicyScopeGroupId "email-report-mailboxes@gieselman.com" `
  -AccessRight RestrictAccess `
  -Description "Restrict EmailReports function to report mailboxes only"
```

## Local Development

```bash
# Copy settings template
cp local.settings.json.example local.settings.json
# Fill in your Entra app credentials and other values

# Create virtual environment
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run locally
func start
```

## Configuration (Environment Variables)

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_TENANT_ID` | Yes | Entra tenant ID |
| `AZURE_CLIENT_ID` | Yes | App registration client ID |
| `AZURE_CLIENT_SECRET` | Yes | App registration client secret |
| `DMARC_MAILBOX` | Yes | UPN/email of the DMARC report mailbox |
| `TLSRPT_MAILBOX` | Yes | UPN/email of the TLS-RPT report mailbox |
| `TEAMS_WEBHOOK_URL` | Yes | Teams incoming webhook URL |
| `TIMER_SCHEDULE_CRON` | No | NCRONTAB schedule (default: every 30 min) |
| `ALERT_EMAIL_ENABLED` | No | `true` to also send email alerts |
| `ALERT_EMAIL_FROM` | No | Sender address for email alerts |
| `ALERT_EMAIL_TO` | No | Recipient address for email alerts |

## Deploy to Azure

```bash
# Create the Function App (one-time)
az functionapp create \
  --resource-group rg-emailreports \
  --consumption-plan-location eastus \
  --runtime python \
  --runtime-version 3.11 \
  --functions-version 4 \
  --name func-emailreports \
  --storage-account stemailreports

# Set app settings
az functionapp config appsettings set \
  --name func-emailreports \
  --resource-group rg-emailreports \
  --settings @appsettings.json

# Deploy
func azure functionapp publish func-emailreports
```

## DNS Records for gieselman.com

Make sure your domain has the correct DNS records so reports arrive:

```
# DMARC (adjust policy as needed)
_dmarc.gieselman.com  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@gieselman.com; ruf=mailto:dmarc-reports@gieselman.com; adkim=s; aspf=s"

# MTA-STS / TLS-RPT
_smtp._tls.gieselman.com  TXT  "v=TLSRPTv1; rua=mailto:tls-reports@gieselman.com"
```

## How It Works

1. Timer fires every 30 minutes (configurable)
2. Fetches unread messages from both mailboxes via Graph API
3. Extracts attachments (.xml, .xml.gz, .zip for DMARC; .json, .json.gz, .zip for TLS-RPT)
4. Parses reports into structured data
5. Builds alert summaries with severity (info/warning/critical)
6. Posts Adaptive Cards to Teams via webhook
7. Optionally sends HTML dashboard emails via Graph sendMail
8. Marks all processed messages as read
