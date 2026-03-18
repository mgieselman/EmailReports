# Monitoring Guide

The function has three layers of failure detection, from fastest to most comprehensive.

## 1. In-code error notifications (instant)

If the function throws an unhandled exception, it:
1. Logs the full traceback to Application Insights
2. Sends a **CRITICAL** alert to Teams and/or generic webhook with the error
3. Re-raises so Azure marks the execution as failed

Per-message error handling ensures one bad message doesn't skip the rest. If 3 out of 10 messages fail, the other 7 still get processed and alerted.

Alert delivery also has per-alert error handling — a failed Teams webhook won't prevent the email alert from sending.

## 2. Azure Monitor metric alerts (within minutes)

Set up an alert to detect when the function stops running:

```bash
# Create an action group (who gets notified)
az monitor action-group create \
  --name "emailreports-alerts" \
  --resource-group rg-emailreports \
  --short-name "EmailRpts" \
  --action email admin admin@yourdomain.com

SCOPE="/subscriptions/<sub-id>/resourceGroups/rg-emailreports/providers/Microsoft.Web/sites/func-emailreports"
ACTION_GROUP="/subscriptions/<sub-id>/resourceGroups/rg-emailreports/providers/microsoft.insights/actionGroups/emailreports-alerts"

# Alert if function stops running entirely
az monitor metrics alert create \
  --name "EmailReports-No-Executions" \
  --resource-group rg-emailreports \
  --scopes "$SCOPE" \
  --condition "total OnDemandFunctionExecutionCount < 1" \
  --window-size 1h \
  --evaluation-frequency 30m \
  --severity 2 \
  --action "$ACTION_GROUP" \
  --description "Function has not executed in over 1 hour"
```

## 3. Application Insights (full history)

All logs, exceptions, and traces are stored in App Insights automatically. Access via **Azure Portal > Application Insights > Logs**.

### Useful KQL queries

```kusto
// All function runs
traces
| where message contains "Executed"
| project timestamp, message
| order by timestamp desc

// Exceptions with full stack traces
exceptions
| order by timestamp desc
| take 10

// Processing summary over time
traces
| where message contains "Run complete"
| project timestamp, message
| order by timestamp desc

// Reports processed per day
traces
| where message contains "Parsed report"
| summarize count() by bin(timestamp, 1d)
| render columnchart
```

## Verifying the function is running

### Azure Portal

**Function App > Functions > process_email_reports > Monitor** shows invocation history with success/failure status.

### Azure CLI

```bash
# Check app state
az functionapp show --name func-emailreports --resource-group rg-emailreports --query "state"

# Manually trigger
MASTER_KEY=$(az functionapp keys list --name func-emailreports --resource-group rg-emailreports --query "masterKey" -o tsv)
curl -X POST "https://func-emailreports.azurewebsites.net/admin/functions/process_email_reports" \
  -H "x-functions-key: $MASTER_KEY" \
  -H "Content-Type: application/json" \
  -d '{}'
```

### Temporarily increase frequency

To verify the timer is working, temporarily set it to every 1 minute:

```bash
az functionapp config appsettings set --name func-emailreports --resource-group rg-emailreports --settings "TIMER_SCHEDULE_CRON=0 */1 * * * *"
```

Check App Insights after 5 minutes for 5 runs, then set it back:

```bash
az functionapp config appsettings set --name func-emailreports --resource-group rg-emailreports --settings "TIMER_SCHEDULE_CRON=0 */30 * * * *"
```
