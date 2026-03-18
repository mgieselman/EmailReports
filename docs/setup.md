# Setup Guide

## 1. Create the shared mailbox

In Exchange Admin Center, create a shared mailbox (e.g., `emailreports@yourdomain.com`) with aliases for:
- `dmarc-reports@yourdomain.com`
- `tls-reports@yourdomain.com`

## 2. Configure DNS records

```
# DMARC — adjust p= policy to your needs (none → quarantine → reject)
_dmarc.yourdomain.com  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc-reports@yourdomain.com; adkim=s; aspf=s"

# TLS-RPT
_smtp._tls.yourdomain.com  TXT  "v=TLSRPTv1; rua=mailto:tls-reports@yourdomain.com"
```

## 3. Create the Entra ID app registration

```bash
# Create the app
az ad app create --display-name "EmailReports" --sign-in-audience "AzureADMyOrg"

# Note the appId from the output, then add Graph permissions
APP_ID="<your-app-id>"
GRAPH="00000003-0000-0000-c000-000000000000"

az ad app permission add --id $APP_ID --api $GRAPH --api-permissions "810c84a8-4a9e-49e6-bf7d-12d183f40d01=Role"  # Mail.Read
az ad app permission add --id $APP_ID --api $GRAPH --api-permissions "e2a3a72e-5f79-4c64-b1b1-878b674786c9=Role"  # Mail.ReadWrite
az ad app permission add --id $APP_ID --api $GRAPH --api-permissions "b633e1c5-b582-4048-a93e-9f11b44c7e96=Role"  # Mail.Send (optional, for email alerts)

# Grant admin consent
az ad app permission admin-consent --id $APP_ID

# Create a client secret (1 year expiry)
az ad app credential reset --id $APP_ID --append --display-name "func-emailreports" --years 1
```

### Scope permissions to the shared mailbox only (recommended)

By default, `Mail.Read` grants access to all mailboxes in your tenant. Use an Exchange application access policy to restrict it:

```powershell
Connect-ExchangeOnline

New-ApplicationAccessPolicy `
  -AppId "<your-app-id>" `
  -PolicyScopeGroupId "emailreports-security-group@yourdomain.com" `
  -AccessRight RestrictAccess `
  -Description "Restrict EmailReports to shared mailbox only"
```

## 4. Deploy Azure resources

```bash
# Resource group
az group create --name rg-emailreports --location <your-region>

# Storage account (used by function runtime + report tracking)
az storage account create --name stemailreports --resource-group rg-emailreports --sku Standard_LRS

# Function App (Flex Consumption)
az functionapp create \
  --name func-emailreports \
  --resource-group rg-emailreports \
  --storage-account stemailreports \
  --flexconsumption-location <your-region> \
  --runtime python \
  --runtime-version 3.12

# Key Vault (store client secret here, not in app settings)
az keyvault create --name kv-emailreports --resource-group rg-emailreports

# Enable managed identity and grant it Key Vault access
PRINCIPAL_ID=$(az functionapp identity assign --name func-emailreports --resource-group rg-emailreports --query principalId -o tsv)

az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee-object-id $PRINCIPAL_ID \
  --assignee-principal-type ServicePrincipal \
  --scope $(az keyvault show --name kv-emailreports --query id -o tsv)

# Store the client secret
az keyvault secret set --vault-name kv-emailreports --name AzureClientSecret --value "<your-client-secret>"
```

## 5. Configure app settings

See [Configuration Reference](configuration.md) for all variables. Set them via:

```bash
az functionapp config appsettings set --name func-emailreports --resource-group rg-emailreports --settings \
  "AZURE_TENANT_ID=<your-tenant-id>" \
  "AZURE_CLIENT_ID=<your-app-id>" \
  "AZURE_CLIENT_SECRET=@Microsoft.KeyVault(SecretUri=https://kv-emailreports.vault.azure.net/secrets/AzureClientSecret/)" \
  "REPORT_MAILBOX=emailreports@yourdomain.com" \
  "DMARC_ALIAS=dmarc-reports@yourdomain.com" \
  "TLSRPT_ALIAS=tls-reports@yourdomain.com" \
  "TIMER_SCHEDULE_CRON=0 */30 * * * *"
```

## 6. Deploy the code

### Option A: GitHub Actions (recommended)

1. Fork this repo
2. Create a service principal for deployment:
   ```bash
   az ad sp create-for-rbac \
     --name "github-deploy-emailreports" \
     --role Contributor \
     --scopes "/subscriptions/<sub-id>/resourceGroups/rg-emailreports" \
     --sdk-auth
   ```
3. Add the JSON output as a GitHub secret named `AZURE_CREDENTIALS`
4. Update `app-name` in `.github/workflows/deploy.yml` to match your Function App name
5. Push to `main` — CI runs tests, then deploys automatically

### Option B: Manual deploy

```bash
pip install -r requirements.txt --target=".python_packages/lib/site-packages"
zip -r deploy.zip . -x ".git/*" ".github/*" ".venv/*" "tests/*"
az functionapp deploy --name func-emailreports --resource-group rg-emailreports --src-path deploy.zip --type zip
```

## 7. Teams webhook (optional)

1. In Teams, right-click the target channel
2. Select **Workflows** > **Post to a channel when a webhook request is received**
3. Copy the webhook URL into your `TEAMS_WEBHOOK_URL` app setting
