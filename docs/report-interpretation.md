# Report Interpretation Guide

This guide explains what each metric in the email reports means and how to interpret them.

## Report Types

The system generates three types of reports:

1. **DMARC Aggregate Reports** — per-report alerts showing authentication results for your domain
2. **TLS-RPT Reports** — per-report alerts showing TLS delivery success/failure
3. **Weekly Summary** — a digest of all reports from the past period

## Severity Levels

All reports include a severity badge:

| Severity | Threshold | Meaning |
|----------|-----------|---------|
| **ALL CLEAR** (green) | No failures | All messages/sessions passed authentication |
| **WARNING** (orange) | Failures exist, but <= 10% | Some failures detected; investigate but not urgent |
| **CRITICAL** (red) | > 10% failure rate | Significant authentication failures; immediate attention needed |

### What to do at each level

- **ALL CLEAR**: No action needed. Your email authentication is working correctly.
- **WARNING**: Review the failure details. A small number of failures from unknown IPs is normal (spoofing attempts being correctly rejected). Failures from your own infrastructure require investigation.
- **CRITICAL**: Investigate immediately. Check if a legitimate sending service lost its DKIM key, if an SPF record was misconfigured, or if a TLS certificate expired.

---

## DMARC Aggregate Reports

DMARC (Domain-based Message Authentication, Reporting, and Conformance) reports are sent by receiving mail servers to tell you how messages claiming to be from your domain performed against your DMARC policy.

### Subtitle Fields

| Field | Meaning |
|-------|---------|
| **Reporter** | The organization that sent this report (e.g., google.com, microsoft.com) |
| **Domain** | Your protected domain that the report covers |
| **Period** | The date range this report covers (usually 24 hours) |
| **DKIM Alignment** | **Strict**: the DKIM signing domain must exactly match the From header domain. **Relaxed**: the signing domain can be a subdomain of the From header domain. Relaxed is more forgiving and is the default per RFC 7489 |
| **SPF Alignment** | **Strict**: the envelope sender (MAIL FROM) domain must exactly match the From header domain. **Relaxed**: it can be a subdomain. Relaxed is the default |
| **Subdomain Policy** | Only shown when it differs from the main policy. This is the DMARC policy applied to messages from subdomains of your domain |
| **Sampling** | Only shown when below 100%. Indicates the percentage of failing messages the receiver applies the policy to. During DMARC rollout, you might set `pct=25` to only quarantine/reject 25% of failures while monitoring |

### Stat Cards

| Card | Meaning |
|------|---------|
| **Total Messages** | Total number of messages the reporter saw claiming to be from your domain |
| **Passing** | Messages where at least one authentication method (DKIM or SPF) passed with alignment |
| **Failing** | Messages where **both** DKIM and SPF failed. These are the messages most likely to be spoofed |
| **Pass Rate** | Percentage of messages that are not fully failing. Green at 100%, orange otherwise |
| **Policy** | Your published DMARC policy: `NONE` (monitor only), `QUARANTINE` (send to spam), or `REJECT` (block delivery) |

### Partial Auth Failures

When present, a line above the record table shows:
- **DKIM-only failures**: Messages where DKIM failed but SPF passed. Common when a third-party sender (e.g., a marketing platform) sends on your behalf but doesn't have your DKIM key
- **SPF-only failures**: Messages where SPF failed but DKIM passed. Common when messages are forwarded (forwarding changes the envelope sender, breaking SPF)

These are not counted as "failing" for severity purposes because one authentication method still passed, but they indicate areas for improvement.

### Record Table

Each row represents a group of messages from a specific source IP:

| Column | Meaning |
|--------|---------|
| **Source IP** | The IP address that sent the messages |
| **Count** | How many messages came from this IP |
| **Disposition** | What the receiver did: `NONE` (delivered normally), `QUARANTINE` (sent to spam), `REJECT` (blocked) |
| **DKIM** | Whether DKIM authentication passed or failed for this source |
| **SPF** | Whether SPF authentication passed or failed for this source |
| **DKIM Domain** | The domain that signed the message with DKIM. Helps identify which service is sending. Empty if no DKIM signature was present |
| **SPF Domain** | The domain used in the SPF check (the envelope sender). Helps identify who the message claims to be from at the SMTP level |
| **Header From** | The domain in the visible From header that recipients see |
| **Envelope From** | The SMTP envelope sender (MAIL FROM). May differ from Header From for forwarded mail or third-party senders |

### How to investigate failures

1. **Unknown source IPs with both DKIM+SPF failing**: Likely spoofing attempts. If your policy is `reject`, these are being blocked — no action needed.
2. **Known source IPs (your servers, your ESP) failing**: Check that DKIM keys are correctly configured and that the sending IP is in your SPF record.
3. **DKIM Domain doesn't match your domain**: A third-party service is signing with their own key. Set up DKIM delegation so they sign with your domain.
4. **Envelope From differs from Header From**: Common with SaaS senders. Ensure the sending service is in your SPF record or uses DKIM signing for your domain.

---

## TLS-RPT Reports

TLS-RPT (SMTP TLS Reporting) reports tell you whether other mail servers were able to establish secure TLS connections when delivering mail to your domain.

### Stat Cards

| Card | Meaning |
|------|---------|
| **Total Sessions** | Total number of SMTP sessions attempted |
| **Successful** | Sessions where TLS was successfully negotiated |
| **Failed** | Sessions where TLS negotiation failed |
| **Success Rate** | Percentage of successful sessions. Green at 100%, orange otherwise |

### Record Table

| Column | Meaning |
|--------|---------|
| **Domain** | The domain the policy applies to |
| **Policy** | The policy type: `STS` (MTA-STS) or `TLSA` (DANE) |
| **Result** | The failure type, or `SUCCESSFUL` if no failures |
| **Sending MTA** | The IP of the server that tried to send mail to you |
| **MX Host** | Your receiving mail server's hostname |
| **Receiving IP** | The IP address of your receiving mail server. Useful when an MX hostname resolves to multiple IPs with different TLS configurations |
| **Failed** | Number of failed sessions with this specific failure |
| **Reason** | Human-readable description of the failure |

### Common failure types

| Result Type | Meaning | Action |
|-------------|---------|--------|
| `certificate-expired` | Your TLS certificate has expired | Renew the certificate immediately |
| `certificate-not-trusted` | Your certificate isn't trusted by the sender's CA store | Check your certificate chain is complete |
| `starttls-not-supported` | Your server doesn't support STARTTLS | Enable STARTTLS on your mail server |
| `validation-failure` | The certificate doesn't match the expected hostname | Ensure your cert covers all MX hostnames |
| `sts-policy-fetch-error` | The sender couldn't fetch your MTA-STS policy | Check that your `mta-sts.yourdomain.com` is accessible |
| `sts-webpki-invalid` | Your MTA-STS policy endpoint has a certificate issue | Fix the HTTPS certificate on your MTA-STS endpoint |

---

## Weekly Summary

The weekly summary aggregates data from all reports processed over the configured period (default: 7 days).

### Subtitle Fields

- **Period**: The lookback window (e.g., "Last 7 days")
- **Reports**: Total number of DMARC + TLS-RPT reports processed
- **Attachments**: Total size of report attachments processed
- **Trend indicators**: When previous-period data is available, arrows show whether pass rates improved or regressed compared to the equivalent prior period. Green up-arrow = improvement, red down-arrow = regression

### Stat Cards

| Card | Meaning |
|------|---------|
| **Reports** | Total number of reports (DMARC + TLS-RPT) |
| **DMARC Messages** | Total messages across all DMARC reports |
| **DMARC Pass Rate** | Overall DMARC pass rate across all reporters |
| **TLS Sessions** | Total sessions across all TLS-RPT reports |
| **TLS Pass Rate** | Overall TLS success rate across all reporters |

### Sections

#### Reporting Sources

Shows the top 10 organizations by volume. Use this to understand who is sending DMARC/TLS-RPT data about your domain and how much traffic each sees.

- **Failures** column: Red if > 0. Cross-reference with the failure details below.

#### DMARC Policy Distribution

Shows how many messages were processed under each DMARC policy level:

| Policy | Color | Meaning |
|--------|-------|---------|
| **REJECT** | Green | Maximum protection — failing messages are blocked |
| **QUARANTINE** | Orange | Moderate protection — failing messages go to spam |
| **NONE** | Red | Monitor-only — no enforcement. *Expected during initial DMARC rollout* |

If you see `NONE` policy with significant volume, this means some reporters are seeing your domain without a strong DMARC policy. This is normal during initial DMARC deployment — the progression path is `none` -> `quarantine` -> `reject`.

#### Top Failure Sources

Organizations that reported the most authentication failures. A high failure count from a major provider (Google, Microsoft) may indicate a misconfigured sending service.

#### DMARC Failure Details

Aggregated across all reports, showing the top failing source IPs grouped by reporting organization. The **Org** column shows which reporter(s) observed each failure, helping you identify whether the issue is isolated to one receiver or widespread.

#### TLS-RPT Failure Details

Aggregated TLS failures showing which MX hosts experienced problems and the failure reasons.

### Truncation

When there are more records than can be displayed, a note like "Showing 20 of 45 records" appears below the table. The most impactful entries (highest count/session count) are always shown first.

---

## Understanding DMARC Rollout

If you're deploying DMARC for the first time, here's how to interpret reports at each stage:

### Phase 1: `p=none` (Monitor)

- **Expected**: Reports showing pass/fail data without enforcement
- **Goal**: Identify all legitimate senders and ensure they pass DMARC
- **Action**: Add missing SPF records and DKIM keys for legitimate senders
- **Move to Phase 2 when**: All legitimate senders consistently pass DMARC

### Phase 2: `p=quarantine` (Soft Enforcement)

- **Expected**: Failing messages go to spam. Some false positives possible
- **Goal**: Verify enforcement doesn't impact legitimate mail
- **Action**: Monitor for any legitimate senders that start failing. Use `pct=25` initially, then increase
- **Move to Phase 3 when**: No legitimate senders are being quarantined

### Phase 3: `p=reject` (Full Enforcement)

- **Expected**: Failing messages are blocked entirely
- **Goal**: Maximum domain protection against spoofing
- **Action**: Continue monitoring. Failures from unknown IPs are spoofing attempts being blocked — this is the desired behavior
