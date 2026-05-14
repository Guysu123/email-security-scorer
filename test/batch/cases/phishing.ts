import { TestCase } from "../../types";

const DMARC_FAIL = `Authentication-Results: mx.google.com;
   dmarc=fail (p=REJECT) header.from=example.com;
   spf=fail (google.com: does not designate 198.51.100.42 as permitted sender) smtp.mailfrom=noreply@example.com;
   dkim=pass header.i=@attacker.com
Received: from mail.attacker.com (mail.attacker.com [198.51.100.42])
   by mx.google.com with ESMTP id x7si123456;
   Wed, 14 May 2026 08:00:00 -0700`;

const DMARC_DKIM_FAIL = `Authentication-Results: mx.google.com;
   dmarc=fail (p=QUARANTINE) header.from=example.com;
   spf=pass smtp.mailfrom=bounce@attacker.com;
   dkim=fail header.i=@example.com reason="signature verification failed"
Received: from mail.attacker.com (mail.attacker.com [203.0.113.5])
   by mx.google.com with ESMTP id y2si654321;
   Wed, 14 May 2026 09:15:00 -0700`;

const DKIM_FAIL_ONLY = `Authentication-Results: mx.google.com;
   dmarc=pass header.from=lastpass-support.net;
   spf=pass smtp.mailfrom=alerts@lastpass-support.net;
   dkim=fail header.i=@lastpass.com reason="key not found"
Received: from mail.lastpass-support.net (mail.lastpass-support.net [192.0.2.88])
   by mx.google.com with ESMTP id z9si999888;
   Wed, 14 May 2026 10:30:00 -0700`;

const DMARC_SPF_FAIL = `Authentication-Results: mx.google.com;
   dmarc=fail (p=REJECT) header.from=vpn-corp.com;
   spf=fail (google.com: domain of noreply@vpn-corp.com does not designate 185.220.101.1 as permitted sender);
   dkim=none
Received: from 185.220.101.1 (185.220.101.1 [185.220.101.1])
   by mx.google.com with ESMTP id a1si000001;
   Wed, 14 May 2026 11:00:00 -0700`;

const makeEnvelope = (id: string) => ({
  messageId: `<${id}@test.local>`,
  gmailThreadId: `thread-${id}`,
  receivedTimestamp: "2026-05-14T14:00:00Z",
});

const META = {
  addonVersion: "1.0.0",
  requestId: "test-runner",
  timestamp: "2026-05-14T14:00:00Z",
};

export const phishingCases: TestCase[] = [
  {
    id: "PHISH_GOOGLE_DOCS_2017",
    description: "Fake shared doc link from typosquatted Google domain",
    category: "phishing",
    email: {
      envelope: makeEnvelope("phish-01"),
      rawHeaders: DMARC_FAIL.replace(/example\.com/g, "goog1e.com").replace(/attacker\.com/g, "goog1e.com"),
      sender: {
        displayName: "Google Docs",
        emailAddress: "noreply@goog1e.com",
        replyTo: null,
      },
      subject: "Guy Surkis shared a document with you",
      body: {
        plainText: `Guy Surkis has shared a document with you.

Click here to view: https://docs.goog1e.com/document/d/1aBcDeFgHiJk/edit

You need to verify your account credentials to access this shared document.
Please click the link above and enter your Google username and password.

This link will expire in 24 hours.`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 95 },
  },
  {
    id: "PHISH_CRED_HARVEST_OKTA",
    description: "Fake Okta SSO portal, DMARC fail, urgency to re-authenticate",
    category: "phishing",
    email: {
      envelope: makeEnvelope("phish-02"),
      rawHeaders: DMARC_FAIL.replace(/example\.com/g, "okta-security.net").replace(/attacker\.com/g, "okta-security.net"),
      sender: {
        displayName: "Okta Security",
        emailAddress: "security@okta-security.net",
        replyTo: null,
      },
      subject: "URGENT: Your Okta session has expired — re-authenticate immediately",
      body: {
        plainText: `Your Okta SSO session has been flagged for suspicious activity and has been terminated.

ACTION REQUIRED: You must re-authenticate within the next 30 minutes or your account will be locked.

Re-authenticate here: https://okta-security.net/sso/re-auth?token=a8f3k2

Failure to complete this step will result in immediate account suspension and loss of access to all company applications.

— Okta Security Team`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 90 },
  },
  {
    id: "PHISH_TEAMS_IMPERSONATION",
    description: "Teams link to attacker domain, Microsoft IT impersonation",
    category: "phishing",
    email: {
      envelope: makeEnvelope("phish-03"),
      rawHeaders: DMARC_DKIM_FAIL.replace(/example\.com/g, "microsofft-it.com").replace(/attacker\.com/g, "microsofft-it.com"),
      sender: {
        displayName: "Microsoft IT Security",
        emailAddress: "noreply@microsofft-it.com",
        replyTo: null,
      },
      subject: "Microsoft Teams: Verify your identity to continue",
      body: {
        plainText: `We detected a sign-in attempt from an unrecognized device on your Microsoft Teams account.

To protect your account, please verify your identity immediately:

https://microsofft-it.com/teams/verify?session=9x2kp1

Enter your Microsoft credentials to confirm this was you. If you do not verify within 1 hour, your Teams access will be suspended pending investigation.

Microsoft IT Security`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 90 },
  },
  {
    id: "PHISH_DOCUSIGN_LOOKALIKE",
    description: "Fake DocuSign notification from typosquatted domain",
    category: "phishing",
    email: {
      envelope: makeEnvelope("phish-04"),
      rawHeaders: DMARC_FAIL.replace(/example\.com/g, "d0cusign.com").replace(/attacker\.com/g, "d0cusign.com"),
      sender: {
        displayName: "DocuSign",
        emailAddress: "dse@d0cusign.com",
        replyTo: null,
      },
      subject: "Complete signing: NDA Agreement — Action Required",
      body: {
        plainText: `You have a document to review and sign.

Document: Non-Disclosure Agreement
Sender: Legal Department

REVIEW & SIGN: https://d0cusign.com/signing?envelope=5fG9kL2mN

You must enter your credentials to access this secure document.
This request will expire in 48 hours.

Do Not Share This Email — DocuSign`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 90 },
  },
  {
    id: "PHISH_VPN_CREDENTIAL_HARVEST",
    description: "Fake VPN portal login alert, DMARC + SPF fail, account suspension threat",
    category: "phishing",
    email: {
      envelope: makeEnvelope("phish-05"),
      rawHeaders: DMARC_SPF_FAIL,
      sender: {
        displayName: "IT VPN Support",
        emailAddress: "vpn-alerts@vpn-corp.com",
        replyTo: null,
      },
      subject: "VPN Account Suspension Notice — Immediate Action Required",
      body: {
        plainText: `Your corporate VPN account has been flagged due to multiple failed authentication attempts.

Your account will be SUSPENDED in 2 hours unless you verify your credentials now.

Verify at: https://vpn-corp.com/portal/verify-identity

Enter your VPN username and password to restore access. After verification, you will be prompted to reset your password.

This is an automated security alert. Do not reply to this email.

IT Security Operations`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 92 },
  },
  {
    id: "PHISH_GITHUB_OAUTH_FAKE",
    description: "Fake CircleCI OAuth request from homograph GitHub domain",
    category: "phishing",
    email: {
      envelope: makeEnvelope("phish-06"),
      rawHeaders: DMARC_FAIL.replace(/example\.com/g, "gïthub.com").replace(/attacker\.com/g, "gïthub.com"),
      sender: {
        displayName: "GitHub",
        emailAddress: "noreply@gïthub.com",
        replyTo: null,
      },
      subject: "CircleCI is requesting access to your GitHub account",
      body: {
        plainText: `CircleCI would like permission to access your GitHub repositories and workflows.

Authorize here: https://gïthub.com/login/oauth/authorize?client_id=circleci&scope=repo,workflow

You will need to enter your GitHub username and password to grant this access.

If you did not initiate this request, please ignore this email and secure your account immediately.

GitHub Security`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 88 },
  },
  {
    id: "PHISH_IT_HELPDESK_SOCIAL",
    description: "Helpdesk impersonation from free provider, credential request",
    category: "phishing",
    email: {
      envelope: makeEnvelope("phish-07"),
      rawHeaders: DMARC_FAIL.replace(/example\.com/g, "gmail.com").replace(/attacker\.com/g, "gmail.com"),
      sender: {
        displayName: "IT Help Desk",
        emailAddress: "it.helpdesk.support@gmail.com",
        replyTo: null,
      },
      subject: "Urgent: Your account credentials need immediate verification",
      body: {
        plainText: `This is the IT Help Desk. We are conducting a mandatory security audit of all employee accounts.

Your account has been flagged for unusual access patterns. To avoid suspension, you must verify your identity by providing your current login credentials by end of day.

Please reply to this email with:
- Username
- Current password
- Employee ID

This is a time-sensitive request. Failure to comply will result in account deactivation.

IT Help Desk`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 88 },
  },
  {
    id: "PHISH_SPEARPHISH_DEVOPS",
    description: "Targeted DevOps engineer, fake npm security update, lookalike domain",
    category: "phishing",
    email: {
      envelope: makeEnvelope("phish-08"),
      rawHeaders: DMARC_FAIL.replace(/example\.com/g, "npm1s.com").replace(/attacker\.com/g, "npm1s.com"),
      sender: {
        displayName: "npm Security",
        emailAddress: "security@npm1s.com",
        replyTo: null,
      },
      subject: "Critical security patch required for your npm packages — do not delay",
      body: {
        plainText: `A critical vulnerability (CVE-2026-19283) has been discovered in packages your account publishes.

This vulnerability allows remote code execution via malformed JSON payloads.

You must apply the patch immediately: https://npm1s.com/security/patch?token=devops-8f3kp2

Log in with your npm credentials to apply the patch. All affected packages will be automatically updated.

DO NOT DELAY — your packages remain exploitable until this is resolved.

npm Security Team`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 88 },
  },
  {
    id: "PHISH_LASTPASS_ENGINEER",
    description: "Targeted engineer, fake LastPass security alert, DKIM fail only",
    category: "phishing",
    email: {
      envelope: makeEnvelope("phish-09"),
      rawHeaders: DKIM_FAIL_ONLY,
      sender: {
        displayName: "LastPass Support",
        emailAddress: "alerts@lastpass-support.net",
        replyTo: null,
      },
      subject: "Your LastPass master password was changed from a new device",
      body: {
        plainText: `We detected that your LastPass master password was recently changed from a device we don't recognize.

Location: Kyiv, Ukraine
Device: Unknown browser on Windows

If this was you, no action is needed.

If this was NOT you, your vault may be compromised. Secure your account immediately before unauthorized changes are made:

https://lastpass-support.net/account/recover?token=9x2kQ8pL

This link expires in 60 minutes.

LastPass Support`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 88 },
  },
  {
    id: "PHISH_REPLY_TO_PHISH",
    description: "Legitimate-looking sender, Reply-To routes to attacker Gmail",
    category: "phishing",
    email: {
      envelope: makeEnvelope("phish-10"),
      rawHeaders: `Authentication-Results: mx.google.com;
   dmarc=pass header.from=company-updates.com;
   spf=pass smtp.mailfrom=noreply@company-updates.com;
   dkim=pass header.i=@company-updates.com
Received: from mail.company-updates.com (mail.company-updates.com [203.0.113.20])
   by mx.google.com with ESMTP id b4si000002;
   Wed, 14 May 2026 12:00:00 -0700`,
      sender: {
        displayName: "Company Account Team",
        emailAddress: "noreply@company-updates.com",
        replyTo: "account-verify-829@gmail.com",
      },
      subject: "Please confirm your identity to continue using your account",
      body: {
        plainText: `A new device was detected signing into your account from an unrecognized location.

Please verify your account immediately to prevent unauthorized access:

https://account-security-portal.net/verify?session=829&ref=4kf2

If you did not authorize this login, reply to this email so we can secure your account.

Account Security Team`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 35, scoreMax: 54 },
  },
];
