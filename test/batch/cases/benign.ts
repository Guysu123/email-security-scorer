import { TestCase } from "../../types";

const AUTH_PASS = (domain: string) =>
  `Authentication-Results: mx.google.com;
   dmarc=pass header.from=${domain};
   spf=pass smtp.mailfrom=noreply@${domain};
   dkim=pass header.i=@${domain}
Received: from mail.${domain} (mail.${domain} [203.0.113.100])
   by mx.google.com with ESMTP id g9si000007;
   Wed, 14 May 2026 15:00:00 -0700`;

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

export const benignCases: TestCase[] = [
  {
    id: "BENIGN_NEWSLETTER",
    description: "Legitimate marketing newsletter, authenticated",
    category: "benign",
    email: {
      envelope: makeEnvelope("benign-01"),
      rawHeaders: AUTH_PASS("mailchimp-newsletters.com"),
      sender: {
        displayName: "ProductHunt Digest",
        emailAddress: "hello@mailchimp-newsletters.com",
        replyTo: null,
      },
      subject: "This week's top products — May 14, 2026",
      body: {
        plainText: `Hi there,

Here are this week's top products on ProductHunt:

1. Notion AI 3.0 — AI-powered workspace
2. Linear Releases — Ship faster with automated release notes
3. Loom for Slack — Async video built into your workflow

Browse all products: https://producthunt.com/newsletter/2026-05-14

To unsubscribe, click here: https://mailchimp-newsletters.com/unsubscribe

ProductHunt Team`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 0, scoreMax: 25 },
  },
  {
    id: "BENIGN_INVOICE_LEGITIMATE",
    description: "Real vendor invoice, established domain, DMARC pass",
    category: "benign",
    email: {
      envelope: makeEnvelope("benign-02"),
      rawHeaders: AUTH_PASS("aws.amazon.com"),
      sender: {
        displayName: "AWS Billing",
        emailAddress: "billing@aws.amazon.com",
        replyTo: null,
      },
      subject: "Your AWS invoice for April 2026 is ready",
      body: {
        plainText: `Hello,

Your AWS invoice for April 2026 is now available.

Invoice number: INV-2026-04-0039182
Amount due: $1,247.83
Due date: May 31, 2026
Payment method: Visa ending in 4242 (auto-pay enabled)

View your invoice: https://console.aws.amazon.com/billing/invoices

No action is required if auto-pay is enabled.

AWS Billing Team`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 0, scoreMax: 25 },
  },
  {
    id: "BENIGN_HR_ONBOARDING",
    description: "HR onboarding email from company domain, DMARC pass",
    category: "benign",
    email: {
      envelope: makeEnvelope("benign-03"),
      rawHeaders: AUTH_PASS("company.com"),
      sender: {
        displayName: "People Team",
        emailAddress: "people@company.com",
        replyTo: null,
      },
      subject: "Welcome aboard! Your first week at Company",
      body: {
        plainText: `Hi and welcome to the team!

We're thrilled to have you join us. Here's what to expect your first week:

Day 1: Orientation with the People team at 9am (Conference Room B)
Day 2: Engineering onboarding — setup your dev environment
Day 3–5: Team introductions and project ramp-up

Please complete the following forms before your start date:
- Direct deposit form: https://company.com/hr/onboarding/bank-info
- Benefits enrollment: https://company.com/hr/benefits
- Equipment request: https://company.com/hr/equipment

Your manager Sarah will reach out to schedule a welcome call.

People Team`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 0, scoreMax: 25 },
  },
  {
    id: "BENIGN_URGENT_MEETING",
    description: "Urgent meeting request from internal sender, no financial ask",
    category: "benign",
    email: {
      envelope: makeEnvelope("benign-04"),
      rawHeaders: AUTH_PASS("company.com"),
      sender: {
        displayName: "Rachel VP Engineering",
        emailAddress: "rachel@company.com",
        replyTo: null,
      },
      subject: "Urgent: can everyone block tomorrow 9–11am?",
      body: {
        plainText: `Team,

I know this is last minute but I need everyone to block tomorrow 9–11am for an all-hands on the Q3 roadmap. Things are moving faster than expected and we need to align before the board meeting on Thursday.

Can you all confirm availability? If 9am doesn't work let me know and we'll find another slot.

Also heads up — we'll be working through lunch on Friday to finalize the release. Budget for that is already approved.

Thanks,
Rachel
VP Engineering`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 0, scoreMax: 34 },
  },
  {
    id: "BENIGN_IT_PASSWORD_RESET",
    description: "Legitimate IT password reset, proper auth headers",
    category: "benign",
    email: {
      envelope: makeEnvelope("benign-05"),
      rawHeaders: AUTH_PASS("company.com"),
      sender: {
        displayName: "Company IT",
        emailAddress: "it@company.com",
        replyTo: null,
      },
      subject: "Your password expires in 7 days",
      body: {
        plainText: `Hi,

Your Company account password will expire in 7 days. Please reset it before then to avoid being locked out.

Reset your password here: https://sso.company.com/password-reset

Your new password must:
- Be at least 12 characters
- Include uppercase, lowercase, and a number
- Not be one of your last 10 passwords

If you have any issues, contact IT support at it@company.com or ext. 1234.

Company IT`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 0, scoreMax: 25 },
  },
  {
    id: "BENIGN_BANK_NOTIFICATION",
    description: "Real bank transaction alert, authenticated sender",
    category: "benign",
    email: {
      envelope: makeEnvelope("benign-06"),
      rawHeaders: AUTH_PASS("alerts.chase.com"),
      sender: {
        displayName: "Chase Alerts",
        emailAddress: "no-reply@alerts.chase.com",
        replyTo: null,
      },
      subject: "Transaction alert: $42.50 at Whole Foods Market",
      body: {
        plainText: `A transaction was made on your Chase Sapphire card ending in 4281.

Merchant: Whole Foods Market
Amount: $42.50
Date: May 14, 2026 at 12:34 PM

If you recognize this transaction, no action is needed.
If you don't recognize this transaction, please call the number on the back of your card.

Manage your alerts: https://secure.chase.com/web/auth/dashboard#/dashboard/alerts

Chase Customer Service`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 0, scoreMax: 25 },
  },
  {
    id: "BENIGN_EXECUTIVE_TRAVEL",
    description: "CEO emailing assistant about travel arrangements, internal domain",
    category: "benign",
    email: {
      envelope: makeEnvelope("benign-07"),
      rawHeaders: AUTH_PASS("company.com"),
      sender: {
        displayName: "David Chen CEO",
        emailAddress: "david@company.com",
        replyTo: null,
      },
      subject: "NYC trip next week — can you book?",
      body: {
        plainText: `Hi,

I have the investor dinner in NYC on Wednesday the 20th. Can you book the following?

Flight: SFO to JFK, Tuesday May 19 afternoon (any direct on United preferred)
Hotel: The Standard High Line, 1 night, checkout Thursday morning
Car: Black car pickup from JFK to hotel

Also please add the dinner (8pm, Le Bernardin) to my calendar as a block. I'll need to leave the hotel by 7:30.

Thanks,
David`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 0, scoreMax: 25 },
  },
  {
    id: "BENIGN_VENDOR_ONBOARDING",
    description: "New vendor introduction, established domain, no financial ask",
    category: "benign",
    email: {
      envelope: makeEnvelope("benign-08"),
      rawHeaders: AUTH_PASS("salesforce.com"),
      sender: {
        displayName: "Salesforce Sales",
        emailAddress: "sales@salesforce.com",
        replyTo: null,
      },
      subject: "Welcome to Salesforce — your account is ready",
      body: {
        plainText: `Hi,

Your Salesforce CRM account has been provisioned and is ready to use. Your team can now log in and start exploring.

Login URL: https://login.salesforce.com
Username: admin@company.com (you will be prompted to set a password on first login)

Your dedicated success manager is Jamie Park (jpark@salesforce.com) and will reach out this week to schedule your kickoff call.

Resources to get started:
- Salesforce Trailhead (free learning): https://trailhead.salesforce.com
- Admin setup guide: https://help.salesforce.com/getting-started

We're excited to have Company on board!

Salesforce Success Team`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 0, scoreMax: 25 },
  },
  {
    id: "BENIGN_DOCUSIGN_LEGITIMATE",
    description: "Real DocuSign contract notification, proper authentication",
    category: "benign",
    email: {
      envelope: makeEnvelope("benign-09"),
      rawHeaders: AUTH_PASS("docusign.net"),
      sender: {
        displayName: "DocuSign",
        emailAddress: "dse@docusign.net",
        replyTo: null,
      },
      subject: "Please DocuSign: Software License Agreement — Company & Acme Corp",
      body: {
        plainText: `Acme Corp has sent you a document to review and sign.

Document: Software License Agreement
Message from sender: "Please review and sign the attached license agreement at your convenience. No rush — we have until end of month."

REVIEW DOCUMENT: https://docusign.net/signing?envelope=7hJkLmNoPq&token=abc123secure

This message was sent to you by DocuSign on behalf of Acme Corp. If you have questions, contact the sender at contracts@acmecorp.com.

Do Not Share This Email`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 35, scoreMax: 54 },
  },
  {
    id: "BENIGN_LEGITIMATE_WIRE_REQUEST",
    description: "Established vendor, authenticated domain, routine wire for existing PO",
    category: "benign",
    email: {
      envelope: makeEnvelope("benign-10"),
      rawHeaders: AUTH_PASS("acmecorp.com"),
      sender: {
        displayName: "Acme Corp Accounts Receivable",
        emailAddress: "ar@acmecorp.com",
        replyTo: null,
      },
      subject: "Invoice INV-2026-0441 — Wire Transfer per PO-7821",
      body: {
        plainText: `Hi,

Please find below wire transfer details for Invoice INV-2026-0441, issued per Purchase Order PO-7821 dated April 1, 2026.

Invoice amount: $34,500.00
Payment terms: Net-30 (due May 31, 2026)

Wire instructions (unchanged from our records on file):
Bank: JPMorgan Chase
Account Name: Acme Corp
Account Number: 1234567890
Routing Number: 021000021

Please initiate the wire at your convenience before the due date. Let us know if you need a copy of the invoice or PO for your records.

Thank you,
Amanda Lee
Accounts Receivable — Acme Corp
ar@acmecorp.com | (415) 555-0192`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 0, scoreMax: 34 },
  },
];
