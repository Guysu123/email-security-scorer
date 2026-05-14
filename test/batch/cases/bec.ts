import { TestCase } from "../../types";

const AUTH_PASS = `Authentication-Results: mx.google.com;
   dmarc=pass header.from=legitcorp.com;
   spf=pass smtp.mailfrom=ceo@legitcorp.com;
   dkim=pass header.i=@legitcorp.com
Received: from mail.google.com (mail.google.com [74.125.0.1])
   by mx.google.com with ESMTP id c5si000003;
   Wed, 14 May 2026 13:00:00 -0700`;

const DMARC_FAIL = `Authentication-Results: mx.google.com;
   dmarc=fail (p=REJECT) header.from=acmecorp.com;
   spf=fail smtp.mailfrom=billing@fake-acme.com;
   dkim=none
Received: from mail.fake-acme.com (mail.fake-acme.com [198.51.100.10])
   by mx.google.com with ESMTP id d6si000004;
   Wed, 14 May 2026 13:30:00 -0700`;

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

export const becCases: TestCase[] = [
  {
    id: "BEC_CEO_WIRE_TRANSFER",
    description: "CEO display name + free Gmail + urgent wire to new vendor",
    category: "bec",
    email: {
      envelope: makeEnvelope("bec-01"),
      rawHeaders: AUTH_PASS.replace(/legitcorp\.com/g, "gmail.com"),
      sender: {
        displayName: "John Smith CEO",
        emailAddress: "jsmith.ceo.urgent@gmail.com",
        replyTo: null,
      },
      subject: "Urgent wire needed today — confidential",
      body: {
        plainText: `I need you to process an urgent wire transfer today. I'm in back-to-back meetings and can't talk but this is time sensitive.

Wire $87,500 to our new vendor:
Bank: First National Bank
Account: 4829103847
Routing: 021000021
Beneficiary: Apex Solutions LLC

This needs to go out before 3pm or we lose the contract. Do not discuss with anyone — I'll explain later. Just get it done and confirm when sent.

John Smith
CEO`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 88 },
  },
  {
    id: "BEC_PAYROLL_DIVERSION",
    description: "HR impersonation, payroll direct-deposit change before Friday",
    category: "bec",
    email: {
      envelope: makeEnvelope("bec-02"),
      rawHeaders: AUTH_PASS.replace(/legitcorp\.com/g, "gmail.com"),
      sender: {
        displayName: "HR Department",
        emailAddress: "hr.payroll.updates@gmail.com",
        replyTo: null,
      },
      subject: "Action Required: Update your direct deposit before Friday payroll run",
      body: {
        plainText: `This is the HR Department. We are updating our payroll processing system and need all employees to resubmit their direct deposit information before this Friday.

Please reply with your:
- Full legal name
- Bank name
- Account number
- Routing number

Employees who do not submit by Thursday EOD will have their payroll held until the following pay period.

This is urgent. Please respond today.

HR Payroll Team`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 88 },
  },
  {
    id: "BEC_GIFT_CARD_REQUEST",
    description: "Executive impersonation, gift card purchase, 'cannot talk right now'",
    category: "bec",
    email: {
      envelope: makeEnvelope("bec-03"),
      rawHeaders: AUTH_PASS.replace(/legitcorp\.com/g, "gmail.com"),
      sender: {
        displayName: "Sarah Connor CFO",
        emailAddress: "s.connor.cfo2026@gmail.com",
        replyTo: null,
      },
      subject: "Quick favor — urgent",
      body: {
        plainText: `Are you available right now? I need a quick favor. I'm in a board meeting and can't step out.

I need you to purchase some gift cards for a client appreciation event. I'll reimburse you today.

Please get 5x $200 Apple iTunes gift cards from any nearby store. Once you have them, scratch off the back and send me the codes.

Don't call me — I'm presenting. Just reply here when done.

Sarah Connor
CFO`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 88 },
  },
  {
    id: "BEC_VENDOR_INVOICE_FRAUD",
    description: "Trusted vendor display name, changed banking details, lookalike domain",
    category: "bec",
    email: {
      envelope: makeEnvelope("bec-04"),
      rawHeaders: DMARC_FAIL.replace(/acmecorp\.com/g, "acmecorp-billing.com").replace(/fake-acme\.com/g, "acmecorp-billing.com"),
      sender: {
        displayName: "Acme Corp Billing",
        emailAddress: "billing@acmecorp-billing.com",
        replyTo: null,
      },
      subject: "Important: Updated banking details for future payments",
      body: {
        plainText: `Dear Accounts Payable,

Please be advised that Acme Corp has changed its banking details effective immediately. All future payments must be directed to our new account.

New banking details:
Bank: Chase Bank
Account Name: Acme Corp LLC
Account Number: 7738291045
Routing Number: 021000021

Please update your records and ensure all outstanding and future invoices are paid to this account. The previous account will be closed at end of month.

Kindly confirm receipt of these updated details.

Regards,
Amanda Lee
Accounts Receivable — Acme Corp`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 88 },
  },
  {
    id: "BEC_ATTORNEY_BEC",
    description: "Fake attorney, merger confidentiality, urgent wire demand",
    category: "bec",
    email: {
      envelope: makeEnvelope("bec-05"),
      rawHeaders: AUTH_PASS.replace(/legitcorp\.com/g, "harrington-lawfirm.net"),
      sender: {
        displayName: "David Levi, Esq.",
        emailAddress: "d.levi@harrington-lawfirm.net",
        replyTo: null,
      },
      subject: "Confidential — M&A Closing: Escrow Wire Required Today",
      body: {
        plainText: `This communication is strictly confidential and subject to attorney-client privilege.

I am reaching out on behalf of the acquisition team regarding the pending transaction. Per the closing agreement, an escrow deposit of $340,000 must be sent via wire transfer to our escrow account no later than 5:00 PM EST today to avoid triggering the penalty clause.

Wire transfer details:
Bank: Wells Fargo
Account number: 5593827461
Routing number: 121000248
Memo: Escrow — Matter 2026-1183

This matter must remain confidential. Do not discuss with other team members until the deal is announced. Please act immediately.

David Levi, Esq.
Harrington & Associates`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 88 },
  },
  {
    id: "BEC_W2_TAX_FRAUD",
    description: "CFO impersonation, urgent W-2 data request",
    category: "bec",
    email: {
      envelope: makeEnvelope("bec-06"),
      rawHeaders: AUTH_PASS.replace(/legitcorp\.com/g, "gmail.com"),
      sender: {
        displayName: "CFO Office",
        emailAddress: "cfo.office.request@gmail.com",
        replyTo: null,
      },
      subject: "Urgent: Employee W-2 data needed for audit — respond today",
      body: {
        plainText: `This is the CFO's office. We are undergoing an unannounced external audit and the auditors have requested a full list of employee W-2 data immediately.

Please send me the following for all employees as soon as possible:
- Full legal name
- Social Security Number
- 2025 W-2 form (PDF)
- Total annual compensation

The auditors are on-site and need this by 2pm today. This is urgent and confidential.

Please do not discuss this request with other staff. Respond directly to this email.

CFO Office`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 88 },
  },
  {
    id: "BEC_REPLY_TO_MISMATCH",
    description: "Legit-looking domain, Reply-To routes to attacker Gmail, wire request",
    category: "bec",
    email: {
      envelope: makeEnvelope("bec-07"),
      rawHeaders: `Authentication-Results: mx.google.com;
   dmarc=pass header.from=globalpartners-inc.com;
   spf=pass smtp.mailfrom=finance@globalpartners-inc.com;
   dkim=pass header.i=@globalpartners-inc.com
Received: from mail.globalpartners-inc.com (mail.globalpartners-inc.com [203.0.113.55])
   by mx.google.com with ESMTP id e7si000005;
   Wed, 14 May 2026 14:00:00 -0700`,
      sender: {
        displayName: "Global Partners Finance",
        emailAddress: "finance@globalpartners-inc.com",
        replyTo: "globalpartners.finance829@gmail.com",
      },
      subject: "Q2 payment — wire transfer details",
      body: {
        plainText: `Hi,

Per our agreement, please process the Q2 payment via wire transfer to the following account:

Bank: Citibank
Account: 3847291056
Routing: 021000089
Amount: $52,000

Please confirm once the wire is initiated. If you have any questions, reply to this email directly.

Thank you,
Finance Team
Global Partners Inc.`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 35, scoreMax: 54 },
  },
  {
    id: "BEC_LOOKALIKE_DOMAIN",
    description: "Email from typosquatted domain, wire request",
    category: "bec",
    email: {
      envelope: makeEnvelope("bec-08"),
      rawHeaders: DMARC_FAIL.replace(/acmecorp\.com/g, "paypa1-transfers.com").replace(/fake-acme\.com/g, "paypa1-transfers.com"),
      sender: {
        displayName: "PayPal Business Transfers",
        emailAddress: "transfers@paypa1-transfers.com",
        replyTo: null,
      },
      subject: "Wire Transfer Request — $28,000 — Approval Required",
      body: {
        plainText: `A wire transfer request has been initiated from your PayPal business account.

Amount: $28,000.00
Recipient: Offshore Holdings Ltd
Destination: International
Reference: TXN-2026-88291

If you authorized this transfer, no action is needed. If you did not authorize this transfer, please call our fraud line immediately and provide your account credentials to cancel.

PayPal Business Transfers`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 88 },
  },
  {
    id: "BEC_FAILED_DMARC_WIRE",
    description: "Wire request from domain with failing SPF + DMARC",
    category: "bec",
    email: {
      envelope: makeEnvelope("bec-09"),
      rawHeaders: `Authentication-Results: mx.google.com;
   dmarc=fail (p=NONE) header.from=vendor-payments.net;
   spf=fail smtp.mailfrom=ap@vendor-payments.net;
   dkim=none
Received: from unknown (unknown [185.220.100.5])
   by mx.google.com with ESMTP id f8si000006;
   Wed, 14 May 2026 14:30:00 -0700`,
      sender: {
        displayName: "Vendor Payments",
        emailAddress: "ap@vendor-payments.net",
        replyTo: null,
      },
      subject: "Outstanding Invoice — Wire Payment Requested",
      body: {
        plainText: `Dear Accounts Payable,

Please process the attached outstanding invoice via wire transfer at your earliest convenience.

Invoice #: INV-2026-00492
Amount Due: $19,750
Due Date: Immediate

Wire Instructions:
Bank: First Republic Bank
Account: 6627384910
Routing: 321081669

Please confirm once the wire has been sent.

Vendor Payments Team`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 70, scoreMax: 88 },
  },
  {
    id: "BEC_AI_GENERATED_DICTION",
    description: "Polished formal BEC attempt, no urgency keywords, no grammar errors",
    category: "bec",
    email: {
      envelope: makeEnvelope("bec-10"),
      rawHeaders: AUTH_PASS.replace(/legitcorp\.com/g, "gmail.com"),
      sender: {
        displayName: "Michael Torres",
        emailAddress: "m.torres.consulting@gmail.com",
        replyTo: null,
      },
      subject: "Amendment to Payment Terms — Invoice 2026-0441",
      body: {
        plainText: `Good afternoon,

I am writing to inform you of a modification to the banking details associated with Invoice 2026-0441, which is currently pending in your accounts payable queue.

Effective immediately, please direct remittance for this invoice to the following updated account:

Financial Institution: Capital One Business Banking
Account Title: Torres Consulting Group LLC
Account Number: 8839201746
ABA Routing Number: 051405515

The previous account referenced on the original invoice has been decommissioned as part of our banking consolidation. We would appreciate confirmation of this update at your earliest convenience.

Thank you for your continued partnership.

Sincerely,
Michael Torres
Principal Consultant`,
        htmlContent: null,
      },
      attachments: [],
      requestMetadata: META,
    },
    expect: { scoreMin: 35, scoreMax: 54 },
  },
];
