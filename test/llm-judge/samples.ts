export interface JudgeSample {
  id: string;
  label: "high-bec" | "medium-bec" | "low-bec" | "benign";
  groundTruth: { scoreMin: number; scoreMax: number; description: string };
  plainText: string;
  subject: string;
  senderDomain: string;
}

export const judgeSamples: JudgeSample[] = [
  {
    id: "J1",
    label: "high-bec",
    groundTruth: {
      scoreMin: 80,
      scoreMax: 95,
      description: "CFO impersonating CEO authority for urgent wire — classic BEC trifecta",
    },
    subject: "Wire needed today — confidential, don't discuss",
    senderDomain: "gmail.com",
    plainText: `I need you to process a wire transfer today. I'm stuck in board meetings all day and cannot take calls.

Wire $92,000 to our new strategic partner before 4pm EST:
Bank: Wells Fargo
Account: 7748291037
Routing: 121000248
Beneficiary: Apex Capital Partners LLC

Keep this between us until I announce it to the team. This is time-sensitive — do not delay.

Michael Chen
CFO`,
  },
  {
    id: "J2",
    label: "high-bec",
    groundTruth: {
      scoreMin: 80,
      scoreMax: 95,
      description: "HR impersonation requesting payroll diversion with urgency",
    },
    subject: "Urgent: Update direct deposit info before Friday payroll",
    senderDomain: "gmail.com",
    plainText: `This is HR. We are migrating to a new payroll system and need all employees to resubmit direct deposit details immediately.

Please provide your bank name, account number, and routing number by end of day Thursday. Anyone who does not respond will have their payroll withheld until the following pay cycle.

This is urgent. Please respond today.

HR Payroll Team`,
  },
  {
    id: "J3",
    label: "high-bec",
    groundTruth: {
      scoreMin: 75,
      scoreMax: 90,
      description: "CEO gift card scam with escalating urgency",
    },
    subject: "Quick favor — need your help right now",
    senderDomain: "gmail.com",
    plainText: `Are you free? I need you to do something for me urgently. I'm presenting to the board and can't step out.

Please buy 5 Apple iTunes gift cards at $200 each from any store nearby. Scratch off the codes on the back and text them to me. I'll pay you back today.

Do NOT call me. Just reply here when done.

Sarah`,
  },
  {
    id: "J4",
    label: "medium-bec",
    groundTruth: {
      scoreMin: 60,
      scoreMax: 75,
      description: "Compromised vendor account requesting banking change — no urgency keywords",
    },
    subject: "Updated banking details for future invoice payments",
    senderDomain: "acmesupplies.com",
    plainText: `Hi,

We wanted to let you know that our banking details have changed. Please update your records to use the new account for all future payments:

Bank: Bank of America
Account: 4839201746
Routing: 026009593
Account Name: Acme Supplies Inc.

Our previous account is being closed. Please confirm you have updated your records.

Regards,
Billing Department
Acme Supplies Inc.`,
  },
  {
    id: "J5",
    label: "low-bec",
    groundTruth: {
      scoreMin: 40,
      scoreMax: 55,
      description: "AI-polished BEC attempt — no urgency, no authority claims, subtle bank detail change",
    },
    subject: "Amendment to payment terms — Invoice 2026-0812",
    senderDomain: "gmail.com",
    plainText: `Good afternoon,

I am writing to advise of an amendment to the banking details associated with Invoice 2026-0812, currently pending in your accounts payable queue.

Please remit payment for this invoice to the following account effective immediately:

Financial Institution: Capital One
Account Title: Torres Advisory Group LLC
Account Number: 9920374651
ABA Routing: 051405515

The previous account referenced on the original invoice has been consolidated into this account. We appreciate your prompt attention.

Sincerely,
James Torres`,
  },
  {
    id: "J6",
    label: "benign",
    groundTruth: {
      scoreMin: 0,
      scoreMax: 20,
      description: "Internal VP email requesting weekend crunch — no financial ask",
    },
    subject: "Weekend push — all hands needed",
    senderDomain: "company.com",
    plainText: `Team,

I need everyone to plan for a working weekend. We have a major release on Monday and we're not quite there yet.

I'll order dinner Saturday night. No formal meetings — just async work and checking in on Slack. If you have prior commitments that can't move, let me know by Friday so I can adjust the plan.

Budget for overtime is already approved. This is a one-time ask.

Thanks for your commitment,
Rachel
VP Engineering`,
  },
  {
    id: "J7",
    label: "benign",
    groundTruth: {
      scoreMin: 0,
      scoreMax: 15,
      description: "Legitimate staffing agency invoice on net-60 terms from established domain",
    },
    subject: "Invoice #2026-0349 — Apex Staffing Group",
    senderDomain: "apexstaffing.com",
    plainText: `Hi,

Please find attached Invoice #2026-0349 for staffing services rendered in April 2026.

Invoice total: $8,400.00
Payment terms: Net-60
Due date: July 13, 2026

Services: 4 weeks of contract engineering support per our Master Services Agreement dated January 15, 2026.

Payment can be made via ACH or check. Our banking details are on file from previous invoices. Please reach out if anything has changed on your end.

Thank you for the continued partnership.

Lisa Chen
Accounts Receivable
Apex Staffing Group`,
  },
  {
    id: "J8",
    label: "benign",
    groundTruth: {
      scoreMin: 0,
      scoreMax: 20,
      description: "Legitimate IT password expiry notice from company domain",
    },
    subject: "Your password expires in 14 days",
    senderDomain: "company.com",
    plainText: `Hi,

Your company account password will expire in 14 days. Please reset it before the expiration date to maintain uninterrupted access.

Reset your password: https://sso.company.com/reset

Password requirements:
- Minimum 12 characters
- At least one uppercase letter, one number, and one special character
- Cannot match any of your last 8 passwords

If you have questions or need help, contact IT support at helpdesk@company.com or call ext. 1100.

Company IT`,
  },
  {
    id: "J9",
    label: "high-bec",
    groundTruth: {
      scoreMin: 65,
      scoreMax: 80,
      description: "Fake deal counsel impersonating attorney, escrow wire demand with confidentiality pressure",
    },
    subject: "Confidential — Closing: Escrow funding required today",
    senderDomain: "harrington-lawfirm.net",
    plainText: `This communication is privileged and confidential.

I am counsel overseeing the closing of the acquisition discussed with your CEO. Per the agreed terms, the escrow account must be funded by 5 PM EST today or the penalty clause will be triggered.

Please wire $215,000 to:
Bank: Wells Fargo
Account: 5593827401
Routing: 121000248
Reference: Escrow Matter 2026-0088

This must remain strictly confidential until the announcement. Do not discuss with other team members or consult your internal legal team at this stage.

David Levi, Esq.
Harrington & Associates`,
  },
  {
    id: "J10",
    label: "high-bec",
    groundTruth: {
      scoreMin: 65,
      scoreMax: 80,
      description: "Supply chain invoice swap — manufacturer impersonation with updated banking on existing PO",
    },
    subject: "Banking update for PO-4821 payment",
    senderDomain: "precisionmfg-corp.com",
    plainText: `Dear Accounts Payable,

This is a notice that Precision Manufacturing Corp has updated its banking details. Please use the new account for all outstanding and future payments, including the pending payment for PO-4821.

New banking details:
Bank: Citibank
Account Name: Precision Manufacturing Corp
Account Number: 8847392015
Routing: 021000089

The old account will be deactivated by end of this week. Please process the PO-4821 payment to the new account immediately to avoid delays.

Amanda Ross
Controller — Precision Manufacturing Corp`,
  },
];
