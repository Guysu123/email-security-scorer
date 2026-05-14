export interface RubricGrade {
  scoreAccuracy: number;     // 1–5
  evidenceQuality: number;   // 1–5
  falsePositiveRisk: number; // 1–5 (only meaningful for benign samples)
  reasoning: string;
}

export function buildJudgePrompt(
  subject: string,
  senderDomain: string,
  plainText: string,
  haikusResponse: string,
  groundTruth: { scoreMin: number; scoreMax: number; description: string },
  label: string
): string {
  return `You are evaluating the output of a BEC (Business Email Compromise) detection model. Your job is to grade how well the model analyzed a given email.

## Email Being Analyzed
Subject: ${subject}
Sender domain: ${senderDomain}

Email body:
${plainText}

## Ground Truth
Label: ${label}
Expected becScore range: ${groundTruth.scoreMin}–${groundTruth.scoreMax}
Description: ${groundTruth.description}

## Model Output (claude-haiku-4-5-20251001)
${haikusResponse}

## Your Task
Grade the model output on exactly 3 dimensions, each scored 1–5:

1. **Score Accuracy** (1–5): Does the becScore reflect the actual threat level?
   - 5: becScore falls within the expected range [${groundTruth.scoreMin}–${groundTruth.scoreMax}]
   - 3: becScore is in the right risk tier but slightly off
   - 1: becScore is in the completely wrong tier

2. **Evidence Quality** (1–5): Is the "evidence" field in each signal a specific quoted excerpt from the email?
   - 5: All evidence fields are specific quoted phrases from the email body
   - 3: Some evidence fields are specific, some are generic summaries
   - 1: Evidence fields are generic paraphrases that could apply to any email

3. **False Positive Risk** (1–5): For benign emails, does the model correctly avoid over-flagging?
   - If this is a BENIGN email: 5 = model correctly gives low score; 1 = model incorrectly flags as high threat
   - If this is a THREAT email: score this 3 (not applicable — focus dimensions 1 and 2 for threat cases)

Respond ONLY with valid JSON in this exact format:
{
  "scoreAccuracy": <1-5>,
  "evidenceQuality": <1-5>,
  "falsePositiveRisk": <1-5>,
  "reasoning": "<one or two sentences explaining your grades>"
}`;
}
