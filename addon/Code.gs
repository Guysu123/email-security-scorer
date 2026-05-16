/**
 * Gmail Add-on entry point.
 *
 * Contextual trigger: onGmailMessage() fires every time the user opens an email.
 * It must return a Card synchronously — Apps Script is single-threaded.
 *
 * Flow:
 *   1. Extract email payload (MimeParser.gs)
 *   2. POST to backend (ApiClient.gs)
 *   3. Build and return result card (CardBuilder.gs)
 *
 * Security:
 *   - API secret comes from ScriptProperties — never hard-coded here.
 *   - Email content is passed as a structured JSON object, not via string concatenation.
 *   - We request only gmail.readonly scope; we never modify or send emails.
 */

/**
 * Contextual trigger — called by Gmail when an email is opened.
 * @param {GoogleAppsScript.Addons.EventObject} e
 * @returns {GoogleAppsScript.Card_Service.Card}
 */
function onGmailMessage(e) {
  try {
    var messageId = e.gmail && e.gmail.messageId;
    if (!messageId) {
      return buildErrorCard("No message ID in trigger event");
    }

    var accessToken = e.gmail.accessToken;
    GmailApp.setCurrentMessageAccessToken(accessToken);

    var message = GmailApp.getMessageById(messageId);
    if (!message) {
      return buildErrorCard("Could not load email message");
    }

    // Extract structured payload — MimeParser.gs handles MIME extraction
    var payload = extractEmailPayload(message);

    // Serve from cache if the result is still fresh (30 min TTL)
    var cached = getCachedResult(messageId);
    if (cached) {
      Logger.log("Cache hit for messageId: " + messageId);
      return buildResultCard(cached);
    }

    // Call backend — ApiClient.gs handles auth, serialization, and error handling
    var result = callAnalyzeApi(payload);

    if (!result.ok || !result.data) {
      Logger.log("Analysis API error: " + result.error + " (HTTP " + result.statusCode + ")");
      return buildErrorCard(
        result.statusCode === 429
          ? "Rate limit reached — please wait before re-analyzing"
          : result.statusCode === 401
          ? "Authentication error — check ADDON_API_SECRET in Script Properties"
          : result.error || "Analysis backend unreachable"
      );
    }

    // Cache the result so re-opens within 30 min skip the backend call
    try {
      setCachedResult(messageId, result.data);
    } catch (err) {
      Logger.log("Cache write error: " + (err.message || String(err)));
    }

    // Persist to per-user score history (dedup by analysisId handles re-opens)
    try {
      appendScoreHistory({
        id:    result.data.analysisId || (payload.envelope && payload.envelope.messageId) || "",
        ts:    Date.now(),
        score: result.data.finalScore,
        risk:  result.data.riskLevel,
        subj:  (payload.subject || "").slice(0, 50),
        from:  (payload.sender && payload.sender.emailAddress || "").slice(0, 40)
      });
    } catch (err) {
      Logger.log("History write error: " + (err.message || String(err)));
    }

    // Render results card — CardBuilder.gs owns all UI construction
    return buildResultCard(result.data);

  } catch (err) {
    Logger.log("onGmailMessage exception: " + (err.message || String(err)));
    return buildErrorCard("Unexpected error: " + (err.message || "unknown"));
  }
}

/**
 * Re-analyze action — called when user clicks "Re-analyze" button.
 * @param {GoogleAppsScript.Addons.EventObject} e
 * @returns {GoogleAppsScript.Card_Service.ActionResponse}
 */
function onRetry(e) {
  // Evict the cache so the user gets a fresh analysis, not the stale one they are disputing
  var messageId = e.gmail && e.gmail.messageId;
  if (messageId) {
    try { PropertiesService.getUserProperties().deleteProperty("bec_" + messageId); } catch (err) {}
  }
  var card = onGmailMessage(e);
  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().updateCard(card)
    )
    .build();
}

/**
 * Required by appsscript.json when authorizationCheckFunction is set.
 * Return true when the add-on is authorized to run.
 */
function authCallback() {
  return true;
}

/**
 * Homepage trigger — shown when the add-on panel is open but no email is selected.
 * @param {GoogleAppsScript.Addons.EventObject} e
 * @returns {GoogleAppsScript.Card_Service.Card}
 */
function onHomepage(e) {
  return buildStatsCard();
}

/**
 * Pushes the stats card onto the navigation stack from within a result card.
 * @param {GoogleAppsScript.Addons.EventObject} e
 * @returns {GoogleAppsScript.Card_Service.ActionResponse}
 */
function onShowStats(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().pushCard(buildStatsCard()))
    .build();
}

/**
 * Pushes the feedback form card. Parameters: messageId, score, riskLevel.
 * @param {GoogleAppsScript.Addons.EventObject} e
 * @returns {GoogleAppsScript.Card_Service.ActionResponse}
 */
function onShowFeedbackForm(e) {
  var p = e.commonEventObject.parameters;
  return CardService.newActionResponseBuilder()
    .setNavigation(
      CardService.newNavigation().pushCard(
        buildFeedbackFormCard(p.messageId, p.score, p.riskLevel)
      )
    )
    .build();
}

/**
 * Saves the submitted feedback and returns to the previous card.
 * @param {GoogleAppsScript.Addons.EventObject} e
 * @returns {GoogleAppsScript.Card_Service.ActionResponse}
 */
function onSubmitFeedback(e) {
  var p      = e.commonEventObject.parameters;
  var inputs = e.commonEventObject.formInputs || {};

  var suggestedRisk = inputs.suggestedRisk
    ? inputs.suggestedRisk.stringInputs.value[0]
    : null;
  var comment = inputs.comment
    ? (inputs.comment.stringInputs.value[0] || "").slice(0, 500)
    : "";

  var feedbackRecord = {
    id:            p.messageId,
    ts:            Date.now(),
    score:         parseInt(p.score, 10),
    risk:          p.riskLevel,
    suggestedRisk: suggestedRisk || null,
    comment:       comment
  };

  // Persist locally for the stats dashboard
  try {
    appendFeedback(feedbackRecord);
  } catch (err) {
    Logger.log("Feedback local write error: " + (err.message || String(err)));
  }

  // Send to backend so disputes are visible in Vercel logs for operator review
  try {
    var fbResult = callFeedbackApi({
      messageId:     p.messageId,
      originalScore: feedbackRecord.score,
      originalRisk:  p.riskLevel,
      suggestedRisk: suggestedRisk || null,
      comment:       comment
    });
    if (!fbResult.ok) {
      Logger.log("Feedback API error: " + fbResult.error);
    }
  } catch (err) {
    Logger.log("Feedback API exception: " + (err.message || String(err)));
  }

  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().popCard())
    .setNotification(CardService.newNotification().setText("Feedback saved — thank you!"))
    .build();
}

/**
 * Dismisses the feedback form without saving.
 * @param {GoogleAppsScript.Addons.EventObject} e
 * @returns {GoogleAppsScript.Card_Service.ActionResponse}
 */
function onCancelFeedback(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().popCard())
    .build();
}
