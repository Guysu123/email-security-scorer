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
