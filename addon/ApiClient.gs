/**
 * HTTP client for the backend /api/analyze endpoint.
 * Uses UrlFetchApp — the only allowed HTTP mechanism in Apps Script.
 *
 * Security notes:
 *  - Payload is always serialized with JSON.stringify — never string-concatenated.
 *  - API secret comes from ScriptProperties, not source code.
 *  - muteHttpExceptions: true so we can handle HTTP errors gracefully.
 */

var REQUEST_TIMEOUT_MS = 25000; // Vercel function maxDuration is 30s

/**
 * @param {Object} payload - Structured email payload from MimeParser
 * @returns {{ ok: boolean, data: Object|null, statusCode: number, error: string|null }}
 */
function callAnalyzeApi(payload) {
  var url     = getBackendUrl() + "/api/analyze";
  var secret  = getApiSecret();
  var reqId   = payload.requestMetadata && payload.requestMetadata.requestId
    ? payload.requestMetadata.requestId
    : Utilities.getUuid();

  if (!secret) {
    return { ok: false, data: null, statusCode: 0, error: "ADDON_API_SECRET not configured in Script Properties" };
  }

  var options = {
    method:             "post",
    contentType:        "application/json",
    headers: {
      "Authorization":  "Bearer " + secret,
      "X-Request-ID":   reqId,
      "X-Addon-Version": ADDON_VERSION
    },
    payload:            JSON.stringify(payload),  // Safe: structured serialization
    muteHttpExceptions: true
  };

  try {
    var response    = UrlFetchApp.fetch(url, options);
    var statusCode  = response.getResponseCode();
    var rawBody     = response.getContentText("UTF-8");

    if (statusCode === 200) {
      var parsed = JSON.parse(rawBody);
      return { ok: true, data: parsed, statusCode: statusCode, error: null };
    }

    // Structured error response from backend
    var errBody = {};
    try { errBody = JSON.parse(rawBody); } catch (e) {}
    return {
      ok:         false,
      data:       null,
      statusCode: statusCode,
      error:      errBody.message || ("HTTP " + statusCode)
    };
  } catch (e) {
    return {
      ok:         false,
      data:       null,
      statusCode: 0,
      error:      e.message || "Network error"
    };
  }
}
