/**
 * Extracts structured data from a GmailMessage for the analysis request.
 * Apps Script gives us the full raw message; we extract what we need here
 * so the backend receives typed, labelled fields rather than a raw MIME dump.
 */

/**
 * @param {GoogleAppsScript.Gmail.GmailMessage} message
 * @returns {Object} Structured payload ready for POST /api/analyze
 */
function extractEmailPayload(message) {
  var rawContent = message.getRawContent();

  // Split raw content into headers block and body
  var headerBodySplit = rawContent.indexOf("\r\n\r\n");
  if (headerBodySplit === -1) headerBodySplit = rawContent.indexOf("\n\n");
  var rawHeaders = headerBodySplit !== -1
    ? rawContent.slice(0, headerBodySplit)
    : rawContent.slice(0, 4096); // fallback: first 4KB

  // Truncate headers defensively (64KB max per sanitizer.ts)
  if (rawHeaders.length > 65536) rawHeaders = rawHeaders.slice(0, 65536);

  // Extract plain text and HTML bodies from rawContent — no extra Gmail API calls
  var plainText = getPlainBodyFromRaw(rawContent) || null;
  var htmlBody  = getHtmlBody(rawContent) || null;

  // Truncate to match backend limits
  if (plainText && plainText.length > 51200) plainText = plainText.slice(0, 51200);
  if (htmlBody  && htmlBody.length  > 20480) htmlBody  = htmlBody.slice(0, 20480);

  // Attachment metadata only — never send attachment content
  var attachments = [];
  try {
    var blobs = message.getAttachments({ includeAttachments: true, includeInlineImages: false });
    attachments = blobs.map(function(blob) {
      return {
        filename:  blob.getName() || "unknown",
        mimeType:  blob.getContentType() || "application/octet-stream",
        sizeBytes: blob.getSize(),
        sha256Hint: null
      };
    });
  } catch (e) {
    Logger.log("Attachment extraction failed: " + e.message);
  }

  var from    = message.getFrom();     // "Display Name <email@domain.com>"
  var replyTo = message.getReplyTo();  // may be empty string

  return {
    envelope: {
      messageId:         message.getHeader("Message-ID") || message.getId(),
      gmailThreadId:     message.getThread().getId(),
      receivedTimestamp: message.getDate().toISOString()
    },
    rawHeaders: rawHeaders,
    sender: {
      displayName:  parseDisplayName(from),
      emailAddress: parseEmailAddress(from),
      replyTo:      replyTo || null
    },
    subject: message.getSubject() || "(no subject)",
    body: {
      plainText:   plainText,
      htmlContent: htmlBody
    },
    attachments: attachments,
    requestMetadata: {
      addonVersion: ADDON_VERSION,
      requestId:    Utilities.getUuid(),
      timestamp:    new Date().toISOString()
    }
  };
}

/** Extract the display name portion from a "Name <email>" string */
function parseDisplayName(from) {
  var match = from.match(/^([^<]+)</);
  return match ? match[1].trim() : from;
}

/** Extract the email address portion from a "Name <email>" string */
function parseEmailAddress(from) {
  var match = from.match(/<([^>]+)>/);
  if (match) return match[1].trim().toLowerCase();
  // Fallback: treat entire string as email if no angle brackets
  return from.trim().toLowerCase();
}

/**
 * Extract the plain-text body from raw MIME without an extra Gmail API call.
 * Handles multipart (finds text/plain part) and simple non-multipart emails.
 */
function getPlainBodyFromRaw(rawContent) {
  var plainMatch = rawContent.match(
    /Content-Type:\s*text\/plain[^\n]*\n(?:[^\n]+\n)*?\n([\s\S]*?)(?=\n--|\n\n--|\s*$)/i
  );
  if (plainMatch) {
    var body = plainMatch[1].trim();
    // Check CTE only within this part's headers, not the whole raw content
    var partStart = rawContent.indexOf(plainMatch[0]);
    var partHeadersEnd = rawContent.indexOf("\n\n", partStart);
    var partHeaders = rawContent.slice(partStart, partHeadersEnd);
    if (/Content-Transfer-Encoding:\s*base64/i.test(partHeaders)) {
      try {
        body = Utilities.newBlob(
          Utilities.base64Decode(body.replace(/\s/g, ""))
        ).getDataAsString("UTF-8");
      } catch (e) {}
    }
    return body || null;
  }
  // Simple non-multipart email: body follows the header block
  var split = rawContent.indexOf("\r\n\r\n");
  if (split === -1) split = rawContent.indexOf("\n\n");
  return split !== -1 ? rawContent.slice(split + 4).trim() || null : null;
}

/**
 * Attempt to find the HTML part of a MIME message.
 * Gmail's getBody() returns the plain body; we need to parse the raw MIME
 * to find the text/html part for structural analysis.
 */
function getHtmlBody(rawContent) {
  // Simple boundary-based MIME parser — finds first text/html part
  var htmlMatch = rawContent.match(/Content-Type:\s*text\/html[^\n]*\n(?:[^\n]+\n)*?\n([\s\S]*?)(?=\n--|\n\n--|\s*$)/i);
  if (!htmlMatch) return null;

  var body = htmlMatch[1];

  // Decode Content-Transfer-Encoding if base64
  var cteMath = rawContent.match(/Content-Transfer-Encoding:\s*(base64|quoted-printable)/i);
  if (cteMath && cteMath[1].toLowerCase() === "base64") {
    try {
      body = Utilities.newBlob(Utilities.base64Decode(body.replace(/\s/g, "")))
                       .getDataAsString("UTF-8");
    } catch (e) {
      // If decoding fails, return raw
    }
  }

  return body.slice(0, 204800); // 200KB max
}
