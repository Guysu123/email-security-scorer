/**
 * Per-user result cache using PropertiesService.
 *
 * Why PropertiesService instead of in-memory: Apps Script has no shared
 * in-memory state across invocations. PropertiesService.getUserProperties()
 * persists per-user across runs and across Vercel cold starts.
 *
 * Key:  "bec_<messageId>"
 * TTL:  30 minutes
 * Limit: 9 KB per property — compactForCache() strips excess before writing.
 */

var CACHE_TTL_MS  = 30 * 60 * 1000; // 30 minutes
var CACHE_KEY_PREFIX = "bec_";
var CACHE_MAX_BYTES  = 9000;         // 9 KB property value limit (safe margin under 9216)

/**
 * Returns cached analysis data for a messageId, or null on miss/expiry.
 * @param {string} messageId
 * @returns {Object|null}
 */
function getCachedResult(messageId) {
  try {
    var raw = PropertiesService.getUserProperties().getProperty(CACHE_KEY_PREFIX + messageId);
    if (!raw) return null;
    var entry = JSON.parse(raw);
    if (!entry || typeof entry.ts !== "number" || !entry.data) return null;
    if (Date.now() - entry.ts > CACHE_TTL_MS) {
      PropertiesService.getUserProperties().deleteProperty(CACHE_KEY_PREFIX + messageId);
      return null;
    }
    return entry.data;
  } catch (e) {
    Logger.log("[Cache] Read error for " + messageId + ": " + (e.message || String(e)));
    return null;
  }
}

/**
 * Stores an analysis result for a messageId.
 * Full-scan results overwrite fast-scan results for the same messageId,
 * so subsequent opens always serve the most detailed cached result.
 * @param {string} messageId
 * @param {Object} data  AnalyzeResponse from the backend
 */
function setCachedResult(messageId, data) {
  try {
    var compact = compactForCache(data);
    var entry   = JSON.stringify({ ts: Date.now(), data: compact });
    if (entry.length > CACHE_MAX_BYTES) {
      Logger.log("[Cache] Skipping cache for " + messageId + " — " + entry.length + " bytes exceeds limit");
      return;
    }
    PropertiesService.getUserProperties().setProperty(CACHE_KEY_PREFIX + messageId, entry);
    Logger.log("[Cache] Stored " + entry.length + " bytes for " + messageId);
  } catch (e) {
    Logger.log("[Cache] Write error for " + messageId + ": " + (e.message || String(e)));
  }
}

/**
 * Produces a compacted version of an AnalyzeResponse that fits within 9 KB.
 * - Strips requestId/analysisId (not used by CardBuilder)
 * - Removes signal arrays for zero-score scanners
 * - Caps signals per scanner at 3, truncates description/evidence strings
 */
function compactForCache(data) {
  var scannerResults = (data.scannerResults || []).map(function(s) {
    var compactSignals = s.score > 0
      ? (s.signals || []).slice(0, 3).map(function(sig) {
          return {
            signalId:    sig.signalId,
            description: (sig.description || "").slice(0, 100),
            severity:    sig.severity,
            evidence:    (sig.evidence    || "").slice(0, 40)
          };
        })
      : [];
    return {
      scannerId:            s.scannerId,
      displayName:          s.displayName,
      score:                s.score,
      weight:               s.weight,
      weightedContribution: s.weightedContribution,
      riskLevel:            s.riskLevel,
      executionMs:          s.executionMs,
      signals:              compactSignals
    };
  });

  return {
    finalScore:      data.finalScore,
    riskLevel:       data.riskLevel,
    verdict:         data.verdict,
    partialAnalysis: !!data.partialAnalysis,
    topSignals:      (data.topSignals || []).map(function(s) {
      return {
        signalId:    s.signalId,
        description: (s.description || "").slice(0, 150),
        severity:    s.severity,
        scannerId:   s.scannerId
      };
    }),
    scannerResults: scannerResults,
    metadata: {
      totalExecutionMs: data.metadata ? data.metadata.totalExecutionMs : 0
    }
  };
}
