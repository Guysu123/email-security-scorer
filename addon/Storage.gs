/**
 * Persistent per-user storage for score history and feedback.
 * Uses PropertiesService.getUserProperties() — survives add-on restarts,
 * scoped automatically to the signed-in Google account.
 *
 * Keys:
 *   SCORE_HISTORY_V1  — JSON array of up to 100 scored-email entries
 *   FEEDBACK_LOG_V1   — JSON array of up to 50 user-feedback entries
 */

var SCORE_HISTORY_KEY  = "SCORE_HISTORY_V1";
var FEEDBACK_LOG_KEY   = "FEEDBACK_LOG_V1";
var MAX_HISTORY        = 100;
var MAX_FEEDBACK       = 50;
var STORAGE_MAX_BYTES  = 9000; // safe margin under 9 KB property limit

// ── Score history ──────────────────────────────────────────────────────────

/**
 * Returns the full score history array, newest-first.
 * @returns {Array}
 */
function getScoreHistory() {
  try {
    var raw = PropertiesService.getUserProperties().getProperty(SCORE_HISTORY_KEY);
    if (!raw) return [];
    return JSON.parse(raw) || [];
  } catch (e) {
    Logger.log("[Storage] getScoreHistory error: " + (e.message || String(e)));
    return [];
  }
}

/**
 * Prepends an entry to score history.
 * Deduplicates by entry.id so re-opening the same email doesn't add a second row.
 * Entry shape: { id, ts, score, risk, subj, from }
 * @param {Object} entry
 */
function appendScoreHistory(entry) {
  if (!entry || !entry.id) return;
  try {
    var arr = getScoreHistory();
    arr = arr.filter(function(e) { return e.id !== entry.id; });
    arr.unshift(entry);
    arr = arr.slice(0, MAX_HISTORY);
    var serialized = JSON.stringify(arr);
    if (serialized.length > STORAGE_MAX_BYTES) {
      // Drop oldest entries until it fits
      while (arr.length > 1 && serialized.length > STORAGE_MAX_BYTES) {
        arr.pop();
        serialized = JSON.stringify(arr);
      }
    }
    PropertiesService.getUserProperties().setProperty(SCORE_HISTORY_KEY, serialized);
  } catch (e) {
    Logger.log("[Storage] appendScoreHistory error: " + (e.message || String(e)));
  }
}

// ── Feedback log ───────────────────────────────────────────────────────────

/**
 * Returns the full feedback log array, newest-first.
 * @returns {Array}
 */
function getFeedbackHistory() {
  try {
    var raw = PropertiesService.getUserProperties().getProperty(FEEDBACK_LOG_KEY);
    if (!raw) return [];
    return JSON.parse(raw) || [];
  } catch (e) {
    Logger.log("[Storage] getFeedbackHistory error: " + (e.message || String(e)));
    return [];
  }
}

/**
 * Prepends a feedback entry. Deduplicates by entry.id.
 * Entry shape: { id, ts, score, risk, suggestedRisk, comment }
 * @param {Object} entry
 */
function appendFeedback(entry) {
  if (!entry || !entry.id) return;
  try {
    var arr = getFeedbackHistory();
    arr = arr.filter(function(e) { return e.id !== entry.id; });
    arr.unshift(entry);
    arr = arr.slice(0, MAX_FEEDBACK);
    var serialized = JSON.stringify(arr);
    if (serialized.length > STORAGE_MAX_BYTES) {
      while (arr.length > 1 && serialized.length > STORAGE_MAX_BYTES) {
        arr.pop();
        serialized = JSON.stringify(arr);
      }
    }
    PropertiesService.getUserProperties().setProperty(FEEDBACK_LOG_KEY, serialized);
  } catch (e) {
    Logger.log("[Storage] appendFeedback error: " + (e.message || String(e)));
  }
}

// ── Aggregated stats ───────────────────────────────────────────────────────

/**
 * Computes statistics over the full score history.
 * @returns {{ total: number, avgScore: number, mostCommonRisk: string, byRisk: Object, recent: Array }}
 */
function computeStats() {
  var history = getScoreHistory();
  var total   = history.length;

  if (total === 0) {
    return {
      total:          0,
      avgScore:       0,
      mostCommonRisk: "—",
      byRisk:         { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
      recent:         []
    };
  }

  var byRisk  = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  var scoreSum = 0;

  history.forEach(function(e) {
    scoreSum += (e.score || 0);
    if (byRisk.hasOwnProperty(e.risk)) byRisk[e.risk]++;
  });

  var avgScore = Math.round(scoreSum / total);

  // Most common risk level
  var mostCommonRisk = "LOW";
  var maxCount = 0;
  ["CRITICAL", "HIGH", "MEDIUM", "LOW"].forEach(function(r) {
    if (byRisk[r] > maxCount) { maxCount = byRisk[r]; mostCommonRisk = r; }
  });

  return {
    total:          total,
    avgScore:       avgScore,
    mostCommonRisk: mostCommonRisk,
    byRisk:         byRisk,
    recent:         history.slice(0, 10)
  };
}
