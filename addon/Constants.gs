/**
 * Runtime constants loaded from Script Properties (encrypted by Google).
 * Never hard-code secrets in source files.
 *
 * To set properties: Apps Script Editor → Project Settings → Script Properties
 *   BACKEND_URL     = https://your-project.vercel.app   (or ngrok URL for local dev)
 *   ADDON_API_SECRET = <shared secret matching Vercel env var>
 */

var ADDON_VERSION = "1.0.1";

function getBackendUrl() {
  return PropertiesService.getScriptProperties().getProperty("BACKEND_URL") ||
    "https://upwind-email-scorer.vercel.app";
}

function getApiSecret() {
  return PropertiesService.getScriptProperties().getProperty("ADDON_API_SECRET") || "";
}

function getEncryptionKey() {
  return PropertiesService.getScriptProperties().getProperty("PAYLOAD_ENCRYPTION_KEY") || null;
}

// UI color constants for risk levels
var RISK_COLORS = {
  CRITICAL: { icon: "ERROR", label: "🔴 CRITICAL RISK" },
  HIGH:     { icon: "ERROR", label: "🟠 HIGH RISK"     },
  MEDIUM:   { icon: "WARNING_SEVERE", label: "🟡 MEDIUM RISK"   },
  LOW:      { icon: "CHECK_CIRCLE", label: "🟢 LOW RISK"     }
};

