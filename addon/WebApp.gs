/**
 * Web app entry point for the stats dashboard.
 *
 * HOW TO SET UP:
 *   1. In the Apps Script editor: Deploy → New Deployment → Web app
 *      - Execute as: Me
 *      - Who has access: Only myself (or Anyone with the link for sharing)
 *   2. Copy the deployment URL.
 *   3. Script Properties → add  STATS_WEBAPP_URL = <paste URL here>
 *   4. The "Open Stats Dashboard" button in the add-on will now open the page.
 *
 * The page calls getStatsData() via google.script.run to read UserProperties
 * server-side, so no data ever leaves Google's infrastructure.
 */

/** Serves Stats.html as the web app response */
function doGet(e) {
  return HtmlService.createHtmlOutputFromFile("Stats")
    .setTitle("Email Security Dashboard")
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

/**
 * Called by Stats.html via google.script.run.
 * Runs in the user's context so it can access UserProperties.
 * @returns {{ stats: Object, history: Array, feedback: Array }}
 */
function getStatsData() {
  return {
    stats:    computeStats(),
    history:  getScoreHistory(),
    feedback: getFeedbackHistory()
  };
}
