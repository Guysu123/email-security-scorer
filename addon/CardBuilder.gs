/**
 * Builds Gmail CardService UI cards from analysis results.
 * CardService has no CSS — we use widget composition and Unicode characters
 * to communicate severity visually.
 */

var SEVERITY_LABELS = {
  CRITICAL: "Critical",
  HIGH:     "High",
  MEDIUM:   "Medium",
  LOW:      "Low"
};

/** Returns the initial loading card shown while the API call is in flight */
function buildLoadingCard() {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Security Scorer")
        .setSubtitle("Analyzing…")
        .setImageUrl("https://upwind-email-scorer.vercel.app/icons/logo.svg")
        .setImageStyle(CardService.ImageStyle.CIRCLE)
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText("🔍 Running security analysis on this email…\n\nChecking authentication, URLs, sender reputation, and linguistic patterns.")
        )
    )
    .build();
}

/** Returns an error card when the API call fails */
function buildErrorCard(errorMessage) {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Security Scorer")
        .setSubtitle("Analysis Failed")
        .setImageUrl("https://upwind-email-scorer.vercel.app/icons/logo.svg")
        .setImageStyle(CardService.ImageStyle.CIRCLE)
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("Error")
            .setText(errorMessage || "Unable to reach analysis backend")
            .setWrapText(true)
        )
        .addWidget(
          CardService.newTextButton()
            .setText("Retry")
            .setOnClickAction(
              CardService.newAction().setFunctionName("onRetry")
            )
        )
    )
    .build();
}

/** Builds the main results card from a successful AnalyzeResponse */
function buildResultCard(data) {
  var riskConfig = RISK_COLORS[data.riskLevel] || RISK_COLORS["LOW"];

  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Security Scorer")
        .setSubtitle("Upwind Security Analysis")
        .setImageUrl("https://upwind-email-scorer.vercel.app/icons/logo.svg")
        .setImageStyle(CardService.ImageStyle.CIRCLE)
    );

  // ── Risk badge + score ────────────────────────────────────────────────────
  var summarySection = CardService.newCardSection()
    .addWidget(
      CardService.newDecoratedText()
        .setTopLabel("RISK LEVEL")
        .setText(riskConfig.label)
        .setBottomLabel("Score: " + data.finalScore + " / 100")
        .setWrapText(false)
    )
    .addWidget(
      CardService.newTextParagraph()
        .setText("<i>" + (data.verdict || "") + "</i>")
    );

  if (data.recommendation && data.riskLevel !== "LOW") {
    summarySection.addWidget(
      CardService.newDecoratedText()
        .setTopLabel("What To Do?")
        .setText(data.recommendation)
        .setWrapText(true)
    );
  }

  card.addSection(summarySection);

  // ── Top signals ───────────────────────────────────────────────────────────
  if (data.topSignals && data.topSignals.length > 0) {
    var topSection = CardService.newCardSection()
      .setHeader("⚠ Key Findings");

    data.topSignals.forEach(function(signal) {
      topSection.addWidget(
        CardService.newDecoratedText()
          .setText(SEVERITY_LABELS[signal.severity] || signal.severity)
          .setBottomLabel(signal.description)
          .setWrapText(true)
      );
    });

    card.addSection(topSection);
  }

  // ── Scanner breakdown (collapsible) ──────────────────────────────────────
  if (data.scannerResults && data.scannerResults.length > 0) {
    var detailSection = CardService.newCardSection()
      .setHeader("Why this score?")
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(0);

    data.scannerResults.forEach(function(scanner) {
      detailSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(scanner.displayName)
          .setText(scanner.score + " / 100")
          .setBottomLabel(
            scanner.signals.length > 0
              ? scanner.signals[0].description.slice(0, 80)
              : "No issues detected"
          )
          .setWrapText(true)
      );
    });

    // Attribution
    detailSection.addWidget(
      CardService.newTextParagraph()
        .setText(
          "<font color=\"#888888\"><i>Analysis by Upwind Email Scorer v" +
          ADDON_VERSION +
          (data.partialAnalysis ? " · partial results" : "") +
          "</i></font>"
        )
    );

    card.addSection(detailSection);
  }

  // ── Actions ───────────────────────────────────────────────────────────────
  var stableId = String((data.analysisId) || (data.metadata && data.metadata.timestamp) || "unknown");

  var actionsSection = CardService.newCardSection()
    .addWidget(
      CardService.newButtonSet()
        .addButton(
          CardService.newTextButton()
            .setText("Re-analyze")
            .setTextButtonStyle(CardService.TextButtonStyle.OUTLINED)
            .setOnClickAction(
              CardService.newAction().setFunctionName("onRetry")
            )
        )
        .addButton(
          CardService.newTextButton()
            .setText("My Statistics")
            .setTextButtonStyle(CardService.TextButtonStyle.OUTLINED)
            .setOnClickAction(
              CardService.newAction().setFunctionName("onShowStats")
            )
        )
    )
    .addWidget(
      CardService.newTextButton()
        .setText("Dispute score")
        .setTextButtonStyle(CardService.TextButtonStyle.TEXT)
        .setOnClickAction(
          CardService.newAction()
            .setFunctionName("onShowFeedbackForm")
            .setParameters({
              messageId: stableId,
              score:     String(data.finalScore),
              riskLevel: data.riskLevel
            })
        )
    );

  if (getWebAppUrl()) {
    actionsSection.addWidget(
      CardService.newTextButton()
        .setText("Open Stats Dashboard")
        .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
        .setOnClickAction(CardService.newAction().setFunctionName("onOpenDashboard"))
    );
  }

  card.addSection(actionsSection);

  return card.build();
}

/** Builds the feedback form card for disputing a score */
function buildFeedbackFormCard(messageId, score, riskLevel) {
  var riskConfig = RISK_COLORS[riskLevel] || RISK_COLORS["LOW"];

  var selectionInput = CardService.newSelectionInput()
    .setType(CardService.SelectionInputType.RADIO_BUTTON)
    .setFieldName("suggestedRisk")
    .setTitle("What do you think the correct risk level is?");

  ["CRITICAL", "HIGH", "MEDIUM", "LOW"].forEach(function(r) {
    selectionInput.addItem(
      RISK_COLORS[r].label,
      r,
      r === riskLevel
    );
  });

  var submitAction = CardService.newAction()
    .setFunctionName("onSubmitFeedback")
    .setParameters({ messageId: String(messageId || "unknown"), score: String(score), riskLevel: riskLevel });

  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Leave Feedback")
        .setSubtitle("Help us improve the scorer")
        .setImageUrl("https://upwind-email-scorer.vercel.app/icons/logo.svg")
        .setImageStyle(CardService.ImageStyle.CIRCLE)
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newDecoratedText()
            .setTopLabel("ORIGINAL SCORE")
            .setText(riskConfig.label)
            .setBottomLabel("Score: " + score + " / 100")
        )
    )
    .addSection(
      CardService.newCardSection()
        .addWidget(selectionInput)
        .addWidget(
          CardService.newTextInput()
            .setFieldName("comment")
            .setTitle("Comment")
            .setHint("What makes you think the score is off?")
            .setMultiline(true)
        )
        .addWidget(
          CardService.newButtonSet()
            .addButton(
              CardService.newTextButton()
                .setText("Submit")
                .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
                .setOnClickAction(submitAction)
            )
            .addButton(
              CardService.newTextButton()
                .setText("Cancel")
                .setTextButtonStyle(CardService.TextButtonStyle.OUTLINED)
                .setOnClickAction(
                  CardService.newAction().setFunctionName("onCancelFeedback")
                )
            )
        )
    )
    .build();
}

/** Risk emoji map used in the stats card */
var RISK_EMOJI = { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🟢" };

/** Builds the statistics card showing aggregated score data for the current user */
function buildStatsCard() {
  var stats = computeStats();

  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("My Email Stats")
        .setSubtitle("Your personal security overview")
        .setImageUrl("https://upwind-email-scorer.vercel.app/icons/logo.svg")
        .setImageStyle(CardService.ImageStyle.CIRCLE)
    );

  if (stats.total === 0) {
    card.addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextParagraph()
            .setText("No emails analyzed yet.\n\nOpen an email to get started.")
        )
    );
    return card.build();
  }

  // ── Overview ──────────────────────────────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .setHeader("Overview")
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel("TOTAL ANALYZED")
          .setText(String(stats.total) + " emails")
      )
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel("AVERAGE SCORE")
          .setText(stats.avgScore + " / 100")
      )
      .addWidget(
        CardService.newDecoratedText()
          .setTopLabel("MOST COMMON RISK")
          .setText((RISK_EMOJI[stats.mostCommonRisk] || "") + " " + stats.mostCommonRisk)
      )
  );

  // ── By risk level ─────────────────────────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .setHeader("Breakdown by Risk Level")
      .addWidget(
        CardService.newDecoratedText()
          .setText("🔴 Critical")
          .setBottomLabel(String(stats.byRisk.CRITICAL) + " email" + (stats.byRisk.CRITICAL !== 1 ? "s" : ""))
      )
      .addWidget(
        CardService.newDecoratedText()
          .setText("🟠 High")
          .setBottomLabel(String(stats.byRisk.HIGH) + " email" + (stats.byRisk.HIGH !== 1 ? "s" : ""))
      )
      .addWidget(
        CardService.newDecoratedText()
          .setText("🟡 Medium")
          .setBottomLabel(String(stats.byRisk.MEDIUM) + " email" + (stats.byRisk.MEDIUM !== 1 ? "s" : ""))
      )
      .addWidget(
        CardService.newDecoratedText()
          .setText("🟢 Low")
          .setBottomLabel(String(stats.byRisk.LOW) + " email" + (stats.byRisk.LOW !== 1 ? "s" : ""))
      )
  );

  // ── Recent history (collapsible) ──────────────────────────────────────────
  if (stats.recent.length > 0) {
    var historySection = CardService.newCardSection()
      .setHeader("Recent History")
      .setCollapsible(true)
      .setNumUncollapsibleWidgets(3);

    stats.recent.forEach(function(entry) {
      var dateLabel = "";
      try {
        dateLabel = Utilities.formatDate(new Date(entry.ts), Session.getScriptTimeZone(), "MMM d");
      } catch (e) {
        dateLabel = "";
      }
      var riskEmoji = RISK_EMOJI[entry.risk] || "";
      historySection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(dateLabel + "  " + riskEmoji + " " + entry.risk)
          .setText((entry.subj || "(no subject)").slice(0, 40))
          .setBottomLabel((entry.from || "").slice(0, 40) + "  ·  " + entry.score + " / 100")
          .setWrapText(true)
      );
    });

    card.addSection(historySection);
  }

  // ── Open full dashboard link ──────────────────────────────────────────
  if (getWebAppUrl()) {
    card.addSection(
      CardService.newCardSection()
        .addWidget(
          CardService.newTextButton()
            .setText("Open Full Dashboard")
            .setTextButtonStyle(CardService.TextButtonStyle.FILLED)
            .setOnClickAction(CardService.newAction().setFunctionName("onOpenDashboard"))
        )
    );
  }

  return card.build();
}
