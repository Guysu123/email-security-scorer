/**
 * Builds Gmail CardService UI cards from analysis results.
 * CardService has no CSS — we use widget composition and Unicode characters
 * to communicate severity visually.
 */

/** Returns the initial loading card shown while the API call is in flight */
function buildLoadingCard() {
  return CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Security Scorer")
        .setSubtitle("Analyzing…")
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
  var scoreBar   = buildScoreBar(data.finalScore);

  var card = CardService.newCardBuilder()
    .setHeader(
      CardService.newCardHeader()
        .setTitle("Email Security Scorer")
        .setSubtitle("Upwind Security Analysis")
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
        .setText(scoreBar)
    )
    .addWidget(
      CardService.newTextParagraph()
        .setText("<i>" + (data.verdict || "") + "</i>")
    );

  card.addSection(summarySection);

  // ── Top signals ───────────────────────────────────────────────────────────
  if (data.topSignals && data.topSignals.length > 0) {
    var topSection = CardService.newCardSection()
      .setHeader("⚠ Key Findings");

    data.topSignals.forEach(function(signal) {
      topSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(signal.severity)
          .setText(signal.description)
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
      var bar = buildScoreBar(scanner.score);
      detailSection.addWidget(
        CardService.newDecoratedText()
          .setTopLabel(scanner.displayName)
          .setText(bar)
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
          ADDON_VERSION + " · " +
          (data.metadata ? data.metadata.totalExecutionMs + "ms" : "") +
          (data.partialAnalysis ? " · partial results" : "") +
          "</i></font>"
        )
    );

    card.addSection(detailSection);
  }

  // ── Actions ───────────────────────────────────────────────────────────────
  card.addSection(
    CardService.newCardSection()
      .addWidget(
        CardService.newButtonSet()
          .addButton(
            CardService.newTextButton()
              .setText("Re-analyze")
              .setOnClickAction(
                CardService.newAction().setFunctionName("onRetry")
              )
          )
      )
  );

  return card.build();
}
