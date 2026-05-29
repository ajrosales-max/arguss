# Template partials (HTMX fragments)

Included from full pages or returned alone from `POST /dashboard/*` handlers.

## Layout / chrome

| Partial | Purpose |
|---------|---------|
| [`_nav.html`](_nav.html) | Top navigation |
| [`_footer.html`](_footer.html) | Page footer |
| [`_logo.html`](_logo.html) | Logo markup |
| [`_mode_tabs.html`](_mode_tabs.html) | Scan / upload / action tabs |
| [`_section_heading.html`](_section_heading.html) | Reusable section title |
| [`_team_member.html`](_team_member.html) | About page team card |
| [`_citation_card.html`](_citation_card.html) | Source citation block |

## Results page

| Partial | Purpose |
|---------|---------|
| [`_summary_banner.html`](_summary_banner.html) | PRS, counts, executive summary |
| [`_exec_summary.html`](_exec_summary.html) | Executive summary body |
| [`_lens_tile.html`](_lens_tile.html) | Per-lens score tile |
| [`_signals_strip.html`](_signals_strip.html) | Key risk signals |
| [`_tier_filter.html`](_tier_filter.html) | AUTO_MERGE / REVIEW / DECLINE filter |
| [`_finding_card.html`](_finding_card.html) | Single finding + verdict card |
| [`_package_row.html`](_package_row.html) | Package table row |
| [`_actions_section.html`](_actions_section.html) | Mode C action outcomes |
| [`_skipped_section.html`](_skipped_section.html) | Skipped dependency groups |
| [`_skipped.html`](_skipped.html) | Single skipped item |
| [`_empty_state.html`](_empty_state.html) | No results placeholder |
| [`_dependency_graph_placeholder.html`](_dependency_graph_placeholder.html) | Graph UI placeholder |
| [`_glossary_section.html`](_glossary_section.html) | Glossary accordion |
| [`_glossary_link.html`](_glossary_link.html) | Inline glossary term link |

## Chat and errors

| Partial | Purpose |
|---------|---------|
| [`_chat_panel.html`](_chat_panel.html) | Q&A panel shell |
| [`_chat_turn.html`](_chat_turn.html) | One chat message turn |
| [`_chat_error.html`](_chat_error.html) | Chat failure message |
| [`_error_card.html`](_error_card.html) | Scan error card (HTMX) |
| [`_loading_indicator.html`](_loading_indicator.html) | In-flight scan spinner |
