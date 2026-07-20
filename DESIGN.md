---
name: Patchwork Security Lab
description: Calm, evidence-first tools for code repair, AI security, and transparent market research.
colors:
  canvas: "oklch(1 0 0)"
  page: "oklch(0.97 0.006 242)"
  surface-subtle: "oklch(0.95 0.009 242)"
  surface-selected: "oklch(0.95 0.035 242)"
  text: "oklch(0.25 0.035 252)"
  text-strong: "oklch(0.18 0.035 252)"
  text-muted: "oklch(0.44 0.035 252)"
  border: "oklch(0.88 0.012 242)"
  border-strong: "oklch(0.76 0.02 242)"
  signal-blue: "oklch(0.5 0.14 242)"
  signal-blue-hover: "oklch(0.42 0.14 242)"
  signal-blue-soft: "oklch(0.96 0.035 242)"
  signal-blue-border: "oklch(0.86 0.04 242)"
  critical: "oklch(0.48 0.18 27)"
  high: "oklch(0.5 0.14 55)"
  medium: "oklch(0.46 0.11 82)"
  low: "oklch(0.48 0.09 242)"
  info: "oklch(0.45 0.03 252)"
  success: "oklch(0.45 0.11 153)"
typography:
  display:
    fontFamily: "Avenir Next, Avenir, ui-sans-serif, system-ui, sans-serif"
    fontSize: "3.375rem"
    fontWeight: 700
    lineHeight: 1.03
    letterSpacing: "-0.035em"
  headline:
    fontFamily: "Avenir Next, Avenir, ui-sans-serif, system-ui, sans-serif"
    fontSize: "1.5rem"
    fontWeight: 700
    lineHeight: 1.17
  body:
    fontFamily: "Avenir Next, Avenir, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "Avenir Next, Avenir, ui-sans-serif, system-ui, sans-serif"
    fontSize: "0.75rem"
    fontWeight: 700
    lineHeight: 1.2
  code:
    fontFamily: "SFMono-Regular, Consolas, Liberation Mono, Menlo, monospace"
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.55
rounded:
  control: "8px"
  panel: "12px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "40px"
components:
  button-primary:
    backgroundColor: "{colors.signal-blue}"
    textColor: "{colors.canvas}"
    rounded: "{rounded.control}"
    padding: "12px 18px"
  button-primary-hover:
    backgroundColor: "{colors.signal-blue-hover}"
    textColor: "{colors.canvas}"
    rounded: "{rounded.control}"
    padding: "12px 18px"
  button-secondary:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.text-strong}"
    rounded: "{rounded.control}"
    padding: "10px 14px"
  input:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.text}"
    rounded: "{rounded.control}"
    padding: "12px 14px"
  panel:
    backgroundColor: "{colors.canvas}"
    textColor: "{colors.text}"
    rounded: "{rounded.panel}"
    padding: "24px"
---

# Design System: Patchwork Security Lab

## 1. Overview

**Creative North Star: "The Release Review Desk"**

A technical reviewer is working in a bright workroom and needs quiet, legible
evidence rather than spectacle—whether inspecting a security finding, a repair
result, or a market-model opinion. The system combines GitHub Security's evidence
density, Linear's disciplined hierarchy, and Stripe Docs' explanatory clarity.
Product controls are familiar; distinctiveness comes from unusually clear
evidence structure and honest language.

The visual system is light-first and restrained. Pure white work surfaces sit
on a lightly blue-tinted structural field. Cobalt is a scarce signal for focus,
selection, and primary action. Severity color always travels with a label and
icon. Motion communicates state in 140–200 milliseconds and disappears under
reduced-motion preferences.

**Key Characteristics:**

- Evidence-dense without feeling alarmist
- Flat, bordered work surfaces with progressive disclosure
- Fixed product typography rather than fluid marketing type
- Familiar, fully keyboard-accessible controls
- Color-independent severity and confidence communication

## 2. Colors

The palette uses neutral blue-gray architecture and one cold signal-blue anchor.
Semantic colors are dark enough to carry labels and are never the sole status
indicator.

### Primary

- **Signal Blue** (`signal-blue`): primary actions, keyboard focus, selected
  tabs, links, and the current finding. It occupies less than 10% of a screen.
- **Soft Signal Blue** (`signal-blue-soft`): selected or explanatory surfaces;
  never used as an ambient page wash.

### Secondary

- **Resolution Green** (`success`): successful checks and safe-state icons.
- **Evidence Orange** (`high`) and **Review Ochre** (`medium`): risk semantics,
  always paired with text and a distinct glyph.

### Neutral

- **Canvas** (`canvas`): primary work surfaces and input fields.
- **Instrument Field** (`page`): structural page background.
- **Strong Ink** (`text-strong`): headings and decisive labels.
- **Working Ink** (`text`): body copy and data.
- **Muted Ink** (`text-muted`): secondary metadata that still meets body-text
  contrast requirements.
- **Divider** (`border`) and **Control Edge** (`border-strong`): hierarchy without
  shadow-heavy elevation.

**The Signal-Light Rule.** Brand color marks an action, focus, or current state.
If it does none of those jobs, it does not earn the color.

**The Paired-Severity Rule.** Critical, high, medium, low, and informational
colors must always appear with their written label and icon or shape.

## 3. Typography

**Display Font:** Avenir Next with system sans fallbacks
**Body Font:** Avenir Next with system sans fallbacks
**Label/Mono Font:** SFMono-Regular with Consolas, Liberation Mono, and Menlo
fallbacks

**Character:** One technical-humanist sans keeps product controls familiar.
Monospace is reserved for code, rule IDs, filesystem paths, timestamps, and
metrics so evidence boundaries remain explicit.

### Hierarchy

- **Display** (700, 3.375rem / 2.75rem / 2.25rem responsive steps, 1.03): the
  single product introduction heading.
- **Headline** (700, 1.5rem, 1.17): finding-detail titles and major result states.
- **Title** (700, 1.1875rem, 1.3): tool sections and review surfaces.
- **Body** (400, 0.875rem, 1.55): explanations, remediation, and limitations;
  prose is capped around 70 characters.
- **Label** (700, 0.75rem, 1.2): form labels, filters, and metadata headings.
- **Code** (400, 0.75rem, 1.55): evidence snippets, rule IDs, and locations.

**The Evidence Type Rule.** Never use monospace as a security costume. Use it
only when content is literally machine-addressable or executable.

## 4. Elevation

The system is flat by default. Depth comes from the white canvas against the
instrument field, 1px structural borders, and spacing. Wide decorative shadows
are forbidden. Temporary focus uses an explicit three-pixel ring; dropdowns or
future overlays may use a short structural shadow no larger than eight pixels
of blur.

**The Flat Evidence Rule.** Findings do not float decoratively. Their importance
comes from order, severity labels, evidence, and current selection.

## 5. Components

### Buttons

- **Shape:** restrained control corners (`8px`).
- **Primary:** Signal Blue fill, white text, 12px × 18px padding; disabled state
  remains visibly unavailable without relying on opacity alone.
- **Hover / Focus:** a darker blue hover and a three-pixel focus ring. State
  transitions last 140ms and become instant when reduced motion is requested.
- **Secondary:** white surface, strong ink, and one structural border; never a
  border plus wide shadow.

### Chips

- **Style:** full pills are reserved for compact severity, confidence, CWE, and
  filter labels. Each severity chip contains both a glyph and text.
- **State:** selected filters use Soft Signal Blue plus an explicit pressed state.

### Cards / Containers

- **Corner Style:** compact panels (`12px`) and controls (`8px`).
- **Background:** Canvas over Instrument Field.
- **Shadow Strategy:** none at rest.
- **Border:** one-pixel Divider or state-specific full border.
- **Internal Padding:** 18–24px depending on information density.

### Inputs / Fields

- **Style:** white field, Control Edge border, 8px corners, leading target-type
  icon, and a persistent plain-language helper.
- **Focus:** Signal Blue border plus a three-pixel focus ring.
- **Error / Disabled:** an inline alert with icon and text; errors never erase the
  previous successful report.

### Navigation

The sticky top bar identifies the lab, current tool, and passive safety boundary.
A conventional top-level product switch separates Sentinel from SignalLab;
source and website modes remain nested within Sentinel. On small screens the
current-tool label collapses before the safety icon.

### Finding Workspace

The result surface uses a summary strip, filter row, selectable finding list,
and detailed evidence pane. Selected rows use a complete background state, not
a colored side stripe. Detail order is fixed: observation, impact, remediation,
verification, references.

### Market Research Workspace

SignalLab uses the same evidence hierarchy without borrowing trading-terminal
theater. The opinion always travels with its benchmark, horizon, as-of date,
calibrated probability, untouched holdout metrics, factor contributions, and
limitations. Bullish and bearish states include text and directional glyphs;
green and red are never the only distinction. The disclaimer stays visible in
the result rather than hiding behind an info icon.

## 6. Do's and Don'ts

### Do:

- **Do** present observation, impact, confidence, remediation, and verification
  in a consistent order.
- **Do** use `signal-blue` only for action, focus, link, or current selection.
- **Do** use full borders and tonal layers instead of decorative side stripes.
- **Do** pair every severity color with text and an icon.
- **Do** preserve visible focus, keyboard order, reduced-motion behavior, and
  zero horizontal overflow at 390px.
- **Do** say when a result is heuristic, incomplete, sample data, or blocked by
  a safety policy.
- **Do** label synthetic market data and show the model's held-out error beside
  every stock opinion.

### Don't:

- **Don't** use neon “hacker movie” visuals or decorative terminal noise.
- **Don't** use fear-based breach language or imply automated scanning replaces
  professional penetration testing.
- **Don't** use opaque risk scores, noisy enterprise dashboards, or generic SaaS
  card grids.
- **Don't** use decorative AI imagery, gradient text, glassmorphism, colored
  side-stripe borders, or gratuitous motion.
- **Don't** use display typography in buttons, table labels, filters, or code.
- **Don't** combine a one-pixel border with a wide soft shadow or exceed 16px
  corners on panels.
- **Don't** use “buy,” “sell,” “winner,” guaranteed-return language, or a lone
  green/red score as an investment conclusion.
