# Kurogane Design Rules

This document defines the visual and interaction rules for the Kurogane web UI (`web/app`). AI agents and
contributors must follow it for every UI change. When a rule here conflicts with a default from a library, a
template, or a model's habit, this document wins.

## 1. Product and audience

Kurogane is a self-hosted server management tool. Its users are operators who manage one server or a fleet.
Every screen exists to let the operator spot a problem and act on it: a firing alert, a failed hardening check, a
pending SSH change. Layout, emphasis, and color follow that job. Decoration does not.

Design read: an operations console for system administrators, in a calm, dense, utilitarian style.

Dial: ENERGY 1 / RHYTHM 1 / MOTION 1

- ENERGY 1: the operator scans this UI under pressure; the data is the loudest thing on screen.
- RHYTHM 1: screens repeat one structure (title, filters, card with table) so every page reads the same way.
- MOTION 1: hover and focus states only; nothing moves unless the operator acts.

Identity motif: the ink sidebar with the shield mark, set against an off-white work area. It is the one element that
makes the product recognizable, and it repeats on every authenticated screen.

Focal point: each screen leads with what needs action. On the Overview, active alerts come first, ahead of the
live metrics.

## 2. Palette

The brand palette has four colors. No other brand colors are introduced.

| Name       | Hex       | Role                                                                        |
|------------|-----------|-----------------------------------------------------------------------------|
| Ink        | `#061E29` | Text in light mode; page background in dark mode; the sidebar in both.      |
| Deep teal  | `#1D546D` | Primary actions in light mode (buttons, links styled as buttons, meters).   |
| Muted teal | `#5F9598` | The single accent: focus ring in both modes, primary actions in dark mode.  |
| Off-white  | `#F3F4F4` | Page background in light mode; text in dark mode.                           |

Measured contrast (WCAG):

| Pair                                                  | Ratio  | Use            |
|-------------------------------------------------------|--------|----------------|
| `#FFFFFF` on `#1D546D`                                | 8.26:1 | Light primary  |
| `#061E29` on `#5F9598`                                | 5.09:1 | Dark primary   |
| `#4A6572` (muted text) on `#F3F4F4`                   | 5.61:1 | Light muted    |
| `#9DB4BA` (muted text) on `#0B2A38` (dark card)       | 6.90:1 | Dark muted     |
| `#5F9598` (ring) on `#F3F4F4`                         | 3.05:1 | Focus ring     |

`#5F9598` fails 4.5:1 as text on light surfaces. Never use it for body text or labels in light mode.

## 3. Tokens

All colors live in `web/app/assets/css/main.css` as CSS variables and are exposed to Tailwind through
`@theme inline`. Components use token classes (`bg-primary`, `text-muted-foreground`, `border-border`,
`text-crit`). Components never use raw hex values or Tailwind palette classes such as `bg-blue-500` or
`text-gray-600`.

The single exception is `components/MetricChart.vue`, where ECharts requires literal colors. Its neutrals (axis
ink, grid lines, tooltip) must match the token values below; its categorical series palette is fixed and must not
be replaced with brand colors, because multi-series charts need clearly distinct hues.

| Token                | Light      | Dark                      |
|----------------------|------------|---------------------------|
| `background`         | `#F3F4F4`  | `#061E29`                 |
| `foreground`         | `#061E29`  | `#F3F4F4`                 |
| `card`               | `#FFFFFF`  | `#0B2A38`                 |
| `popover`            | `#FFFFFF`  | `#0E3142`                 |
| `primary`            | `#1D546D`  | `#5F9598`                 |
| `primary-foreground` | `#FFFFFF`  | `#061E29`                 |
| `secondary`/`accent` | `#E3EDEE`  | `#12394A`                 |
| `muted`              | `#E6EBEC`  | `#12394A`                 |
| `muted-foreground`   | `#4A6572`  | `#9DB4BA`                 |
| `border`             | `#D5DEE0`  | `rgb(243 244 244 / 12%)`  |
| `input`              | `#B9C7CA`  | `rgb(243 244 244 / 20%)`  |
| `ring`               | `#5F9598`  | `#5F9598`                 |

To add a token, add it to both `:root` and `.dark`, map it in `@theme inline`, verify contrast in both modes, and
record it in this table.

## 4. Theme

- The UI supports light and dark modes through the existing toggle (`useDark` in `layouts/default.vue`). Every
  change must work in both.
- The sidebar and the mobile header always render in the dark token scope (the `dark` class on the element). This
  anchors the ink color in light mode without separate sidebar tokens. Do not add `--sidebar-*` variables.

## 5. Status colors

- `ok`, `warn`, and `crit` mark real system state only: alert severity, check results, connection state, meter
  thresholds. They are never used for decoration, emphasis, or branding.
- State is never conveyed by color alone. Use `StateBadge`, which renders the state word with its color. Add new
  state words to its map instead of styling badges by hand.
- `destructive` is reserved for destructive actions and error messages.
- Status hues are intentionally distinct from the brand teal. Do not tint them toward the palette.

## 6. Accent

Muted teal (`#5F9598`) is the only accent. It appears on the focus ring, as the primary action color in dark mode,
and as the active navigation surface inside the sidebar. It does not appear on borders, dividers, icons, headings,
or backgrounds elsewhere.

## 7. Typography

- Sans: IBM Plex Sans (variable, `@fontsource-variable/ibm-plex-sans`). Mono: IBM Plex Mono, weights 400 and
  500, Latin subset only (`@fontsource/ibm-plex-mono`). Reason: Plex was drawn for engineering tools, and its mono
  separates `0`/`O` and `l`/`1`/`I`, which matters when an operator reads IPs, hostnames, and key fingerprints.
- Fonts are bundled through `nuxt.config.ts` and embedded in the Go binary, so the UI never fetches fonts from the
  internet. Do not add a font CDN, a third family, or more mono weights.
- ECharts draws on a canvas and does not inherit CSS fonts; `MetricChart` sets the Plex family explicitly.
- Mono: only for machine values that the operator copies or compares: SSH key fingerprints, IP addresses, file
  paths, config keys and values, audit action names, CIS identifiers. Never for headings or decoration.
- Numbers in tables, stat cards, and counters use `tabular-nums`.
- Headings use sentence case. No uppercase labels with wide letter-spacing.
- Page title: `text-2xl font-semibold`. Card title: the `CardTitle` default. Supporting text: `text-sm` or
  `text-xs` with `text-muted-foreground`.

## 8. Shape, spacing, and elevation

- Radius comes from the `--radius` scale (`rounded-md`, `rounded-lg`, `rounded-xl`). Pills (`rounded-full`) are
  limited to badges, meters, and status dots.
- Cards are flat: a border on a white (light) or `#0B2A38` (dark) surface over the page background. Cards carry no
  shadow. Shadows are allowed only on floating layers: popovers, dropdowns, dialogs, tooltips, toasts.
- No glassmorphism, `backdrop-blur`, or glow.
- Page content sits in `main` with `space-y-6`; related controls group with `gap-2` to `gap-4`. Use the Tailwind
  spacing scale; no arbitrary pixel values.

## 9. Components to reuse

Use existing components before writing new markup.

| Need                                   | Use                                                   |
|----------------------------------------|-------------------------------------------------------|
| Buttons, inputs, dialogs, tables, tabs | `components/ui/*` (shadcn-vue)                        |
| A single metric with optional meter    | `StatCard`                                            |
| Any state or severity label            | `StateBadge`                                          |
| Loading, error, or empty async block   | `LoadState`                                           |
| Time-series chart                      | `MetricChart`                                         |
| Confirmation before a risky action     | `ConfirmButton`, `RiskDialog`                         |
| Pending SSH change countdown           | `PendingBanner`                                       |
| Labelled select                        | `FormSelect`                                          |
| Before/after text                      | `DiffView`                                            |
| Brand mark (shield on deep teal tile)  | `Logo`; keep it identical to `public/favicon.svg`     |
| Dates, durations, sizes, percentages   | `ago`, `fmtDate`, `pct`, `bytes`, `num` (composables) |

Merge class overrides with `cn` from `web/app/lib`.

Every table sits inside `<Card><CardContent>`. When a table is loaded asynchronously, the `LoadState` goes inside
the `CardContent` with the table, so loading, error, and empty states appear in the same card. Filters and action
buttons for a table stay above the card.

## 10. States

- Every async block goes through `LoadState` (or an equivalent with the same three states).
- Empty text names the reason and the next action, for example: "No servers enrolled. Create an enrollment token
  under Fleet." Do not write "No data" or "Nothing here".
- Error states show the server's message through `errMsg`.
- Loading uses `Skeleton` sized like the content it replaces.

## 11. Icons

- Icons come from `@lucide/vue` at `size-4`, with `aria-hidden="true"` when a text label is present. Icon-only
  buttons require an `aria-label`. Reason: Lucide is the set shadcn-vue is built on, so component glyphs (select
  chevrons, dialog close) and page icons share one stroke weight; mixing sets would look inconsistent.
- Icons appear in navigation and on actions where they speed recognition. No decorative icons on headings, cards,
  or list items, and no sparkle, magic, or robot glyphs.
- No arrow glyphs on buttons unless the action navigates away from the app.

## 12. Motion

No animation beyond the transitions built into the shadcn components (dialogs, dropdowns, tooltips). No looping,
pulsing, bouncing, or entrance animations. Charts render with `animation: false`. Status dots do not pulse.

## 13. Copy and data

- Sentence case, plain operator language, no emoji, no marketing tone.
- Show real values, or a hyphen (`-`) when a value is missing. Never invent metrics, deltas, names, or activity
  entries.
- An action keeps one name through the flow: the button says "Acknowledge", the toast says "Acknowledged". Spell
  actions out ("Acknowledge", not "Ack"). Placeholders describe the input ("Any user"), never a sample value that
  could be mistaken for a filled field.
- Never use the em dash character in UI text. Use a comma, colon, period, or parentheses instead.
- Empty states name the reason and the next action, and every claim in them must match what the backend does.
- Placeholders describe the expected input (`123456` for a TOTP code is acceptable because it shows the format).

## 14. Accessibility

- Text contrast is at least 4.5:1; UI boundaries and focus indicators are at least 3:1, in both modes.
- Every interactive element is keyboard reachable and shows the global `focus-visible` outline.
- Keep the skip link, `aria-current` on navigation, `role="alert"` on blocking banners, and `role="meter"` with
  values on meters.
- Layouts must work from 360 px wide upward; wide tables scroll horizontally inside their card.
- On touch devices, buttons, inputs, selects, tabs, and navigation links are at least 44 px tall. This is applied
  with the `pointer-coarse:` variant in the shared components, so mouse layouts keep their density. New controls
  must follow the same pattern.

## 15. Forbidden

The following are not permitted without a written reason added to this document:

- Gradients, colored glows, radial blobs, or background grid and dot patterns.
- Colors outside the palette and status tokens.
- Glassmorphism or `backdrop-blur`.
- Shadows on cards or inline content.
- Eyebrow pill badges above headings; decorative "New", "Beta", or "AI" badges.
- Decorative status dots that mark no real state.
- Left-edge color stripes that carry no state.
- Fake terminal windows, illustrations, or stock imagery.
- Generic dashboard filler: invented stat cards, activity feeds, or charts without a stated question.

## 16. Checklist before merging a UI change

- [ ] Only token classes are used; no raw hex or Tailwind palette colors (except `MetricChart`).
- [ ] The change was checked in light and dark mode, including the ink sidebar.
- [ ] Status colors mark real state and are paired with a word.
- [ ] New text and UI pairs meet 4.5:1 and 3:1 contrast.
- [ ] Async content has loading, error, and empty states with actionable empty text.
- [ ] Every control works with the keyboard and shows a focus outline.
- [ ] No new animation, shadow, gradient, or decorative icon was introduced.
- [ ] `pnpm typecheck` and `pnpm build` pass in `web/`.
