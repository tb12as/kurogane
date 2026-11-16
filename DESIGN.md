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

Identity motif: the round mark (keyhole with a `>_` prompt and an orange tab), on charcoal or warm cream surfaces.
It sits at the top of the sidebar on every authenticated screen and on the sign-in card, and it is the one element
that makes the product recognizable.

Focal point: each screen leads with what needs action. On the Overview, active alerts come first, ahead of the
live metrics.

## 2. Palette

The brand palette comes from the logo. No other brand colors are introduced.

| Name     | Hex       | Role                                                                          |
|----------|-----------|-------------------------------------------------------------------------------|
| Charcoal | `#0B0B0C` | Page background in dark mode.                                                 |
| Ink      | `#141416` | Text in light mode; text on primary actions in light mode.                    |
| Cream    | `#FAF6F1` | Page background in light mode.                                                |
| Bone     | `#EFEAE4` | Text in dark mode; muted surfaces in light mode.                              |
| Orange   | `#F65F0A` | The single accent: primary actions and the focus ring (see light mode below). |

Light mode uses two shades. Primary actions use burnt orange `#C2410C` so that their white text reaches 4.5:1.
The focus ring uses `#EE5A0A`, visually identical to the logo orange, because `#F65F0A` reaches only 2.98:1
against the cream background and the ring needs 3:1.

Measured contrast (WCAG):

| Pair                                                  | Ratio  | Use            |
|-------------------------------------------------------|--------|----------------|
| `#FFFFFF` on `#C2410C`                                | 5.18:1 | Light primary  |
| `#0B0B0C` on `#F65F0A`                                | 6.15:1 | Dark primary   |
| `#5E5D5B` (muted text) on `#FAF6F1`                   | 6.11:1 | Light muted    |
| `#A3A09C` (muted text) on `#161618` (dark card)       | 6.94:1 | Dark muted     |
| `#EE5A0A` (ring) on `#FAF6F1`                         | 3.20:1 | Focus ring     |
| `#F65F0A` (ring) on `#0B0B0C`                         | 6.15:1 | Focus ring     |
| `#8A837A` (input border) on a card                    | 3.70:1 | Field boundary |
| `#6E6A66` (input border) on a dark card               | 3.42:1 | Field boundary |

Primary actions use white text in light mode and charcoal text in dark mode; white on the bright logo orange is
3.2:1 and fails 4.5:1. Orange is never used for body text or labels on light surfaces.

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
| `background`         | `#FAF6F1`  | `#0B0B0C`                 |
| `foreground`         | `#141416`  | `#EFEAE4`                 |
| `card`               | `rgb(255 255 255 / 60%)` | `rgb(22 22 24 / 60%)` |
| `popover`            | `#FFFFFF`  | `#1C1C1F`                 |
| `primary`            | `#C2410C`  | `#F65F0A`                 |
| `primary-foreground` | `#FFFFFF`  | `#0B0B0C`                 |
| `secondary`/`accent` | `#EFEAE4`  | `#232326`                 |
| `muted`              | `#EFEAE4`  | `#232326`                 |
| `muted-foreground`   | `#5E5D5B`  | `#A3A09C`                 |
| `border`             | `#E3DDD5`  | `rgb(239 234 228 / 12%)`  |
| `input`              | `#8A837A`  | `#6E6A66`                 |
| `ring`               | `#EE5A0A`  | `#F65F0A`                 |

To add a token, add it to both `:root` and `.dark`, map it in `@theme inline`, verify contrast in both modes, and
record it in this table.

## 4. Theme

- The UI supports light and dark modes through the existing toggle (`useDark` in `layouts/default.vue`). Every
  change must work in both.
- The sidebar and the mobile header follow the active theme like the rest of the page, separated from the work area
  by a border. Do not add `--sidebar-*` variables.
- `Logo` shows the light emblem in light mode and the dark icon in dark mode (`dark:` variant). The favicon is
  the dark icon in both, since it sits on the browser tab strip rather than the page.

## 5. Status colors

- `ok`, `warn`, and `crit` mark real system state only: alert severity, check results, connection state, meter
  thresholds. They are never used for decoration, emphasis, or branding.
- State is never conveyed by color alone. Use `StateBadge`, which renders the state word with its color. Add new
  state words to its map instead of styling badges by hand.
- `destructive` is reserved for destructive actions and error messages.
- Status hues are not tinted toward the palette. Brand orange sits between `crit` and `warn`, so status is
  always paired with its word through `StateBadge` and never shown as an orange surface.

## 6. Accent

Orange is the only accent. It appears on primary actions, on the focus ring, and as the underline of
link-style buttons (the link text stays `foreground`, because orange text fails 4.5:1 on light surfaces). It does not
appear on borders, dividers, icons, headings, navigation, or backgrounds elsewhere; the active navigation item uses
the neutral `accent` surface. Meters below their warn threshold use `muted-foreground`, because orange is too
close to `warn` amber to tell a normal meter from a warning one.

### Logo files

`Logo` and the favicon use the delivered round icons as is, without resizing:

- Light mode: `public/logo-light-128.png` and `public/logo-light-256.png` (the 2x source in `srcset`) are copies of
  the 128x128 and 256x256 `Circular-Kurogane-Terminal-Emblem` files.
- Dark mode: `public/logo-128.png` and `public/logo-256.png` are copies of the 128x128 and 256x256
  `kurogane-dark-minimal-1080` files.
- Favicon: `public/favicon.png` is the 64x64 `kurogane-dark-minimal-1080` file.

Replace them by copying new files over these names.

### Background dither

The page background carries one texture: an orange ordered (8x8 Bayer) dither that fades out from the corners. It
gives the flat background some of the logo's character without competing with the data.

- Work area (`layouts/default.vue`): `DitherBackground` draws two fades, from the top-left and bottom-right
  corners, that die out before the middle (`lib/dither.ts`, tested in `tests/dither.test.ts`). It renders into a
  canvas at half resolution shown at exactly 2x with crisp pixels and redraws on resize. Opacity is
  `opacity-12 dark:opacity-20`. The sidebar stays flat.
- Sign-in page: two corners (bottom-right and mirrored top-left) from `web/public/dither-corner.png`, 240x150,
  through the `.dither` class, at `opacity-35 dark:opacity-60`.
- Nowhere else. In the work area the top-left fade sits under the page title and description, so do not raise its
  opacity above these values.
- Both are hidden under `prefers-contrast: more` and `forced-colors: active`. Under `prefers-contrast: more`
  cards also turn opaque, since there is nothing left to show through.
- Regenerate the PNG with:

  ```sh
  magick -size 240x150 xc: -fx "max(0,1-hypot((w-i)/w,(h-j)/h))^1.5" -ordered-dither o8x8 \
    -fill '#f65f0a' -opaque white -transparent black -strip PNG8:web/public/dither-corner.png
  ```

## 7. Typography

- Sans: IBM Plex Sans (variable, `@fontsource-variable/ibm-plex-sans`). Mono: IBM Plex Mono, weights 400 and
  500, Latin subset only (`@fontsource/ibm-plex-mono`). Reason: Plex was drawn for engineering tools, and its mono
  separates `0`/`O` and `l`/`1`/`I`, which matters when an operator reads IPs, hostnames, and key fingerprints.
- Brand: Montserrat, weights 400, 500 and 600, Latin subset only (`@fontsource/montserrat`), exposed as
  `font-brand`. It matches the logo artwork and is used only for the wordmark, page titles and the description
  paragraph that follows them (base rule `h1, h1 + p` in `main.css`), card titles (`CardTitle`), form labels
  (`Label`), input and select placeholders, and button text (`buttonVariants`). Body text, tables, badges, tabs
  and menus stay in IBM Plex Sans.
- Fonts are bundled through `nuxt.config.ts` and embedded in the Go binary, so the UI never fetches fonts from the
  internet. Do not add a font CDN, a fourth family, or more weights.
- ECharts draws on a canvas and does not inherit CSS fonts; `MetricChart` sets the Plex family explicitly.
- Mono: only for machine values that the operator copies or compares: SSH key fingerprints, IP addresses, file
  paths, config keys and values, audit action names, CIS identifiers. Never for headings or decoration.
- Numbers in tables, stat cards, and counters use `tabular-nums`.
- Headings use sentence case. No uppercase labels with wide letter-spacing.
- Wordmark: "KUROGANE" next to `Logo` (sidebar, mobile header, sign-in card) uses `font-brand` (Montserrat 500,
  Latin subset, `@fontsource/montserrat`) with `uppercase tracking-[0.2em]`, matching the logo artwork. It is the
  only uppercase, wide-tracked text.
- Page title: `text-2xl font-semibold`. Card title: the `CardTitle` default. Supporting text: `text-sm` or
  `text-xs` with `text-muted-foreground`.

## 8. Shape, spacing, and elevation

- Radius comes from the `--radius` scale (`rounded-md`, `rounded-lg`, `rounded-xl`). Pills (`rounded-full`) are
  limited to badges, meters, and status dots.
- Cards are flat: a border on a translucent white (light) or charcoal (dark) fill, 60% opaque, so the background
  dither continues through them, dimmed. Popovers stay opaque. Measured worst case (card over a dither dot):
  `foreground` 16.97:1 and `muted-foreground` 6.07:1 in light, 14.40:1 and 6.62:1 in dark. Cards carry no
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
| Brand mark (round keyhole, orange tab) | `Logo`; its files are copies of the delivered icon set (section 6) |
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

- Gradients, colored glows, radial blobs, or background grid and dot patterns, except the background dither
  in section 6.
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
- [ ] The change was checked in light and dark mode, including the sidebar and mobile header.
- [ ] Status colors mark real state and are paired with a word.
- [ ] New text and UI pairs meet 4.5:1 and 3:1 contrast.
- [ ] Async content has loading, error, and empty states with actionable empty text.
- [ ] Every control works with the keyboard and shows a focus outline.
- [ ] No new animation, shadow, gradient, or decorative icon was introduced.
- [ ] `pnpm typecheck` and `pnpm build` pass in `web/`.
