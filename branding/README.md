# Gapura

**Gapura** is the product name for this Rust rewrite (owner decision, 2026-10-31). A *gapura* is the traditional Indonesian and Balinese gateway; the split *candi bentar* form is the gate every visitor passes through. An identity provider is that gate for every user before they reach their applications.

The mark is a *candi bentar*: two mirrored, stepped tower halves standing on a plinth, with the split between them carved into a keyhole. It is drawn in Majapahit red-brick terracotta.

## Files

| File | Use |
| --- | --- |
| `gapura-mark.svg` | Square mark (512×512): app icon, avatar, sidebar |
| `gapura-logo.svg` | Mark + wordmark, for light backgrounds |
| `gapura-logo-on-dark.svg` | Mark + wordmark, for dark backgrounds |
| `favicon.svg` | Simplified mark (fewer steps) that stays legible at 16 px |

## Colors

| Role | Hex |
| --- | --- |
| Brick, top of gradient | `#DE6B43` |
| Brick, bottom of gradient | `#A63F22` |
| Brick, flat (favicon) | `#C4542F` |
| Plinth | `#7A2E19` |
| Wordmark on light | `#1F2433` |
| Wordmark on dark | `#F4EDE8` |

## Rules

- The wordmark is lowercase `gapura`, bold geometric sans. It is currently SVG text with a font stack; it must be outlined into paths before release so it renders the same everywhere (M18).
- Do not recolor the mark, separate the halves further, or remove the keyhole.
- Branding is applied in M18, after the rewrite is complete (`docs/MIGRATION_PLAN.md`). Until then the product still presents itself as authentik, so that the differential tests compare like with like.
- The upstream authentik attribution (MIT) stays in `NOTICE.md` permanently. Gapura must not use authentik's name or logo.
