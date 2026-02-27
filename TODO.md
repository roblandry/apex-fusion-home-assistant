# TODO / Roadmap

This is a small roadmap of improvements planned (or being considered) for this Home Assistant integration.

## Known working (my setup)

As of 2026-01-31, I actively run this integration against:

- **Controller type:** AC6J
- **Firmware:** 5.12J_CA25
- **APIs available:** REST (`/rest/*`) is expected; legacy CGI endpoints (`/cgi-bin/status.*`) may also be present and are used only as fallback
- **Modules observed via REST:**
  - FMM
  - MXM
  - Trident ACM (`TRI`)
  - Trident NP (`TNP`) (added 2/27/2026)
  - PM2
  - VDM

Notes:

- Everything in my environment is newer hardware; REST support is expected.
- Trident entities are gated on Trident presence.

## Short-term

- Improve docs around what data is sourced from REST vs legacy CGI.
- Expand “device dump” contribution instructions (what to share, how to redact, what endpoints help most).
- Tighten entity naming/unique IDs so entity renames don’t create duplicates.
- Decide on a task tracking approach (GitHub Issues/Projects vs a static roadmap file).

## Module coverage

- Confirm module-type detection + entity gating for:
  - DOS
  - PMUP
  - EB832/EB8 variants
  - AFS
- Firmware-related:
  - Confirm whether firmware update reporting via Home Assistant Update entities should be enabled by default (or kept optional)

## Medium-term

- Broaden module detection + entity gating (only create entities when the backing module/feature is present).
- Add more resilient parsing for optional/missing fields across firmware generations.
- Add a small set of parsing tests backed by redacted fixtures.

## Longer-term / Nice-to-have

- More module-specific entities where the controller provides stable, real values (no guessed percentages).
- Better handling of REST rate limiting / backoff and clearer logs when falling back to legacy.
- Add a simple troubleshooting guide (common symptoms → what to collect → what logs/dumps to include).

## Work tracking

If you prefer “real tasks” over a static list, the best fit is to open GitHub Issues (and optionally manage them with GitHub Projects). This file can stay as a high-level roadmap.
