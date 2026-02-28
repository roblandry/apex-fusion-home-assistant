
[![HACS](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://hacs.xyz/)
[![GH Release](https://img.shields.io/github/v/release/roblandry/apex-fusion-home-assistant?sort=semver)](https://github.com/roblandry/apex-fusion-home-assistant/releases)
[![GH Last Commit](https://img.shields.io/github/last-commit/roblandry/apex-fusion-home-assistant?logo=github)](https://github.com/roblandry/apex-fusion-home-assistant/commits/main)
[![Codecov](https://codecov.io/gh/roblandry/apex-fusion-home-assistant/branch/main/graph/badge.svg)](https://codecov.io/gh/roblandry/apex-fusion-home-assistant)
[![GitHub Clones](https://img.shields.io/badge/dynamic/json?color=success&label=Clone&query=count&url=https://gist.githubusercontent.com/roblandry/90aeef6ae32b7dd94f74f067de2277fb/raw/clone.json&logo=github)](https://github.com/MShawon/github-clone-count-badge)
![GH Code Size](https://img.shields.io/github/languages/code-size/roblandry/apex-fusion-home-assistant)
[![BuyMeCoffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-donate-FFDD00?logo=buymeacoffee&logoColor=black)](https://www.buymeacoffee.com/roblandry)

# Apex Fusion (Local)

Home Assistant custom integration for local (LAN) polling of an Apex controller.

If you’ve tried other Apex options and found gaps (cloud dependence, stale support, or missing local REST/module support), I’d love feedback on what you need—this project aims to close those gaps with a local-first approach.

Contributors are welcome (issues, testing feedback, and PRs).

> [!WARNING]
> This project is not affiliated with Neptune Systems and has no connection to the Apex Fusion
> cloud service. It communicates only with the controller on your local network.
>
> Use at your own discretion. Firmware updates are applied via Neptune’s workflow, and this
> project cannot guarantee update safety. You assume all risk, including potential device
> malfunction or warranty implications.

> [!NOTE]
> The Apex REST API and legacy CGI endpoints can report different device/module layouts.
>
> This integration validates REST logins: if you provide credentials and they’re wrong, setup/update
> fails (no silent fallback).
>
> If the integration switches between REST and legacy parsing, or between read-only and authenticated
> control, it will purge stale entities/devices from the previous mode on the next reload to avoid
> confusing duplicates.

## Features

- REST-first polling with legacy (CGI) fallback
- Config flow (UI setup)
- Input/probe sensors (Temp, pH, Cond, Trident results, etc)
- Digital inputs as binary sensors (leak/float switches, etc)
- Optional **No login (read-only)** mode (visual-only)
- Output mode as a **read-only sensor** when control is unavailable
- Output control via 3-way selects (Off / Auto / On) when authenticated REST is available
- Firmware version entities (controller + modules) when REST is available
- Trident-family waste/reagent support (levels + alerts + controls, when a Trident `TRI` or Trident NP `TNP` is present)
- Designed for stable device identity and robust backoff on rate limiting

## Tested / Intended Hardware

This integration is designed for Neptune Apex controllers reachable on your LAN.

- **Written for** controllers that expose the local REST API (for example: `GET /rest/status`, `GET /rest/config`).
- **Fallback support** for legacy/older firmwares that only expose `GET /cgi-bin/status.xml` (best-effort).
- **Developed against** real controller payloads including Trident-family modules (container level sensors are only created when a Trident-family module is detected).

If your controller/modules behave differently, please consider contributing a redacted dump (see Development below) so support can be expanded safely.

### Known working (my setup)

As of 2026-01-31, I actively run this integration against:

- **Controller type:** AC6J (A3 Apex Jr)
- **Firmware:** 5.12J_CA25
- **APIs available:** REST (`/rest/*`) is expected; legacy CGI endpoints (`/cgi-bin/status.*`) may also be present and are used only as fallback
- **Modules observed via REST:**
  - FMM (Software Version: **24**)
  - MXM (Software Version: **1**)
  - Trident ACM (`TRI`) (Software Version: **23**)
  - Trident NP (`TNP`) (Software Version: **54**)
  - PM2 (Software Version: **3**)
  - VDM (Software Version: **13**)

## Installation

### HACS (Custom Repository)

1. HACS → Integrations → 3-dot menu → **Custom repositories**
2. Add this repository URL as **Integration**
3. Install **Apex Fusion (Local)**
4. Restart Home Assistant

> [!NOTE]
> Once this repository is accepted into the HACS default store, it will no longer need to be added as a custom repository.
>
> The brand icon is added to [Home Assistant Brands](https://github.com/home-assistant/brands/pull/9527)

### Manual

Copy `custom_components/apex_fusion` into your Home Assistant `config/custom_components/apex_fusion` folder, then restart Home Assistant.

## Configuration

Add the integration from Home Assistant UI:

1. Settings → Devices & services → Add integration
2. Search for **Apex Fusion (Local)**

    > [!TIP]
    > `admin` (default password `1234`) is recommended because it's commonly preconfigured, but it is not required.
    >
    > Best practice is to create a **dedicated Apex account** for Home Assistant and avoid using the same account in the
    > Apex **local web UI** at the same time (shared local logins can cause session conflicts).
    >
    > If you run more than one local integration / Home Assistant instance against the same controller, use **separate
    > Apex accounts** for each.

### Login modes (important)

This integration supports two modes:

- **Authenticated (control enabled)**
  - Provide a username + password.
  - The integration validates the REST login.
  - Control entities (select/switch/button/number) are created.
- **No login (read-only / visual-only)**
  - Enable **No login (read-only)** in the config flow (or leave the password blank).
  - No control entities are created.
  - You still get sensors/binary_sensors (including a read-only outlet mode sensor when the controller reports outlet state).

If you previously had a wrong password and saw “weird” devices/entities: that was the legacy CGI layout. With validation enabled,
wrong credentials will now fail loudly instead of silently switching data sources.

## Entities

This integration provides entities across these Home Assistant platforms.

Always created:

- **Sensors**
  - Probes/inputs from the controller (temperature, pH, conductivity, Trident readings, etc)
  - Outlet intensity sensors for variable/serial outputs
  - Trident-family container levels (mL) when a Trident-family module is detected
- **Binary sensors**
  - Digital inputs (leak/float switches)
  - Per-module **Connected** diagnostics (one per Aquabus module from config)
  - Trident-family Testing / Waste Full / Reagent Empty alerts (when a Trident-family module is present)

Only when **REST is active** (no legacy CGI parsing):

- **Updates** (read-only firmware version entities)
- **Network diagnostics** (IP, gateway, netmask, Wi‑Fi SSID/strength/quality, DHCP/Wi‑Fi enabled)

Only when **REST is active and login is enabled** (authenticated control):

- **Selects**
  - One select per controllable output: Off / Auto / On
  - Control via `PUT /rest/status/outputs/<did>`
- **Switches** (Feed modes)
- **Buttons** (Refresh config + Trident actions)
- **Numbers** (Trident waste container size)

When control is unavailable (legacy or read-only), outlet “mode” is exposed as a **sensor** (visual-only) instead of a SelectEntity.

### Naming & Uniqueness (important)

Home Assistant entity_ids must be globally unique within your HA instance.

This integration intentionally prefixes **suggested entity IDs** with a tank/controller slug derived from the controller hostname (spaces/underscores normalized), so you can:

- Run **multiple Apex controllers** in one HA instance without entity_id collisions.
- Re-add / migrate controllers without accidentally reusing old entity IDs.

Notes:

- This affects **entity_id** (used in automations), not the entity's display name.
- Home Assistant only applies suggested IDs when an entity is first created, so upgrading may not change existing entity_ids automatically.

If you rely on old entity_ids in automations, review the Entity Registry after upgrading.

#### Outlet collisions

Outlets usually have a unique `device_id` (`did`), but some controller payloads can contain duplicates.
When this happens, the integration disambiguates the affected entities using module identity (Aquabus address / hwtype).

To preserve Home Assistant history:

- If a `did` is unique in the current payload, the entity uses the plain `did` (no suffix).
- Only when a `did` collides does the integration suffix it (for example `did@abaddr`).

### Config Refresh

Config is larger and changes less frequently than status, so it is refreshed on a slower cadence than `/rest/status`.

If you need config changes to show up immediately (including after using Trident control entities), use the controller button entity "Refresh Config Now" to force an immediate `/rest/config` refresh.

### Entity attributes (examples)

Select entities expose useful attributes for dashboards/automations:

```yaml
state: Auto
options: Off, Auto, On
state_code: TBL
mode: AUTO
effective_state: On
output_id: 12
type: MXMPump|AI|Axis
gid: 0
status: TBL, , Cnst, OK
icon: mdi:pump
friendly_name: 80g_Frag_Tank AI Axis (Axis 90)
```

```yaml
State: Off
options: Off, Auto, On
state_code: AON
mode: AUTO
percent: 100
effective_state: On
output_id: 21
type: serial
gid: null
status: AON, 100, OK,
icon: mdi:power-socket-us
friendly_name: 80g_Frag_Tank WhtLED 6 6
```

Binary sensors have attributes like:

```yaml
state: off
value: 0
type: digital
device_class: opening
icon: mdi:toggle-switch-outline
friendly_name: 80g_Frag_Tank Level
```

Sensors have attributes like:

```yaml
state: 33.6
state_class: measurement
unit_of_measurement: ppt
icon: mdi:flash
friendly_name: 80g_Frag_Tank Cond
```

When **REST is active**, diagnostic sensors expose network/controller state (examples):

```yaml
DHCP Enabled: On
Gateway: 10.0.30.1
IP Address: 10.0.30.40
Last Alert Statement: Unknown
Netmask: 255.255.255.0
Wi-Fi Enabled: On
Wi-Fi Quality: 99.0%
Wi-Fi SSID: MySSID-IoT-2.4
Wi-Fi Strength: 100.0%
```

## Firmware Updates

Home Assistant has a first-class Update platform; this integration exposes firmware
updates there.

These entities are only available when REST parsing is active (they are not created in legacy CGI mode).

> Important: The Update entities are **informational only**. This integration does not
> initiate or install firmware updates. Apply firmware updates using Neptune’s own
> workflow (Fusion/app/controller UI).

- **Controller update** uses controller-reported values (prefers sanitized config from `/rest/config` when
  available, otherwise `/rest/status`):
  - Installed version from `system.software`
  - Latest version from `nconf.latestFirmware` / `nstat.latestFirmware`
  - Update flag from `nconf.updateFirmware` / `nstat.updateFirmware`
- **Module update** support varies by firmware. This integration uses (in priority order):
  - Module config flags from sanitized config (from `/rest/config`) when present
  - Module status signals from `/rest/status.modules[]` (`swrev` and `swstat`)

If a module doesn't report a concrete latest version, the integration will still surface
useful state:

- `swstat: OK` -> assumes up-to-date (latest == installed)
- `swstat: UPDATE` -> reports update available even if no version string is provided

## Trident Support

When a Trident-family module is present (`hwtype: TRI` or `hwtype: TNP`), the integration exposes:

- Trident-family Status sensor
- Trident-family Testing binary sensor
- Trident-family container levels (mL) from `modules[].extra.levels`
- Trident-family Waste Full + Reagent Empty binary sensors
- Trident-family controls: Prime (Reagents + Sample), Reset Reagent, Reset Waste
- Trident-family Waste Container Size number entity (mL)

If more than one Trident-family module is detected, entities are created per module (keyed by Aquabus address). In Home Assistant, this typically shows up as separate Trident devices, each with its own set of sensors/controls.

> Note: On Trident NP (`TNP`), reagents are labeled as **Reagent 1/2/3** (instead of A/B/C).

Some firmwares also expose Trident **selector outputs** (for example names like `Trident_5_3` / `Alk_5_4`).
When present, they appear as output mode selects (Off/Auto/On). Setting them to **On** may initiate the corresponding test, depending on firmware.

## Development

- Create and use `.venv`
- Run tests: `.venv/bin/pytest -q`
- Lint: `.venv/bin/ruff check .`
- Optional (commit messages): `pip install -r requirements.txt` then run `cz commit` for an interactive Conventional Commit prompt

### Contributions

Contributions are welcome. The goal of this integration is to stay compatible with Home Assistant **LATEST** and to only expose entities backed by stable, controller-provided values.

Before opening a PR:

- Run tests: `.venv/bin/pytest -q`
- Run lint: `.venv/bin/ruff check .`
- If you change parsing/entity behavior, include updated/added pytest coverage (PRs that break tests won’t be accepted).

If your change depends on real controller payloads (new module support, missing fields, firmware differences), a redacted device dump is the fastest way to validate behavior (see the Device dump helper below). Please do not commit unredacted dumps.

### Device dump helper

The repo includes a local-only helper script for collecting controller payloads to help add support for additional devices/modules:

- Dump one controller (redacted by default): `python3 apex_dev.py dump --ip 192.168.1.50`
- Scan a subnet (noisy; use carefully): `python3 apex_dev.py scan --cidr 192.168.1.0/24`

Notes:

- Dumps are written under `.dev/dumps/` by default (gitignored).
- Redaction is enabled by default. Set `APEX_REDACT=0` only if you understand the risks.
- You can provide credentials via `--username/--password` or `APEX_USERNAME`/`APEX_PASSWORD` (optionally in a `.env`).

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=roblandry/apex-fusion-home-assistant&type=date&legend=top-left)](https://www.star-history.com/#roblandry/apex-fusion-home-assistant&type=date&legend=top-left)

## License

MIT. See [LICENSE](LICENSE).
