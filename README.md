
[![HACS](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://hacs.xyz/)
[![GH Release](https://img.shields.io/github/v/release/roblandry/apex-fusion-home-assistant?sort=semver)](https://github.com/roblandry/apex-fusion-home-assistant/releases)
[![GH Last Commit](https://img.shields.io/github/last-commit/roblandry/apex-fusion-home-assistant?logo=github)](https://github.com/roblandry/apex-fusion-home-assistant/commits/main)
[![Codecov](https://codecov.io/gh/roblandry/apex-fusion-home-assistant/branch/main/graph/badge.svg)](https://codecov.io/gh/roblandry/apex-fusion-home-assistant)
[![GitHub Clones](https://img.shields.io/badge/dynamic/json?color=success&label=Clone&query=count&url=https://gist.githubusercontent.com/roblandry/90aeef6ae32b7dd94f74f067de2277fb/raw/clone.json&logo=github)](https://github.com/MShawon/github-clone-count-badge)
![GH Code Size](https://img.shields.io/github/languages/code-size/roblandry/apex-fusion-home-assistant)
[![BuyMeCoffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-donate-FFDD00?logo=buymeacoffee&logoColor=black)](https://www.buymeacoffee.com/roblandry)

# Apex Fusion (Local)

> [!CAUTION]
> This is a Work In Progress and is subject to changes

Home Assistant custom integration for local (LAN) polling of an Apex controller.

## Features

- REST-first polling with legacy (CGI) fallback
- Config flow (UI setup)
- Input/probe sensors (Temp, pH, Cond, Trident results, etc)
- Digital inputs as binary sensors (leak/float switches, etc)
- Output control via 3-way selects (Off / Auto / On)
- Firmware update entities (controller + modules)
- Trident reagent + waste container level sensors (mL)
- Designed for stable device identity and robust backoff on rate limiting

## Installation

### HACS (Custom Repository)

> [!CAUTION]
> This is a Work In Progress and is subject to changes. It will be added to HACS once complete.

<del>

1. HACS → Integrations → 3-dot menu → **Custom repositories**
2. Add this repository URL as **Integration**
3. Install **Apex Fusion (Local)**
4. Restart Home Assistant

</del>

### Manual

Copy `custom_components/apex_fusion` into your Home Assistant `config/custom_components/apex_fusion` folder, then restart Home Assistant.

## Configuration

Add the integration from Home Assistant UI:

1. Settings → Devices & services → Add integration
2. Search for **Apex Fusion (Local)**

   > [!TIP]
   > Recommend using `admin` user with default password of `1234` or changing the password.
   > It is known that the user logged in will log out any users using the local webpages.

## Entities

This integration provides entities across these Home Assistant platforms:

- **Sensors**
  - Probes/inputs from the controller (temperature, pH, conductivity, Trident readings, etc)
  - Trident container levels from `status.modules[].extra.levels` (mL)
    - Trident Waste Used (mL)
    - Trident Reagent A/B/C Remaining (mL)
    - Trident Auxiliary Level (mL)
- **Binary sensors**
  - Digital inputs (leak/float switches)
  - Trident Testing (when a Trident is present)
- **Selects**
  - One select per controllable output: Off / Auto / On
  - Sends control via the local REST API (`PUT /rest/status/outputs/<did>`)
- **Updates**
  - Controller firmware update entity, named by controller type (example: `AC6J Firmware`)
  - Module firmware update entities (FMM, PM2, VDM, TRI, etc)

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

Diagnostic sensors expose network/controller state (examples):

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

> Important: The Update entities are **informational only**. This integration does not
> initiate or install firmware updates. Apply firmware updates using Neptune’s own
> workflow (Fusion/app/controller UI).

- **Controller update** uses controller-reported values (prefers `/rest/config/nconf` when
  available, otherwise `/rest/status`):
  - Installed version from `system.software`
  - Latest version from `nconf.latestFirmware` / `nstat.latestFirmware`
  - Update flag from `nconf.updateFirmware` / `nstat.updateFirmware`
- **Module update** support varies by firmware. This integration uses (in priority order):
  - Module config flags from `/rest/config/mconf` when present
  - Module status signals from `/rest/status.modules[]` (`swrev` and `swstat`)

If a module doesn't report a concrete latest version, the integration will still surface
useful state:

- `swstat: OK` -> assumes up-to-date (latest == installed)
- `swstat: UPDATE` -> reports update available even if no version string is provided

## Trident Support

When a Trident module is present (`hwtype: TRI`), the integration exposes:

- Trident Status sensor
- Trident Testing binary sensor
- Trident container levels (mL) from `modules[].extra.levels`

## Development

- Create and use `.venv`
- Run tests: `.venv/bin/pytest -q`
- Lint: `.venv/bin/ruff check .`

## License

MIT. See [LICENSE](LICENSE).
