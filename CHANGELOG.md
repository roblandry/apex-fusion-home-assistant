# Changelog

All notable changes to this project will be documented in this file.

## v2026.10.23-beta.1

### Before you update

- Take a Home Assistant backup before installing this release.
- Before installing any controller firmware, read Neptune's release notes for that version and save your Apex configuration.
- Stay present while a firmware install runs.

### Features

- Controller (AOS) firmware can now be installed from Home Assistant's update entity. It is offered only for controllers using the REST connection with a password. A progress bar shows while the update runs, and the controller appears as unavailable while it reboots, without prompting you to log in again. The update request is sent once and is never retried automatically. The install counts as successful only when a newer version is reported and stays reported through a settling period; if that is not confirmed within 20 minutes, a Repairs issue is raised. Module firmware install is not included (#40, #41)

### Fixes

- Module firmware updates are now detected from the controller's status, excluding module types the controller never updates (#39)
- Leftover controller devices from the v2 migration are cleaned up. Orphans with no entities are removed automatically on restart; orphans that still hold old entities are kept and can now be deleted from the device page with the Delete button (#38)

### Known limitation

Before the update request is sent, the in-progress record is written with an atomic, fsynced file write. Durability beyond what the OS and filesystem guarantee (for example, power loss on storage that ignores fsync) is not guaranteed. Don't start a second update until the first has clearly finished or timed out.

## v2026.10.22-beta.1

**Take a Home Assistant backup before installing: this release runs a one-time migration that removes orphaned APEX 1.0 devices.**

### CI

- Releases are now cut automatically when a version bump merges (#35)
- Pin ruff (#32)

### Fixes

- Firmware update entities now show when a newer AOS version is available, even if the controller's "no update" flag is stale. Version comparison ignores the J/L hardware letter (#31)
- Each controller uses one connection method, chosen deterministically at setup (the newer REST API, detected by its login gate, or the older interface). An outage now shows entities as unavailable instead of switching methods, and the old wipe-on-restart cleanup is removed (#33)
- Stable device identity: a one-time migration keeps existing entity IDs, history and customizations, and removes the orphaned "APEX 1.0" devices left by the old fallback (#34)

## v0.1.6

### CI

- add a login check script
- pytest 100%

### Chores

- Add integration installs badge to README

### Features

- expose error codes
- add DOS/DQD sensors

### Fixes

- reorder tri/tnp prime buttons to map to correct reagent
- tnp/tri testing status inconsistent capitalization
- mxm_status line in selects
- login regression

## v0.1.5

### Chores

- update meta for no3 and po4
- Automatically added GitHub issue links to TODOs
- remove unreachable return
- v0.1.5

### Features

- set proper units + device classes for current (A), power (W), and voltage (V); Improve friendly names

### Fixes

- fix reagent naming

### Tests

- reach 100% coverage

## v0.1.4

### Chores

- remove '_' from hub name
- update readme
- v0.1.4

### Features

- add connected sensors to all modules

### Fixes

- fix login failure
- correct parsing for trident entities.
- login retries

### Refactors

- changed entity naming to be more in line with home assistant expectations

## v0.1.3

### Chores

- v0.1.3

### Features

- correct for and add trident np

## v0.1.2

### CI

- todo settings.json

### Chores

- fix todo workflow
- fix todo manual workflow
- Automatically added GitHub issue links to TODOs
- clean up old todo links
- add lables
- remove unused/unfound values
- v0.1.2

### Fixes

- optical level sensor reports 200 for closed.

## v0.1.1

### CI

- fix failing test
- generate coverage badge with genbadge
- fix genbadge invocation
- install genbadge coverage deps

### Chores

- chore(manifests) update manifests for addition to brands and HACS
- fix md lint
- chore(manifests) correct HACS manifest
- update changelog
- Inform users of BROKEN v0.1.0
- v0.1.1

### Features

- add read-only mode and strict REST auth

## v0.1.0

### Chores

- sync TODO issue links
- sync TODO issue links
- sync TODO issue links
- v0.1.0

### Features

- coordinator-driven REST control; add feed switches; restore 100% coverage; update README.md
- unified device info identifiers; added trident waste full and reagent empty binary sensors; buttons for trident priming and resetting reagents/waste; number entity for trident waste container; updated /rest/config polling; README update
- moved entities to their respective modules; renamed entities; added friendly names for probes; renamed firmware updates; new trident selects to initiate testing; added config refresh buttons to modules;

### Fixes

- replace missing icon

### Refactors

- reconfigure device naming scheme; Split trident into own device
- internal api
- clean internal api

## v0.1.0-rc.2

### Chores

- keep git-cliff output markdownlint-clean
- v0.1.0-rc.2

### Features

- allow re-login by removing and adding integration. this helps with using different user. update readme and strings to reflect best practices
- add reconfigure step to allow different login

### Fixes

- change 0 to open and 1 to closed to properly represent status

## v0.1.0-rc.1

### CI

- replace TODO-to-issue workflow with repo script

### Chores

- Initial commit
- Bump
- Automatically added GitHub issue links to TODOs
- Fix coverage url
- Fix manifest
- Fix coverage action
- Fix coverage action
- create clone count badge
- Add readme and license
- Move repo
- Update license to comply with Home Assistant
- Chenge from switched to 3 way selects with attributes
- Show trident testing message; Attempt warning message when notifications are triggered. Digital outputs show Open/Closed. Remove 'mode' from select friendly names. UoM for conductivity. Update Readme.md.
- Upadte readme for disclaimer
- v0.1.0-rc.1

### Features

- add firmware update entities and trident levels

### Fixes

- add issue templates, triage labels, and release tooling
