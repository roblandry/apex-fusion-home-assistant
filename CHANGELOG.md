# Changelog

All notable changes to this project will be documented in this file.

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
