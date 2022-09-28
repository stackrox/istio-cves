# Istio-cves

This repository is meant to be a single source of truth for 
Istio-related CVEs. The data gathered here is meant to be as up-to-date
as possible. Currently, the data comes from announcements from [istio-security-bulletin](https://istio.io/latest/news/security/)

Though this repository is meant to be a single source of truth,
there may be mistakes. We try to keep everything as accurate and up-to-date
as possible, but it is possible for things to fall through the cracks,
or data to be input incorrectly. If you find any incorrect data, please feel free
to make a pull request, and we will review it.

This repository doesn't include ISTIO-SECURITY-2020-011, ISTIO-SECURITY-2021-002, ISTIO-SECURITY-2021-004 since those are not associated with any CVEs, but rather they are suggestions from Istio.

## YAML Format

```yaml
name: 'Security Name (ex: ISTIO-SECURITY-2022-003)'
link: URL for the vulnerability. This will typically be a link to Istio vluneralbility page.
published: 'Date Istio vluneralbility was first published publicly (ex: 2022-02-22T00:00Z)'
description: Istio vluneralbility description
cvss:
  scoreV3: V3 score
  vectorV3: V3 vector
affected:
  # list of version constraints affected by the vulnerability
  # with corresponding fix version, if it exists.
  # ranges should be in order from oldest to newest.
  #
  # Constraints adhere to https://github.com/hashicorp/go-version.
  # ex:
  - range: "< 1.14.8"
    fixedBy: "1.14.8"
  - range: ">= 1.15.0, <= 1.15.4"
    fixedBy: "1.15.5"
  - range: ">= 1.16, < 1.16.0"
    fixedBy: "1.16.1"
```
