# Third-Party Notices

This extension includes data and content from the following sources, governed by the licenses below. The enrichment bundles are `app/data/enrich/*.json`; the pack data dictionaries are `app/packs/*.values.json`, each carrying its own `licence` and `cite` blocks; the FDR field catalogue is `app/packs/crowdstrike-falcon.fields.json`; the known-good corpus is `app/data/known/*.json`.

## MITRE ATT&CK

Source: https://github.com/mitre-attack/attack-stix-data

Version: Enterprise ATT&CK 19.2

Fetched: 2026-09-19

License: Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/)

License Text: "MITRE hereby grants you a non-exclusive, royalty-free license to use ATT&CK for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy."

Obligation: Retain MITRE's copyright designation and license terms in any copies or derivatives.

## Splunk Enterprise Security Content Update (ESCU)

Source: https://github.com/splunk/security_content

Branch: develop

Fetched: 2026-09-19

License: Apache License 2.0 (https://github.com/splunk/security_content/blob/develop/LICENSE)

License Text: A copy of the Apache License 2.0 is available at https://www.apache.org/licenses/LICENSE-2.0.

Obligation: Include a copy of the license and notice of any modifications. Include prominent NOTICE file if applicable.

## CISA Known Exploited Vulnerabilities Catalog

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

License: CC0 1.0 Universal (https://www.cisa.gov/sites/default/files/licenses/kev/license.txt)

Fetched: 2026-09-19

License Text: "You may use this data in any legal manner. The data is provided 'as is' with no warranties expressed or implied."

Obligation: No copyright notice required; public domain equivalent.

## LOLDrivers

Source: https://www.loldrivers.io/

GitHub: https://github.com/magicsword-io/LOLDrivers

Fetched: 2026-09-19

License: Apache License 2.0 (https://github.com/magicsword-io/LOLDrivers/blob/main/LICENSE)

License Text: A copy of the Apache License 2.0 is available at https://www.apache.org/licenses/LICENSE-2.0.

Obligation: Include a copy of the license and notice of any modifications.

## LOLRMM

Source: https://lolrmm.io/api/rmm_tools.json

GitHub: https://github.com/magicsword-io/LOLRMM

Fetched: 2026-09-19

License: Apache License 2.0 (https://github.com/magicsword-io/LOLRMM/blob/main/LICENSE)

License Text: A copy of the Apache License 2.0 is available at https://www.apache.org/licenses/LICENSE-2.0.

Obligation: Include a copy of the license and notice of any modifications.

## Microsoft Azure Sentinel

Source: https://github.com/Azure/Azure-Sentinel

Branch: master

Fetched: 2026-09-19

License: MIT License (https://github.com/Azure/Azure-Sentinel/blob/master/LICENSE)

License Text: A copy of the MIT License is available at https://opensource.org/licenses/MIT.

Obligation: Include a copy of the license and copyright notice in any copies or derivatives.

## SigmaHQ Detection Rules

Source: https://github.com/SigmaHQ/sigma

Fetched: 2026-09-19

License: Detection Rule License 1.1 (https://github.com/SigmaHQ/Detection-Rule-License)

License Text: The Detection Rule License 1.1 permits use, modification, distribution, sale and sublicense provided that author attribution is retained in any copies, distributions and rule matches display author identification.

Obligation: Preserve author attribution and license designation in all uses.

## Linux and macOS Known-Good Corpus

Source: tools/dev/linux-corpus.sh and tools/dev/macos-corpus.sh, run on stock installs (macOS builds 25F71, 25G83 and 26A5416b; Ubuntu 22.04 and 24.04, RHEL 9, Amazon Linux 2023)

Generated: 2026-09-18 to 2026-09-20

License: Enumeration of platform-default binaries; no external license applies to the signing ids, paths, package names and Linux checksums. The shipped macOS index carries signing ids, paths and the builds each pair was seen on, no file hashes; the enumeration CSVs under tools/dev/corpus keep every column.

Obligation: The signing identities, paths, package manifests and checksums are factual data without copyright constraints. A macOS row's one-line description, where present, is the summary line of the platform's own man page or the bundle's Info.plist; a Linux row's is the package's own short description. Each is one line, attributed to the platform by the row's build or release.

## Splunk Common Information Model documentation

Source: https://docs.splunk.com/Documentation/CIM/6.1.0 (the Endpoint, Network Traffic, Authentication and related data model field pages)

Used in: `app/packs/crowdstrike-falcon.fields.json`, the 74 field records whose `meaning.source` is `reference`

Read: 2026-09-17

License: Splunk documentation; no open license is claimed. Each record reproduces the one-line field description the CIM field page prints, verbatim, with that page's URL as `basis_ref`.

Obligation: Keep the attribution and the URL with each description. Whether these one-line definitions stay as quotations or are rewritten is an open decision recorded in docs/COMPLIANCE.md §6.

## Splunk Add-on for CrowdStrike FDR

Source: Splunkbase app 5579, version 3.2.0 (`props.conf`, `transforms.conf`, `eventtypes.conf`, `tags.conf`, `fields.conf`, `macros.conf` and its lookup CSVs)

Used in: `app/packs/crowdstrike-falcon.fields.json` (the `ta` and `decode_table` records: field aliases, calculated fields, eventtypes and 169 decode tables), `app/packs/crowdstrike-events.values.json` and `app/packs/crowdstrike-inventory.values.json` (paraphrase)

Read: 2026-09-17

License: The add-on's Splunkbase terms; its configuration files carry no separate license. What is taken is the configuration as fact: which field maps to which, and which literal decodes to which label.

Obligation: None beyond attribution; the add-on's text is not reproduced.

## Elastic integrations, CrowdStrike FDR package

Source: https://github.com/elastic/integrations, `packages/crowdstrike/data_stream/fdr/fields/fields.yml` and the pipeline test fixtures under `_dev/test/pipeline/`

Used in: `app/packs/crowdstrike-falcon.fields.json` (field names and types, and the per-event field union)

License: Elastic License 2.0 (https://github.com/elastic/integrations/blob/main/LICENSE.txt)

Obligation: Only field names, types and event membership are taken, as facts about the FDR schema; no descriptive text from the package is reproduced.

## AWS documentation (pack data dictionaries)

Source: the awsdocs repositories and docs.aws.amazon.com (CloudTrail, CloudTrail Lake, EventBridge, AWS Config, EC2, GuardDuty, Inspector, IAM, VPC flow logs, Security Lake and the OCSF schema)

Used in: `app/packs/aws-*.values.json`, `app/packs/ocsf-aws.values.json`

Read: 2026-09-18 to 2026-09-19

License: Creative Commons Attribution-ShareAlike 4.0 International (https://creativecommons.org/licenses/by-sa/4.0/), Amazon Web Services, Inc.

Obligation: Attribution, carried by each entry's `cite` URL. Entries paraphrase the documentation in the pack's own words; a quote is at most twenty of the vendor's words, kept beside its cite.

## Microsoft Learn documentation (pack data dictionaries)

Source: learn.microsoft.com pages published from MicrosoftDocs/azure-docs, MicrosoftDocs/defender-docs, microsoftgraph/microsoft-graph-docs-contrib, MicrosoftDocs/office-365-management-api and the Azure REST API reference

Used in: `app/packs/azure-monitor.values.json`, `app/packs/ms-defender.values.json`, `app/packs/ms-defender-ti.values.json`, `app/packs/mscs-*.values.json`, `app/packs/o365.values.json`, `app/packs/entra-signin.json`

Read: 2026-09-19

License: Creative Commons Attribution 4.0 International (https://github.com/MicrosoftDocs/azure-docs/blob/main/LICENSE), Microsoft. The rendered learn.microsoft.com pages also carry Microsoft's Terms of Use (https://learn.microsoft.com/en-us/legal/termsofuse); `ms-defender-ti.values.json` and `o365.values.json` record where a repository's license could not be read directly.

Obligation: Attribution, carried by each entry's `cite` URL. Entries paraphrase; a quote is at most twenty of the vendor's words.

## Google Cloud and Google Workspace documentation (pack data dictionaries)

Source: cloud.google.com, docs.cloud.google.com, developers.google.com and the Google API discovery documents

Used in: `app/packs/google-gcp-*.values.json`, `app/packs/gws*.values.json`

Read: 2026-09-18 to 2026-09-19

License: Creative Commons Attribution 4.0 International (https://creativecommons.org/licenses/by/4.0/), Google LLC; the Security Command Center protos in the googleapis repository are Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0.html)

Obligation: Attribution, carried by each entry's `cite` URL. Entries paraphrase; a quote is at most twenty of the vendor's words.

## Okta Management API specification

Source: https://github.com/okta/okta-management-openapi-spec and the developer.okta.com Event Types catalog

Used in: `app/packs/okta.values.json`, `app/packs/okta-inventory.values.json`

Read: 2026-09-18 to 2026-09-19

License: Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0.html), Okta, Inc.

Obligation: Include a copy of the license and notice of any modifications. Entries paraphrase the schema descriptions.

## GitHub REST API documentation

Source: https://docs.github.com (the enterprise audit log reference)

Used in: `app/packs/github.values.json`

Read: 2026-09-19

License: Creative Commons Attribution 4.0 International (https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features), GitHub, Inc.

Obligation: Attribution, carried by each entry's `cite` URL. Entries paraphrase; no quotation is used.

## Cisco and Splunk documentation (pack data dictionaries)

Source: the Cisco Secure Firewall ASA and Threat Defense syslog message guides (cisco.com), the Splunk Common Information Model field reference and the Splunk add-on source type pages (splunk.github.io)

Used in: `app/packs/cisco-asa.values.json`, `app/packs/cisco-ftd.values.json`, `app/packs/crowdstrike-events.values.json`, `app/packs/crowdstrike-inventory.values.json`, `app/packs/google-gcp-security.values.json`, `app/packs/gws-directory.values.json`, `app/packs/mscs-security.values.json`

Read: 2026-09-18 to 2026-09-19

License: Vendor documentation terms; no open license is claimed.

Obligation: Entries paraphrase in the pack's own words, each beside its `cite` URL; a quote is at most twenty of the source's words.
