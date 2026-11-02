# Elastibank lab assets

The assets behind the Elastic Agentic SOC Workshop: the bash libraries that build the lab on a fresh sandbox, the Kibana content (detection rules, ES|QL tools, workflows, a skill and agent definition), and the generator for the synthetic attack dataset.

Everything here is fictional. Elastibank, its people and its hosts do not exist, and the network addresses use documentation ranges.

| Path | Purpose |
|---|---|
| `lib/bootstrap.sh` | Builds the lab: loads the dataset, applies the content, starts the mail inbox. |
| `lib/apply.sh`, `lib/kibana.sh` | Idempotent helpers over the Kibana and Elasticsearch APIs. |
| `lib/checks.sh`, `lib/solves.sh` | Helpers the challenge check and solve scripts call. |
| `kibana/` | Content as code. |
| `scenario/generator/` | `python3 -m scenario.generator --out <dir>` writes the dataset as `_bulk` NDJSON. Python 3.10+, standard library only. |

This repository is generated from a private source repository; changes are made there.
