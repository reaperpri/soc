# SOC Detective: Security Telemetry Correlation Lab

A Python-based educational Security Operations Centre (SOC) investigation
pipeline that analyses synthetic authentication, endpoint and network
telemetry to generate correlated incident findings.

## Learning objectives

- Understand Windows authentication event IDs 4624, 4625 and 4672.
- Examine simulated Sysmon process-creation events.
- Interpret synthetic Suricata-style alerts and Zeek-style connection data.
- Build explainable Python detection rules.
- Correlate events using identity, endpoint and timestamps.
- Generate JSON and Markdown investigation reports.
- Validate detection behavior with automated unit tests.

## Architecture

```text
Synthetic JSON Evidence
          |
          v
       loader.py
          |
          v
      detector.py
          |
          v
     correlator.py
          |
          v
      reporter.py
          |
          v
  JSON + Markdown Reports
```

## Project structure

```text
day4-soc-detective/
├── data/
├── src/
├── tests/
├── outputs/
├── docs/
├── .gitignore
├── README.md
└── requirements.txt
```

## Requirements

- Python 3.10 or newer recommended
- VS Code or another Python-compatible editor
- No third-party packages required

## Run the investigation

From the project root:

```bash
python -m src.main
```

The application loads the synthetic evidence, executes detection rules,
correlates relevant events and generates reports in `outputs/`.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

## Detection logic

The authentication rule flags at least five failed logons for the same
account and source IP within five minutes before a successful logon.

The process rule flags selected discovery-oriented commands for review.

The correlation engine associates evidence by account, endpoint and
time window. Network evidence is associated using endpoint and time.

These rules are illustrative heuristics, not production detection logic.

## Outputs

- `outputs/incident_report.json`
- `outputs/incident_report.md`

The report includes event counts, incident findings, evidence summaries,
recommended investigation steps and limitations.

## Important limitations

- All data is fictional and for training purposes.
- The reserved example IP ranges do not identify real attackers.
- Correlation does not prove causation or account compromise.
- Source IP mismatches require additional investigation.
- The project does not connect to a live SIEM, endpoint or network sensor.
- The rules have not been validated against real-world attack datasets.

## Ethical use

This project is intended for defensive education, detection engineering
and incident response practice. Do not use synthetic findings as evidence
of a real security incident.

## License

No license file is included yet. Add one before distributing this project.