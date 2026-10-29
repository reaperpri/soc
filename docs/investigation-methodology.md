# Investigation methodology

## Scope and data handling

This project analyzes three local JSON files containing synthetic training
events:

- `data/auth_events.json` — Windows-style authentication records.
- `data/process_events.json` — endpoint process-creation records.
- `data/network_alerts.json` — synthetic network sensor records.

The loader expects each file to contain a JSON list of event objects. No live
systems, external services, or real user data are queried.

## Detection rules

### AUTH-001: repeated failed logons followed by success

The detector looks for at least five event ID `4625` failures followed by an
event ID `4624` success within five minutes. The username and source IP must
match, and each failure must occur at or before the success. The result is a
high-severity triage alert.

### PROC-001: discovery-oriented process execution

The detector flags command lines containing `whoami`, `ipconfig`, `net user`,
`net.exe user`, or `get-service`. These commands can be normal administrative
activity; the alert asks for context and does not determine intent.

## Correlation

For each authentication alert, the correlator collects process events matching
the account and host and network events matching the host within ten minutes
before or after the successful logon. A shared host and nearby timestamps
establish a relationship for review, not causation. The sample data also uses
different authentication and network source IP addresses; they should not be
treated as proof of the same network session.

## Report and analyst review

The report includes event counts, correlated evidence, conclusions, suggested
follow-up, and limitations. Analysts should validate the account owner, check
original source telemetry, and follow their organization's incident-response
process before drawing conclusions or taking action.

## Limitations

- The evidence is fictional and intentionally small.
- Rules use fixed thresholds and simple string matching; they are not tuned
  for a real environment.
- Missing, delayed, or malformed telemetry can affect results.
- Host-and-time correlation can include unrelated events.
- This tool does not confirm compromise, attribute an actor, or perform
  containment.