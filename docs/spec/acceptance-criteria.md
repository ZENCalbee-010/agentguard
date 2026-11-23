# Acceptance Criteria and Traceability Matrix (draft for approval)

## 1. Milestone acceptance criteria (summary)

| ID | Milestone | Criterion |
|---|---|---|
| AC-M2-01 | M2 | Benchmark version/commit recorded; ≥1 representative tool-mediated scenario runs natively, or incompatibility documented with evidence |
| AC-M2-02 | M2 | Each benchmark injection task classified: direct / adapted / unsupported / out of scope |
| AC-M3-01..15 | M3 | SEC-001..SEC-015 positive and negative tests pass (no LLM) |
| AC-M3-16 | M3 | Denied calls: state snapshot equal before/after (property test over generated calls) |
| AC-M3-08 | M3 | Conflicting allow/deny rules → DENY |
| AC-M3-17 | M3 | Import-boundary tests: oracle ↛ defense/policy; sandbox ↛ network modules |
| AC-M4-01 | M4 | Test-double agent completes scripted benign task end-to-end in all four configs |
| AC-M4-02 | M4 | Each candidate model qualified or rejected with recorded benign utility, valid-call rate, errors |
| AC-M4-03 | M4 | Timeouts, malformed calls, context overflow produce error records, never success |
| AC-M5-01 | M5 | Four configs differ only in `gateway_mode` (config-diff test) |
| AC-M5-02 | M5 | Analyzer unit tests per signal S1–S4 and threshold boundary |
| AC-M6-01 | M6 | Metrics recomputed from stored raw records reproduce exported tables exactly |
| AC-M6-02 | M6 | CI green on 3.12 and 3.13 (after approved push) |
| AC-M7-01 | M7 | Pilot end-to-end; cost/time per case measured; GO/NO-GO documented |
| AC-M8-01 | M8 | Every reported number traceable to raw records + analysis script commit |

## 2. Requirement → test traceability

| Requirement / invariant | Test IDs (planned) | Milestone |
|---|---|---|
| SEC-001 / REQ-POL-5 | T-001-P, T-001-N | M3 |
| SEC-002 / REQ-SBX-2 | T-002-P, T-002-N | M3 |
| SEC-003 / REQ-SBX-3 | T-003-P, T-003-N, AC-M3-16 | M3 |
| SEC-004 / REQ-POL-2 / REQ-AGT-1 | T-004-P, T-004-N | M3, M4 |
| SEC-005 / REQ-POL-1 | T-005-P, T-005-N | M3 |
| SEC-006 / REQ-CA-3 | T-006-P, T-006-N | M3 (stub analyzer), M5 |
| SEC-007 | T-007-P, T-007-N | M3 |
| SEC-008 / REQ-POL-5 | T-008-P, T-008-N | M3 |
| SEC-009 | T-009-P, T-009-N | M3, M4 |
| SEC-010 / REQ-AUD-1 / REQ-CA-5 | T-010-P, T-010-N | M3 |
| SEC-011 | T-011-P, T-011-N | M3 |
| SEC-012 | T-012-P, T-012-N | M3 |
| SEC-013 / REQ-CA-2 | T-013-P, T-013-N | M3, M5 |
| SEC-014 / REQ-POL-6 / REQ-EVL-1 | T-014-P, T-014-N, AC-M5-01 | M5, M6 |
| SEC-015 / REQ-SBX-1 | T-015-P, T-015-N, AC-M3-17 | M3 |
| REQ-POL-3 | AC-M3-08 | M3 |
| REQ-POL-4 | Protocol review; record carries policy hash | M5, M8 |
| REQ-CA-1, REQ-CA-4 | AC-M5-02; config hash check | M5 |
| REQ-ORC-1 | T-ORC-1 (claim-without-effect → false), T-ORC-2 (effect → true) | M3 |
| REQ-ORC-2 | AC-M3-17 | M3 |
| REQ-ORC-3 | T-ORC-3 (matcher incl. normalization) | M3/M6 |
| REQ-ORC-4 | T-RUN-1 (errored runs excluded + counted) | M6 |
| REQ-EVL-2, -3, -5 | T-REC-1 schema, T-RUN-2 pairing, T-MAN-1 manifest hash | M6 |
| REQ-EVL-6 | T-ADP-1 context overflow | M4 |
| REQ-AGT-2, -3 | T-AGT-1 limits, T-AGT-2 test double | M4 |
| REQ-GOV-1 | T-GOV-1 adapter refuses paid call at cap 0 | M4 |

Every **C**-priority requirement in `requirements.md` maps to at least one test or protocol check above.
