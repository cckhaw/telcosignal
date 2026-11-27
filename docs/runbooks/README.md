# Runbooks (sandbox reference implementation)
Each runbook states Purpose, Trigger, Roles, Steps, Verification and Owner (proposed). They describe what the platform supports TODAY and say plainly what is not yet automated or not yet possible (for example anything needing Neon, a real HSM or a real WAF).
No runbook has been exercised by a human team: they were written alongside the code and tested where the step is automatable (restore, rotation, kill switch, retention).

| Runbook | Use it when |
|---|---|
| incident-response.md | A security or availability incident is suspected |
| alerts-response.md | An alert fires (one section per alert rule) |
| kill-switch.md | You must stop traffic for a participant, telco or signal |
| breach-notification.md | Personal data may have been exposed (PDPA 2024 / BNM / CSA 2024 inputs) |
| backup-restore.md | Taking, testing or performing a restore |
| disaster-recovery.md | A region, database or host is lost |
| key-rotation.md | Rotating platform or participant keys and certificates |
| retention-deletion.md | Retention periods, deletion jobs and legal holds |
| onboarding-operations.md | Onboarding or offboarding a telco or bank |
| sandbox.md | Running the local sandbox (participant plane, admin plane, mock telcos, mock IdP, worker) |
