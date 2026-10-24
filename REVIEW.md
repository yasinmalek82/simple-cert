# Stabilization and automation review

Baseline: `55554c6` (0.1.9) plus the existing uncommitted 0.1.10 work. The change preserves
that work and prepares version 0.1.10. No live server, CA account, existing
panel/node TLS, public release or production timer was changed during implementation.

## Findings addressed

- Release checksum mismatch: regenerate against the formatted application; verify exact candidate
  bytes before installation. Linux CI now installs its checkout, rather than downloading a different tag.
- Non-root delivery under CLI umask 077: explicitly set traversable owned version directories while
  keeping keys 0600 and candidate directories private to the intended reader.
- Conflicting Docker host/context: resolve the effective context first, reject remote endpoints and
  pin the inspected local Unix endpoint for discovery and all subsequent reader commands.
- Malformed records/missing keys: validate consumed state fields, isolate damaged records and display
  file health without preventing access to other certificates.
- No-op renewal/delivery: compare validated pairs, retain pointers and versions, and independently retry
  pending delivery or verify an already-published pair without another CA request.
- Uncertain CA/export/publication: preserve candidate identity and unknown intent, reconcile validated
  local/export evidence before replay, and hold across days when evidence is insufficient. A disk-copy
  error after ACME completion is also unknown, rather than a definite failure eligible for reissuance.
- Process cancellation: stop command descendants; entry-point TERM/HUP unwind operation intent.
- Full-state hardening work: harden touched ACME homes rather than scanning all retained certificate versions.
- Renewal attribution: respect a separate ACME `--config-home`.

## Agreed additions

Opt-in per-certificate file renewal through a noninteractive worker, a registered systemd timer at
04:00/04:10/04:20 Tehran, bounded daily retry slots, independent durable Telegram notices, grouped
menus and certificate-specific renewal/enrollment/recovery/delivery actions. Existing IDs, paths,
accounts and inactive defaults are retained. No API integration, Core edits or service activation.
See [automation and recovery](AUTOMATION.md) for precise ownership, outcome and delivery contracts.

## Verification and remaining acceptance

Local offline suite: 161 passed, 1 Linux-specific systemd syntax check skipped on macOS, on both Python 3.10 and Python 3.13. Tests cover generated real PEMs, state/publication interruption, expiry,
unknown holds, bounded retries, per-certificate locks, no-op files, private HTTP notices, timer
ownership and real disposable-prefix terminal uninstall. Ruff and shell/CLI smoke are checked.

Docker is installed but its daemon is unavailable on this host. The real non-root Docker acceptance
was updated to use the actual umask and exercise both unchanged and changed renewals; it remains
unexecuted locally. Actual timer calendar parsing runs when systemd-analyze is available in Linux CI.
Live systemd scheduling/shutdown/update, public CA issuance, Cloudflare access, a real Telegram send
and live consumer TLS remain separately authorized acceptance work. Local fixtures do not prove them.

The 0.1.10 GitHub release is published separately after release checks. Publication does not
deploy to any mother panel or enable its timer. The bootstrap URL requires matching application
and installer bytes on the release tag.
