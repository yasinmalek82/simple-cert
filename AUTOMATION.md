# Scheduled file renewal and recovery

This is the operating contract for version 0.1.10. Local verification is not live CA,
Linux service or node TLS acceptance. All operations run on the mother host. Management TLS,
Core configuration, panel API, database access and service activation remain outside scope.

## Opt in

1. Install this exact candidate using the verified installer workflow; use the same OS user/state
   as the existing certificates. A source checkout cannot register a production timer.
2. In Settings and automation, configure a dedicated Telegram bot using the hidden token prompt
   and a numeric chat ID. Saving sends nothing. Sending a test notice requires separate confirmation.
3. Open a certificate's details and select Enable/disable automatic renewal. Only successfully
   issued, currently valid certificates can be enrolled. Confirm the schedule and file-update notice.
4. Check Settings and automation -> Automation status for registration, actual timer state,
   per-certificate enrollment and the last scheduled outcome.

Registration requires root on a Linux mother with systemd and Asia/Tehran timezone data (`tzdata`).
There is one system-wide `simple-cert-renew.timer` / `.service` pair and one registered installation
and state directory, recorded privately in `/etc/simple-cert/automation.json`. A second installation
or state directory cannot take over implicitly. Unknown or modified units are never overwritten.
Installation and program update alone do not enable automation. Reinstallation keeps the existing
registration. Disabling a certificate excludes it from subsequent scheduled attempts; the idle timer
may remain installed to retry notices. Uninstall stops the owned timer and running worker, removes
its units/registration and preserves all certificate state, credentials and delivered files.

## Schedule and result meanings

The systemd timer triggers at 04:00, 04:10 and 04:20 **Asia/Tehran**, irrespective of server timezone.
`Persistent=false` prevents missed-run catch-up at boot. The worker starts certificate operations
only during 04:00-04:30 Tehran and rechecks the clock between certificates. A long-running operation
may finish later and skip subsequent retry opportunities; three is a maximum, not a guarantee.
A whole-worker lock excludes overlapping runs. Short certificate locks coordinate manual and
scheduled writes; account operations are also serialized. Idle menus hold no operation lock.

Each selected certificate has at most three attempts per Tehran calendar day, and no duplicate
attempt in the same ten-minute slot. A successful check suppresses later CA checks that day.
The pinned ACME client decides whether renewal is due. Identical certificate/key bytes produce
`Unchanged`: the current pointer, version count and delivered copies remain stable. A changed
pair is validated, durably prepared and published through an atomic current pointer. Previous
versions are retained. The details screen reports retained count and bytes; there is no automatic
version deletion.

CA success, local publication and each Docker delivery result are separate evidence. `Complete`
for a delivery means matching files were read through the selected container's configured default
user; it is not a live node handshake or Core activation. Only existing registered delivery paths
are refreshed automatically. Mount changes require explicit review. A failed delivery keeps local
renewal success and a pending destination; details action 7 retries delivery without contacting CA.
An already-published matching pair is verified without creating another delivery version.

After a changed certificate, activate the consuming service manually. The tool never issues a
restart, reload or Core PUT. A consumer that rereads files itself may nevertheless use the updated
pair immediately; enrollment explicitly explains this distinction. Panel HTTPS certificate files
remain separate and cannot be delivered using the Core publication action.

## Unknown outcomes

The saved intent and candidate identity precede CA/publication effects. Timeout, cancellation or
interrupted publication can leave `unknown`, `issuing`, `renewing` or `publishing`. These states
block another CA call. Scheduled recovery first examines the saved candidate, current pointer and
changed ACME export, validates the pair and finishes local publication when evidence is sufficient.
An unchanged old export alone is insufficient evidence. If no validated candidate/export proves
completion, the certificate stays on hold across days and a notice requests operator review.

Certificate details action 6, or the following command, performs evidence-based recovery without
contacting the CA or activating any service:

```bash
sudo simple-cert --reconcile CERTIFICATE_ID
sudo simple-cert --section panel --reconcile CERTIFICATE_ID
```

Recovery can publish a validated prepared pair; it is not purely read-only. Do not edit state to
clear unknown outcomes or delete ACME workspaces blindly. Preserve a private backup of the state
and delivered version directories before manual repair. A malformed record is reported individually
and does not hide healthy certificates. Missing/invalid published files are shown separately.

## Telegram and local evidence

The private `telegram.json` and `notifications.json` live in the selected state root (0600, within
0700 state). Token and chat ID have no command-line options. Requests use HTTPS POST, refuse
redirects and suppress raw responses. Notices include certificate identity, expiry/action context,
never tokens, keys, PEM contents or raw API/ACME output.

The durable queue covers changed files requiring manual activation, final definite failure,
unknown outcomes, pending delivery, recovery and expiry thresholds of 7, 3 and 1 day. Expiry events
are tied to the expiry date; repeated scans at the same threshold do not enqueue duplicate events.
Delivery failure of Telegram does not roll back or repeat renewal. Retry happens on later worker
runs or Settings and automation -> Retry queued notices. Without Telegram settings, events stay
local. A lost acknowledgement after Telegram accepted a message may cause a retry/duplicate;
message delivery cannot promise exactly-once semantics.

Inspect certificate details, Automation status, and `journalctl -u simple-cert-renew.service` for
safe local evidence. The worker's `--worker` interface is noninteractive and requires matching
installation/state registration. It exits nonzero when a processed operation or notice delivery
needs attention; an overlapping worker is skipped successfully.

## Acceptance before deployment

Run pytest, ruff check, ruff format --check, bash -n install.sh and the disposable-prefix maintenance
acceptance. CI installs the checked-out candidate with its checksum rather than a public tag.
The Docker acceptance runs generated test pairs under umask 077 with a real non-root container
reader. A separate Linux/systemd acceptance must check timer parsing, opt-in, no boot catch-up,
worker shutdown, update preservation and uninstall cleanup. Public CA issuance and consumer TLS
acceptance require a separately authorized staging run. Local development checks do not authorize production deployment, timer enablement or real
Telegram messages. GitHub release publication is separate from live deployment.
