# ContentOps · journaled security execution

Status: generic recovery primitives implemented and tested locally. This file
does not assert a server deployment or a successful production permission fix.

`security_transaction.py` contains no server address, private configuration,
credential, application source or deployment action. The private operational
entry point and reviewed integration remain outside this public repository.

## Authorization and order

The owner authorized one bounded intervention: verify the installed backup,
apply compatible permissions, validate, and deploy the existing module only
after the security gate passes. No second deployment approval is required
within that scope. Missing critical evidence stops the operation before changes.
Never expand to neighboring services or change owners to accommodate a guess.

Accept the already approved restoration and integration evidence. Do not rerun
historical tests as a substitute for checking the actual permission change.

## Transaction guarantees

- Caller-pinned exact paths and identities; no recursive chmod/chown.
- Refuse symlinks, unexpected hardlinks and unreviewed ACLs.
- Persist intent before each descriptor-based chmod, then verify the result.
- Revalidate object device/inode/owner; never recover onto a replacement file.
- Close directories before files; preserve contents and owners.
- Recover interrupted journals only with an independently supplied exact policy.
- Recovery restores file modes while retaining private directories; it never
  automatically reopens world-writable or world-readable directories.
- A committed journal cannot be replayed as an interrupted transaction.

The operational wrapper must additionally validate actual runtime UID/GID,
backup invocation/source/configuration, mount mappings, supported flags,
schedule and absence of a concurrent sync. Root-owned backup files alone do
not establish the backup process identity. Unknown backends must block.

## Commit gate

A production security PASS needs both a persisted PASS result and the matching
transaction journal in `COMMITTED` state. A crash before either is available
does not authorize deployment. On failure, record containment/recovery status;
do not emit a false PASS or overwrite live databases from an old backup.

SIGKILL or host failure cannot guarantee automatic rollback. After a restart,
the caller must use the saved private journal and exact scope for recovery.
`load_recovery()` refuses committed, public, malformed or out-of-scope journals.

## ContentOps acceptance

Retain the existing private integration, owner authentication, persistent data,
and credentials. Keep uploads and external publishing disabled. Verify two
fictional agents at the real HTTPS URL: V1, change request, V2, explicit
approval, logout, relogin, history and cross-agent/admin denial. Local tests
are not production acceptance. Revert only target source/configuration if the
deployment fails; keep current data and secure permissions.

## Focused local verification

Run `python3 -m unittest -v test_security_transaction` from this directory.
These are synthetic tests of the new permission/recovery primitives, not the
historical ContentOps acceptance suite. No real credentials or provider calls.
