# Keeper SDK for Python 1.2.7

## Release summary

Version 1.2.7 adds PAM workflow management to the SDK and CLI, and improves
Nested Shared Folder (NSF) access reporting and performance.

## New features

### PAM workflows

The SDK now exposes PAM workflow helpers under `keepersdk.helpers.workflow`.
They support creating, reading, updating, and deleting workflows; managing
approvers; requesting, approving, denying, starting, and ending access; and
retrieving workflow and user-access state.

Keeper CLI adds the `pam workflow` command group (also available as
`workflow` in the vault command scope). It supports workflow configuration,
approval administration, access requests, check-out/check-in, and status
reporting for PAM records.

### Nested Shared Folders

- Folder detail responses now include the parent folder UID and, when
  available, its name. CLI output displays the parent as `name (UID)`.
- SDK access lookups now process folders and records in batches of up to 100
  UIDs. Folder lookups fully consume continuation pages, providing complete
  results without caller-managed pagination.
- NSF folder and record access details can be cached in memory. Use
  `nsf-load-access --folders`, `nsf-load-access --records`, or both to preload
  the relevant access details for the current vault session.

## Dependencies

The SDK now requires `tzlocal>=5.2.0`.

## Upgrade notes

Update with your preferred package-management workflow. Existing NSF access
calls continue to return the same result collections; folder-access responses
no longer expose `has_more` or `continuation_token`, because pagination is
handled internally.

## Verification

This release adds unit coverage for the workflow SDK. Run the SDK test suite
with:

```bash
python -m unittest discover -s keepersdk-package/unit_tests/
```
