# Proposal

## Why

The command line has twenty-one top-level flags and two subcommands, and the flags do not say which command they belong to. `--generate-invite`, `--generate-2fa` and `--show-2fa` write credentials; `--local-proxy` and `--generate-secret` write nothing at all; `--invite-domains`, `--invite-name`, `--invite-relay`, `--invite-ticket` and `--endpoint-id` only mean anything next to one of the others, and the one they modify is not in their own name. The help a new operator reads is a flat list of twenty-one flags, and the only way to find out which of them go together is to read the source.

Grouping the flags into named commands makes the surface say what it does: `nexapipe invite`, `nexapipe client enroll`, `nexapipe secret`.

## What Changes

- The twenty-one top-level flags become eight command groups: `serve`, `status`, `client`, `invite`, `qr`, `secret`, `config`.
- Every flag the command line has today keeps working for one release, and says which command has replaced it.
- Running the server still needs no command: `nexapipe` on its own starts the server, as it does now.
- The messages the binary prints name the commands instead of the flags.
- Three flags are renamed rather than moved, because they describe how a QR code is drawn and that is now a property of the command rather than of the whole binary: `--qr-format` becomes `--format`, `--qr-invert` becomes `--invert`, `--qr-out` becomes `--out`. The old spellings keep working.

The commands, in full:

```
nexapipe [serve] [--local-proxy]
nexapipe status [--json]
nexapipe client list [--json]
nexapipe client add <CLIENT_ID> [--device NAME] [--public-key HEX] [--force]
nexapipe client revoke <CLIENT_ID> [--device NAME]
nexapipe client enroll <CLIENT_ID> [--force]
nexapipe client qr <CLIENT_ID>
nexapipe invite [CLIENT_ID] [--registration] [--create-client] [--domains LIST] [--name NAME] [--relay URL] [--ticket TICKET] [--endpoint-id ID]
nexapipe qr <TEXT>
nexapipe secret
nexapipe config show
nexapipe config path
```

`--config`, `--storage`, `--storage-url` and `--issuer` stay global: they are settings rather than requests, and they mean the same thing whichever command is running.

### Out of scope

- A `route` group. The routes of a running instance are already in `nexapipe status`, and the routes in the store are in `nexapipe config show`; a third spelling of the same question would be a third answer to keep in step. Writing routes — `route add`, `route remove` — needs the storage seam to grow, and that belongs with the change that writes routes for the console.
- Changing what any command does. The grouping is the change; the behaviour behind each command is the behaviour behind the flag it replaces.
- Removing the old flags. They go in the release after this one.
- A `--json` form for every command. `status` and `client list` have one today; the others print for a human and are given a machine-readable form when something needs one.
