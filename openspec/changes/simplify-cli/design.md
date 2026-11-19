# Design

## Context

The command line today is one clap struct with a few global arguments and twenty-one flat action flags, plus two subcommands (`status`, `client`). The credential commands were moved out of `main.rs` into `crates/nexapipe/src/cli/` a while ago, and they take the whole `Cli` struct rather than the arguments they need: `print_2fa_enrollment(&Cli, …)`, `print_endpoint_invite(&Cli, …)`, `add_client(&Cli, …)`, and `render_qr(&str, &Cli, &str)` reads the three drawing options off it.

Those modules are also where the messages that name flags live — the invite tells the operator to run `--generate-invite <client> --registration` and `--generate-2fa <client> --force`, and the enrollment tells the operator to "pass `--force` to rotate it instead".

Two things shape the approach. The credential commands were restructured by the one-time device invitation that landed just before this change: `cli/invite.rs` now hands out `build_invite_base` and `create_client_for_invite` to the new `cli/device.rs`, and `--registration` and `client add --device` already refuse and point at `nexapipe device invite`. That change is still moving, so this one has to be written on top of it rather than beside it. And the old flags cannot simply be deleted: a deployment script that runs `nexapipe --generate-invite phone` has to keep working for a release.

## Goals / Non-Goals

**Goals:**

- The help says what the binary can be asked to do, in the words an operator would use.
- Every behaviour has exactly one implementation, whether it was asked for with a flag or with a command.
- The old spellings keep working for one release and say what replaced them.
- The messages the binary prints name the commands.

**Non-Goals:**

- Changing what any command does.
- Removing the old flags.
- A `route` group, and a `--json` form for every command.

## Decisions

### The commands live in `cli/commands.rs`, and `Cli` stays the internal request

The command enums move out of `main.rs` into a new `crates/nexapipe/src/cli/commands.rs`, next to the commands they dispatch to — `serve`, `status`, `client`, `device`, `invite`, `qr`, `secret` and `config`. The parser folds the command into the flat fields the implementations already read — `Commands::Invite { client_id, domains, … }` becomes `cli.generate_invite`, `cli.invite_domains` and the rest — and the implementations are called exactly as they are today.

**Why:** every spelling, old or new, then converges on one internal request, so there is one implementation per behaviour rather than one per spelling. The second half of that is the point: the credential modules are not rewritten, and the diff is the parser plus the messages.

**The `device` group is carried over as it is.** The one-time device invitation already is a command, and it already lives in `cli/device.rs` with its own arguments. This change moves it into the same enum as the others and gives it a place in the help, but it does not change what it does.

**Alternative considered:** giving each command its own arguments struct and changing the four credential functions to take it. That is the cleaner shape, and it is what the code would look like with no history. It rewrites every `cli.` into `req.` across `cli/invite.rs`, `cli/enrollment.rs` and `cli/client.rs` — the three files the device-identity work has just rewritten — and every one of those renames is a merge conflict waiting to happen, over a refactor nobody asked for. The indirection it removes is one `&Cli` parameter, and the price is not worth it now.

**The cost, named:** the internal request uses the older names for things — `cli.generate_invite` for the invite command. That reads oddly next to `Commands::Invite`, and the fold deserves a comment saying why it is there. When the credential modules are next rewritten for another reason, the request can be renamed with them.

### The old flags stay on `Cli`, hidden, and are folded before dispatch

The action flags keep their fields. They are hidden from `--help`, and the parser folds them into the equivalent command before anything is dispatched — `--generate-invite phone` becomes `Commands::Invite { client_id: "phone", … }`, and `client enroll` reuses the implementation the flag used.

**Why:** the implementations are the flag's behaviour, and folding keeps one of each. Hiding them keeps the help honest about what the command line is now, while the code keeps accepting them.

**The two flags that were retired before this change stay retired.** `--registration` and `client add --device` refuse and point at `nexapipe device invite`, and this change does not bring either spelling back: the deprecation budget was spent once, on the device invitation, and spending it twice would give an operator two different deprecation notices for the same thing.

### A flag and the command that replaced it are an error

Giving both is refused, and the refusal names both.

**Why:** they are two answers to one question, and picking one silently would leave the operator unsure which one ran. Refusing is the only outcome that cannot be wrong.

**Alternative considered:** the command wins and the flag is ignored. Rejected: an operator who typed both would be reading output that does not match the flag they thought they used.

### The modifier flags only mean something next to the flag they modified

`--invite-domains`, `--invite-name`, `--invite-relay`, `--invite-ticket`, `--endpoint-id`, `--create-client` and `--force` keep behaving as they do today: on their own they change nothing. They are reported as replaced, and the request they would have changed is not made.

**Why:** that is what they do today. Making `--invite-domains a,b` print an invite would change what a command does, which this change is not about — and it would surprise anyone who typed them expecting them to be inert. `--invite-ticket` is the exception the device invitation asked for: it is global now, because `device invite` carries a ticket too, and it says so when it is given on its own.

### The drawing options are renamed, and stay global

`--qr-format`, `--qr-invert` and `--qr-out` become `--format`, `--invert` and `--out`. The old spellings keep working as hidden aliases of the same arguments.

**Why:** they are global today, so they have to stay global — an operator who writes `nexapipe --qr-out f.svg invite phone` has to keep working, and a per-command copy would break it. Renaming them is what makes `nexapipe qr "text" --out f.svg` read as one thing rather than two.

**Alternative considered:** giving each of the four commands that draw a QR its own copy of the three options, and dropping the global. Rejected: the global spelling is the one that has to keep working, and four copies of the same three options is four places for them to drift.

**The cost, named:** `--out` and `--invert` are vague names for a global argument. The help text says they describe how a QR code is drawn, and nothing else on the command line writes a file or inverts anything.

### The deprecation notice names the replacement

Every old flag that is actually used produces one line on stderr, naming the command that has replaced it: `warning: --generate-invite is deprecated; use "nexapipe invite [CLIENT_ID]" instead`.

**Why:** the notice is the whole reason the flags can go in the next release. It has to name a command the operator can copy, not a description.

**The renamed flags do not get one.** A hidden alias cannot be told apart from the name it aliases, so there is nothing to notice. The help of the argument mentions the older spelling instead.

### `config show` and `config path` read the store and nothing else

`config show` prints the text the store holds as its configuration, and `config path` prints the store's own description of itself.

**Why:** both are answered by what the `Storage` trait already has — `config()` and `describe()` — so this change needs nothing from the storage seam and does not wait for the database work.

**Why no `route` group:** the routes of a running instance are in `nexapipe status`, and the routes in the store are in `nexapipe config show`. A third spelling of the same question is a third answer to keep in step, and writing routes needs the storage seam to grow, which belongs with the change that writes routes for the console.

## Risks / Trade-offs

- **A deployment script breaks.** → Nothing it does today stops working: the old flags keep their behaviour for one release, and each of them says what replaced it. What breaks is a script that parses `--help` for a flag list, which is a script reading the binary's own words.
- **The internal request uses the older names.** → One comment where the fold happens, and the names are renamed with the credential modules the next time those are rewritten for another reason.
- **Two spellings drift apart.** → They cannot: both spellings end up in the same folded request before anything is dispatched, and there is one implementation behind it.
- **The help loses the old flags.** → They are hidden, not removed. `nexapipe --help` shows what the command line is now; the old flags are documented in the release notes as still accepted.
