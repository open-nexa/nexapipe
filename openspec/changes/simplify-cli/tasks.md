# Tasks

## 1. The command groups

- [ ] 1.1 Add `crates/nexapipe/src/cli/commands.rs` with the `serve`, `status`, `client`, `device`, `invite`, `qr`, `secret` and `config` command enums and the `client` subcommands `list`, `add`, `revoke`, `enroll` and `qr`, and verify `cargo check -p nexapipe` compiles
- [ ] 1.2 Move `Commands`, `ClientAction` and `DeviceAction` out of `crates/nexapipe/src/main.rs` into that module, keeping `status`, `client` and `device invite` behaving as they do today, and verify `nexapipe status --json`, `nexapipe client list` and `nexapipe device invite --client phone` still answer as before
- [ ] 1.3 Give the `invite` command the options the invite has always taken — the client id, `--create-client`, `--domains`, `--name`, `--relay`, `--ticket`, `--endpoint-id` — and verify `nexapipe invite phone` produces the invite the flag produced
- [ ] 1.4 Give `client enroll` and `client qr` their own `--force` and the client id, and verify `nexapipe client enroll phone` prints the credential, the `otpauth://` URI and the QR code, and `nexapipe client qr phone` prints the QR code of the secret the client already has
- [ ] 1.5 Rename the drawing options to `--format`, `--invert` and `--out`, keeping `--qr-format`, `--qr-invert` and `--qr-out` as hidden aliases of the same arguments, and verify both spellings draw the QR code the same way

## 2. The fold and the notices

- [ ] 2.1 Fold the parsed command into the flat fields the implementations read, in `crates/nexapipe/src/cli/commands.rs`, and verify that every command reaches the implementation the flag it replaced reached
- [ ] 2.2 Keep the action flags working and hidden, and fold each into the command it has become — `--local-proxy`, `--generate-secret`, `--generate-2fa`, `--show-2fa`, `--generate-invite`, `--create-client`, `--invite-domains`, `--invite-name`, `--invite-relay`, `--invite-ticket`, `--endpoint-id`, `--force` — and verify each one still does what it did
- [ ] 2.3 Print one line on stderr for every old flag that is used, naming the command that has replaced it, and verify the line names a command the operator can copy and that it goes to stderr rather than stdout
- [ ] 2.4 Refuse a command and the flag that has replaced it when both are given, naming both ways of asking, and verify the refusal happens before the command runs
- [ ] 2.5 Leave a modifier flag on its own inert, as it is today, and verify `--invite-domains a,b` on its own prints the deprecation line and starts the server rather than printing an invite
- [ ] 2.6 Leave `--registration` and `client add --device` refused, the way the device invitation left them, and verify each still points at `nexapipe device invite --client <CLIENT_ID>`

## 3. The commands that have no flag behind them

- [ ] 3.1 Implement `nexapipe qr <TEXT>`, which draws a QR code carrying the text it is given and writes it to `--out` when that is given, and verify the file it writes is the one the `--out` option has always written
- [ ] 3.2 Move the secret key printing into `nexapipe secret`, keeping the text it prints today, and verify `nexapipe secret` prints a key and writes nothing
- [ ] 3.3 Implement `nexapipe config show`, printing the configuration the store holds in the format it is written in, and verify it prints the same text the store gives the server
- [ ] 3.4 Implement `nexapipe config path`, printing the store that holds the configuration, and verify it names the file or the database the instance is using

## 4. The messages

- [ ] 4.1 Replace every flag named in a message the binary prints with the command that has replaced it, in `crates/nexapipe/src/cli/invite.rs`, `crates/nexapipe/src/cli/enrollment.rs` and `crates/nexapipe/src/storage/sqlite.rs`, and verify with a grep that no message names `--generate-invite`, `--generate-2fa`, `--show-2fa`, `--create-client` or `--invite-domains` any more
- [ ] 4.2 Check the messages in `crates/nexapipe/src/conn/auth/` and `crates/nexapipe/src/auth/` for the same flags, and verify each one that names a flag names the command instead
- [ ] 4.3 Check the messages in `crates/nexapipe/src/cli/device.rs` for the flags it replaced, and verify each one names `nexapipe device invite --client <CLIENT_ID>`

## 5. Verification and documentation

- [ ] 5.1 Add tests for the fold — one per old flag, asserting it reaches the same behaviour as its command — and verify they pass
- [ ] 5.2 Run `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo test --workspace --locked`, and verify they pass
- [ ] 5.3 Update `README.md` and `README.zh-CN.md` to show the commands rather than the flags, and verify every command in the documentation is one the binary accepts
- [ ] 5.4 Note in `CHANGELOG.md` which flags are deprecated and what has replaced them, and verify each flag the note names is one the binary still accepts
