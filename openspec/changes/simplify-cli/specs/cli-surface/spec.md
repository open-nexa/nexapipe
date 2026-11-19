# Spec Delta

## Purpose

What an operator types on the command line, which command each request belongs to, and what becomes of the spellings that came before.

## ADDED Requirements

### Requirement: Starting the server needs no command

The command line SHALL start the server when no command is named.

#### Scenario: The command line with nothing on it

- **WHEN** the command line names no command
- **THEN** the server starts, and the instance behaves as it does today

#### Scenario: The server behind a name

- **WHEN** the command line names the `serve` command
- **THEN** the server starts

### Requirement: The credential commands live under one command

The `client` command SHALL carry the operations that read and write the credentials of a client.

#### Scenario: Listing the clients

- **WHEN** the operator asks the `client` command to list
- **THEN** the clients are listed, and the devices of each are named

#### Scenario: Issuing a credential

- **WHEN** the operator asks the `client` command to add a client, with a public key
- **THEN** that device is issued the credential, and the client's own credential is left alone

#### Scenario: Withdrawing a credential

- **WHEN** the operator asks the `client` command to revoke a client, naming a device
- **THEN** that device's credential is dropped, and the client and its other devices are left alone

#### Scenario: Enrolling a client in 2FA

- **WHEN** the operator asks the `client` command to enroll a client
- **THEN** the credential, the `otpauth://` URI and the QR code carrying it are printed, and a client that already has a secret keeps it unless the operator asked for it to be replaced

#### Scenario: Showing a client that is already enrolled

- **WHEN** the operator asks the `client` command for the QR code of a client
- **THEN** the QR code of the secret that client already has is printed, and no secret is written

### Requirement: The device invitation is its own command

The `device` command SHALL print the one-time invitation a device enrolls with.

#### Scenario: An invitation for a device

- **WHEN** the operator asks the `device` command for an invitation naming a client
- **THEN** a one-time invitation is printed, carrying the client, the domains and an expiry

#### Scenario: How long the invitation is good for

- **WHEN** the operator asks the `device` command for an invitation and names a lifetime
- **THEN** the invitation expires after that lifetime, and after the default when none is named

#### Scenario: A client that does not exist yet

- **WHEN** the operator asks the `device` command for an invitation naming a client that does not exist, and asks for the client to be created
- **THEN** the client is created, and the invitation is printed

### Requirement: The endpoint invite is its own command

The `invite` command SHALL print the endpoint invite, and SHALL take the options the invite has always taken.

#### Scenario: An invite for an endpoint

- **WHEN** the operator asks the `invite` command for an invite without naming a client
- **THEN** the invite carries the endpoint and its domains, and no credential

#### Scenario: An invite that carries a client's credential

- **WHEN** the operator asks the `invite` command for an invite naming a client
- **THEN** the invite carries that client's credential as well

#### Scenario: An invite for a client that does not exist yet

- **WHEN** the operator asks the `invite` command for an invite naming a client that does not exist, and asks for the client to be created
- **THEN** the client is created with a secret, and the invite carries it

#### Scenario: The endpoints the invite names

- **WHEN** the operator asks the `invite` command for an invite and names the domains, the name, the relay or the ticket
- **THEN** the invite carries what was named, in place of what the configuration would have supplied

### Requirement: A QR code of arbitrary text is its own command

The `qr` command SHALL print a QR code carrying the text it is given.

#### Scenario: A QR code of a link

- **WHEN** the operator asks the `qr` command for a QR code of a link
- **THEN** the QR code carrying that link is printed

#### Scenario: A QR code of a link written to a file

- **WHEN** the operator asks the `qr` command for a QR code of a link and names a file
- **THEN** the QR code is written to that file, in the format the extension asks for

### Requirement: Generating a secret key is its own command

The `secret` command SHALL print a new secret key for the endpoint's identity, and write nothing.

#### Scenario: A new secret key

- **WHEN** the operator asks the `secret` command for a secret key
- **THEN** a new key is printed with the instructions for using it, and no configuration is written

### Requirement: The configuration can be read from the command line

The `config` command SHALL report the configuration the store holds and where that store is.

#### Scenario: The configuration itself

- **WHEN** the operator asks the `config` command to show the configuration
- **THEN** the configuration the store holds is printed, in the format it is written in

#### Scenario: Where the configuration lives

- **WHEN** the operator asks the `config` command for the path
- **THEN** the store that holds the configuration is named

### Requirement: The older spellings keep working

Every flag the command line has today SHALL keep working for one release, and the instance SHALL say which command has replaced it.

#### Scenario: A flag that has become a command

- **WHEN** an operator types the flag that prints the endpoint invite
- **THEN** the invite is printed, and the instance says which command replaces the flag

#### Scenario: Two ways of asking for the same thing

- **WHEN** an operator types a flag and the command that replaced it, together
- **THEN** the instance refuses, and names both ways of asking

#### Scenario: A modifier on its own

- **WHEN** an operator types a flag that only means something next to another flag, without that other flag
- **THEN** the instance says the flag has been replaced, and the request it would have changed is not made

#### Scenario: A spelling that was retired before this change

- **WHEN** an operator types a flag that another change has already retired
- **THEN** the instance refuses it, and points at the command that replaced it — this change does not bring the spelling back

### Requirement: The messages name the commands

Every message the binary prints that names a flag SHALL name the command that has replaced the flag.

#### Scenario: The instructions the binary prints

- **WHEN** the binary tells the operator how to enroll a client, or how to revoke an invite
- **THEN** the message names the command to run, not the flag it replaced

### Requirement: The QR drawing options are named for what they do

The command line SHALL take `--format`, `--invert` and `--out` for how a QR code is drawn, and SHALL keep the older `--qr-format`, `--qr-invert` and `--qr-out` spellings.

#### Scenario: The older spelling of a drawing option

- **WHEN** an operator types `--qr-format` where a format is asked for
- **THEN** the QR code is drawn in that format, as it was before the rename

#### Scenario: The newer spelling of a drawing option

- **WHEN** an operator types `--format` where a format is asked for
- **THEN** the QR code is drawn in that format
