# Spec Delta

## Purpose

The browser console a running instance offers: the pages it shows, the API it talks to, and the rule that decides who may change what.

## ADDED Requirements

### Requirement: The instance serves the console

The admin listener SHALL serve the console's static files when a console directory is configured, and SHALL not serve them when it is not.

#### Scenario: A configured console

- **WHEN** the console directory is configured and holds a built console
- **THEN** the listener serves the console's index at `/`, and the files the index asks for

#### Scenario: No console configured

- **WHEN** no console directory is configured
- **THEN** the listener answers the console's path with "not found", and every other path is answered as it was before

#### Scenario: A path that leaves the console directory

- **WHEN** a request names a path that would reach outside the console directory
- **THEN** the request is refused, and nothing outside the directory is served

### Requirement: The console's API answers in JSON

The listener SHALL answer the console's API with JSON, and SHALL never answer it with an allowance for another origin to read the answer.

#### Scenario: A question

- **WHEN** the console asks the API a question
- **THEN** the answer is JSON, and carries no header allowing another origin to read it

### Requirement: The console's API is addressed to this host

The listener SHALL refuse a request to the console's API whose host is not a loopback address.

#### Scenario: A request addressed to another name

- **WHEN** a request to the console's API carries a host that is not a loopback address
- **THEN** the request is refused, and the answer says the request was not addressed to this host

### Requirement: The console's API needs the admin token

The listener SHALL refuse a request to the console's API that does not carry the admin token.

#### Scenario: A request without the token

- **WHEN** a request to the console's API carries no admin token
- **THEN** the request is refused, and the answer says a token is needed

#### Scenario: A request with the token

- **WHEN** a request to the console's API carries the admin token
- **THEN** the request is answered

### Requirement: A write says that it is a write

The listener SHALL refuse a write to the console's API that does not carry the header `X-NexaPipe-Admin: 1`.

#### Scenario: A write without the header

- **WHEN** a write to the console's API arrives without the header
- **THEN** the request is refused, and the answer names the header

#### Scenario: A write with the header

- **WHEN** a write to the console's API arrives with the header
- **THEN** it is carried out

### Requirement: The console reads the instance

The console's API SHALL answer with the instance's status, its routes, its clients, the connections open right now and the health of its backends, and SHALL never answer with a client's secret.

#### Scenario: The clients

- **WHEN** the console asks which clients exist
- **THEN** the answer names every client and every device, and carries no secret

### Requirement: The console changes the clients

The console's API SHALL issue a credential to a client, drop a client's credential and drop one device's credential, and SHALL do it through the store the server reads.

#### Scenario: A client issued a credential

- **WHEN** the console issues a credential to a client
- **THEN** the credential is in the store, and a running instance accepts it after its next reload

#### Scenario: A client whose credential is dropped

- **WHEN** the console drops a client's credential
- **THEN** the credential is gone from the store, and the client can no longer authenticate

#### Scenario: A device whose credential is dropped

- **WHEN** the console drops one device's credential and names the device
- **THEN** that device's credential is gone, and the client and its other devices are untouched

### Requirement: The console changes the routes

The console's API SHALL add a route and remove a route, and SHALL do it through the store the server reads.

#### Scenario: A route added

- **WHEN** the console adds a route
- **THEN** the route is in the store, and a running instance serves it after its next reload

#### Scenario: A route removed

- **WHEN** the console removes a route
- **THEN** the route is gone from the store, and a running instance stops serving it after its next reload

#### Scenario: A route that is not there

- **WHEN** the console removes a route that is not in the store
- **THEN** the answer says there was no such route

### Requirement: The console is an application of its own

The console SHALL be a Vue 3 and TypeScript application built with Vite, laid out like the desktop application, and SHALL be translated the way the desktop application is translated.

#### Scenario: The console is built

- **WHEN** the console is built
- **THEN** the build produces a bundle of static files and the type check passes

#### Scenario: The console is run in another language

- **WHEN** the console is run in a language other than English
- **THEN** every string it shows is translated, and no string is left in English

#### Scenario: The console reaches the instance

- **WHEN** the console asks the instance a question
- **THEN** the question carries the admin token, and a write carries the write header as well
