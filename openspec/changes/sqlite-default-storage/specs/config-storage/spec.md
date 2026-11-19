# Spec Delta

## Purpose

Where a running instance keeps its configuration, which store an operator gets when they have not said, and how a configuration written for the file store reaches a database store.

## ADDED Requirements

### Requirement: The database store is the default

An instance SHALL keep its configuration in a database store when the operator has not chosen a store.

#### Scenario: A deployment that says nothing about its store

- **WHEN** an instance starts with no store named on the command line and none in the environment
- **THEN** it keeps its configuration in the database store

#### Scenario: A deployment that names the file store

- **WHEN** an instance starts with the file store named explicitly
- **THEN** it keeps its configuration in that file and opens no database

### Requirement: The default database path follows the configuration directory

The instance SHALL derive the path of the default database from the configuration directory, and SHALL let an explicit URL override it.

#### Scenario: A configuration directory in the environment

- **WHEN** the environment names a configuration directory and no database URL is given
- **THEN** the database is the file `nexapipe.db` inside that directory

#### Scenario: No configuration directory

- **WHEN** neither a configuration directory nor a database URL is given
- **THEN** the database is the file `nexapipe.db` in the working directory

#### Scenario: A database URL that overrides the derived path

- **WHEN** a database URL is given on the command line or in the environment
- **THEN** that URL is the database the store opens, and the derived path is not used

### Requirement: The file store stays available

The file store SHALL remain selectable, and SHALL keep reading and writing the file it is given.

#### Scenario: A deployment that wants a file it can read

- **WHEN** an instance is started with the file store named
- **THEN** the configuration is read from that file, and a change to it is written back to that file

### Requirement: A legacy configuration file is imported once

When the database holds no configuration and a `config.toml` sits beside it, the instance SHALL import that file's configuration into the database exactly once, and SHALL leave the file where it is.

#### Scenario: The first start next to an existing file

- **WHEN** an instance starts, finds its database holds no configuration, and finds a `config.toml` beside it
- **THEN** the configuration in the file is in the database once the start proceeds

#### Scenario: A start that finds the configuration already there

- **WHEN** an instance starts and its database already holds the configuration
- **THEN** the file beside it is not read, and the configuration in the file is not applied

#### Scenario: The operator is told what happened

- **WHEN** a file has been imported into the database
- **THEN** the instance reports which file was imported and that the database is what it now reads

#### Scenario: The imported file is still there afterwards

- **WHEN** a file has been imported into the database
- **THEN** the file is still at the path it was at

#### Scenario: A file that cannot be read

- **WHEN** the file beside an empty database cannot be parsed
- **THEN** the start fails with the reason it could not be read, and the database is left holding no configuration

### Requirement: A store accepts a whole configuration

A store SHALL accept a complete configuration and make it the configuration it holds.

#### Scenario: A configuration written into an empty store

- **WHEN** a configuration is written into a store that holds none
- **THEN** reading the store afterwards returns that configuration

#### Scenario: A configuration written over another one

- **WHEN** a configuration is written into a store that already holds one
- **THEN** reading the store afterwards returns the configuration that was written, and the store's revision has moved
