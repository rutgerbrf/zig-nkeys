# NKeys support for Zig

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![CI](https://github.com/rutgerbrf/zig-nkeys/actions/workflows/main.yml/badge.svg)](https://github.com/rutgerbrf/zig-nkeys/actions/workflows/main.yml)

Still a work in progress, things will definitely change!

Contains a tool called `znk` which is a clone of the [`nk` tool](https://github.com/nats-io/nkeys/tree/master/nk).

## Building

Zig master works at the time of writing.

Use `zig build znk` to build the `znk` tool.
The `znk` tool can be run by using `zig build run-znk`.

Tests for the library can be run by using `zig build test`.
Tests for the `znk` tool can be run by using `zig build test-znk`.

