package main

// Registers the "sqlite" driver expected by go-rpmdb's SQLite3 backend.
// mattn/go-sqlite3 registers "sqlite3" instead, which does not match.
import _ "modernc.org/sqlite"
