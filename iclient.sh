#!/usr/bin/env bash

cd client
if [ -f ../target/debug/cli ]; then
    ../target/debug/cli "$@"
elif [ -f ../target/release/cli ]; then
    ../target/release/cli "$@"
fi
