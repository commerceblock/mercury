#!/bin/bash
(cargo build && cargo test && cd integration-tests && cargo test --no-default-features -- --test-threads=1 && cargo test test_deposit_pay_on_demand --no-default-features -- --test-threads=1 --include-ignored)
