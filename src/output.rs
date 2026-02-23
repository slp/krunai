// Copyright 2026 Sergio Lopez
// SPDX-License-Identifier: Apache-2.0

/// Print to stdout only if verbose mode is enabled
#[macro_export]
macro_rules! vprintln {
    ($verbose:expr, $($arg:tt)*) => {
        if $verbose {
            println!($($arg)*);
        }
    };
}

/// Print to stdout only if verbose mode is enabled (without newline)
#[macro_export]
macro_rules! vprint {
    ($verbose:expr, $($arg:tt)*) => {
        if $verbose {
            print!($($arg)*);
        }
    };
}
