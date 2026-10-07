use std::io::{self, Write};
use std::process::ExitCode;
use winkey_helper::{
    ops::UnavailableOps,
    wire::{dispatch, read_request, Response},
};
use zeroize::Zeroize;

fn main() -> ExitCode {
    let response = match read_request(io::stdin().lock()) {
        Ok(request) => dispatch(request, &mut UnavailableOps),
        Err(error) => Response::from_error(error),
    };
    let failed = response.is_error();
    let mut output = response.to_json();
    output.push('\n');
    let written = io::stdout().lock().write_all(output.as_bytes());
    output.zeroize();
    if failed || written.is_err() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
