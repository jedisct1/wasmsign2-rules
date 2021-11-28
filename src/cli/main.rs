#[macro_use]
extern crate clap;

use std::{fs, io};

use clap::Arg;
use wasmsign2_rules::Rules;

fn main() {
    let matches = app_from_crate!()
        .arg(
            Arg::with_name("rules")
                .value_name("rules_file")
                .long("--rules")
                .short("-r")
                .multiple(false)
                .required(true)
                .help("Rules file"),
        )
        .arg(
            Arg::with_name("input")
                .value_name("input_file")
                .long("--input")
                .short("-i")
                .multiple(false)
                .required(true)
                .help("WASM input file"),
        )
        .arg(
            Arg::with_name("signature_file")
                .value_name("signature_file")
                .long("--signature-file")
                .short("-S")
                .multiple(false)
                .help("Signature file"),
        )
        .get_matches();

    let rules_file = matches.value_of("rules").unwrap();
    let input_file = matches.value_of("input").unwrap();
    let signature_file = matches.value_of("signature_file");

    let rules = Rules::from_yaml_file(rules_file).unwrap();
    let input = fs::File::open(input_file).unwrap();
    let mut reader = io::BufReader::new(input);

    let detached_signature_vec;
    let detached_signature = match signature_file {
        None => None,
        Some(signature_file) => {
            detached_signature_vec = fs::read(signature_file).unwrap();
            Some(detached_signature_vec.as_slice())
        }
    };

    rules.verify(&mut reader, detached_signature).unwrap();
}
