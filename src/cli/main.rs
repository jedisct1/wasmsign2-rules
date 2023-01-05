#[macro_use]
extern crate clap;

use std::{fs, io};

use clap::Arg;
use wasmsign2_rules::Rules;

fn main() {
    let matches = command!()
        .arg(
            Arg::new("rules")
                .value_name("rules_file")
                .long("rules")
                .short('r')
                .required(true)
                .help("Rules file"),
        )
        .arg(
            Arg::new("input")
                .value_name("input_file")
                .long("input")
                .short('i')
                .required(true)
                .help("WASM input file"),
        )
        .arg(
            Arg::new("signature_file")
                .value_name("signature_file")
                .long("signature-file")
                .short('S')
                .help("Signature file"),
        )
        .get_matches();

    let rules_file = matches.get_one::<String>("rules").unwrap();
    let input_file = matches.get_one::<String>("input").unwrap();
    let signature_file = matches.get_one::<String>("signature_file");

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
