use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use wasmsign2::*;

mod raw {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct RequiredSections {
        pub r#type: String,
        pub matching: Option<String>,
        pub eq: Option<String>,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct Signer {
        pub file: String,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct Rule {
        pub sections: Vec<RequiredSections>,
        pub signers_names: Vec<String>,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct Rules {
        pub signers: BTreeMap<String, Vec<Signer>>,
        pub required_signatures: Option<Vec<Rule>>,
        pub rejected_signatures: Option<Vec<Rule>>,
    }
}

#[derive(Debug, Clone)]
enum RequiredCustomSections {
    Eq(String),
    Regex(String),
}

#[derive(Debug, Clone)]
enum RequiredSections {
    StandardSections,
    CustomSections(RequiredCustomSections),
}

#[derive(Debug, Clone)]
struct Rule {
    pub sections: Vec<RequiredSections>,
    pub signers_names: Vec<String>,
}

#[derive(Debug, Clone)]
struct Rules {
    signers: BTreeMap<String, PublicKeySet>,
    required_signatures: Vec<Rule>,
    rejected_signatures: Vec<Rule>,
}

fn main() {
    let yaml = fs::read_to_string("/tmp/a.yaml").unwrap();
    let rules_raw: raw::Rules = serde_yaml::from_str(&yaml).unwrap();
    dbg!(&rules_raw);

    let mut signers = BTreeMap::new();
    for (signers_name_raw, signers_raw) in rules_raw.signers {
        let mut pks = PublicKeySet::empty();
        for signer_raw in signers_raw {
            let pk = PublicKey::from_file(&signer_raw.file).unwrap();
            pks.insert(pk).unwrap();
        }
        signers.insert(signers_name_raw, pks);
    }

    let mut required_signatures = vec![];
    for rule_raw in rules_raw.required_signatures.unwrap_or_default() {
        let mut sections = vec![];
        for section_raw in rule_raw.sections {
            match section_raw.r#type.as_str() {
                "standard" => {
                    sections.push(RequiredSections::StandardSections);
                }
                "custom" => {
                    if let Some(rx) = section_raw.matching {
                        sections.push(RequiredSections::CustomSections(
                            RequiredCustomSections::Regex(rx),
                        ));
                    } else if let Some(name) = section_raw.eq {
                        sections.push(RequiredSections::CustomSections(
                            RequiredCustomSections::Eq(name),
                        ));
                    }
                }
                _ => panic!("Unexpected custom section name matcher"),
            }
        }
        for signer_name in &rule_raw.signers_names {
            if !signers.contains_key(signer_name) {
                panic!("Signer name not defined");
            }
        }
        let rule = Rule {
            sections,
            signers_names: rule_raw.signers_names,
        };
        required_signatures.push(rule);
    }

    let rejected_signatures = vec![];

    let rules = Rules {
        signers,
        required_signatures,
        rejected_signatures,
    };
    dbg!(rules);
}
