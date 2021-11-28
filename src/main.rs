use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use wasmsign2::reexports::thiserror;
use wasmsign2::*;

#[derive(Debug, thiserror::Error)]
pub enum WSRError {
    #[error("Internal error: [{0}]")]
    InternalError(String),
    #[error("Configuration error: [{0}]")]
    ConfigError(String),
    #[error("I/O error: [{0}]")]
    IOError(#[from] io::Error),
    #[error("YAML error: [{0}]")]
    YAMLError(#[from] serde_yaml::Error),
    #[error("WASMSign error: [{0}]")]
    WSError(#[from] wasmsign2::WSError),
}

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
pub struct Rules {
    signers: BTreeMap<String, PublicKeySet>,
    required_signatures: Vec<Rule>,
    rejected_signatures: Vec<Rule>,
}

fn signature_rules(
    required_signatures_raw: &Option<Vec<raw::Rule>>,
    signers: &BTreeMap<String, PublicKeySet>,
) -> Result<Vec<Rule>, WSRError> {
    let mut required_signatures = vec![];
    let required_signatures_raw = match required_signatures_raw {
        Some(rules) => rules,
        None => return Ok(required_signatures),
    };
    for rule_raw in required_signatures_raw {
        let mut sections = vec![];
        for section_raw in &rule_raw.sections {
            match section_raw.r#type.as_str() {
                "standard" => {
                    sections.push(RequiredSections::StandardSections);
                }
                "custom" => {
                    if let Some(rx) = &section_raw.matching {
                        sections.push(RequiredSections::CustomSections(
                            RequiredCustomSections::Regex(rx.clone()),
                        ));
                    } else if let Some(name) = &section_raw.eq {
                        sections.push(RequiredSections::CustomSections(
                            RequiredCustomSections::Eq(name.clone()),
                        ));
                    }
                }
                x => {
                    return Err(WSRError::ConfigError(format!(
                        "Unexpected matcher name for a section set: [{}]",
                        x
                    )))
                }
            }
        }
        for signer_name in &rule_raw.signers_names {
            if !signers.contains_key(signer_name) {
                return Err(WSRError::ConfigError(format!(
                    "Signer name not defined: [{}]",
                    signer_name
                )));
            }
        }
        let rule = Rule {
            sections,
            signers_names: rule_raw.signers_names.clone(),
        };
        required_signatures.push(rule);
    }
    Ok(required_signatures)
}

impl Rules {
    pub fn from_yaml_file(file: impl AsRef<Path>) -> Result<Rules, WSRError> {
        let yaml = fs::read_to_string(file.as_ref())?;
        let rules_raw: raw::Rules = serde_yaml::from_str(&yaml)?;

        let mut signers = BTreeMap::new();
        for (signers_name_raw, signers_raw) in rules_raw.signers {
            let mut pks = PublicKeySet::empty();
            for signer_raw in signers_raw {
                let pk = PublicKey::from_file(&signer_raw.file)?;
                pks.insert(pk)?;
            }
            signers.insert(signers_name_raw, pks);
        }

        let required_signatures = signature_rules(&rules_raw.required_signatures, &signers)?;
        let rejected_signatures = signature_rules(&rules_raw.rejected_signatures, &signers)?;

        let rules = Rules {
            signers,
            required_signatures,
            rejected_signatures,
        };
        Ok(rules)
    }
}

fn main() {
    Rules::from_yaml_file("/tmp/a.yaml").unwrap();
}
