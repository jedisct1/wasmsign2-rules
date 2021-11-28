use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek};
use std::path::Path;
use wasmsign2::*;

mod error;

pub use error::*;

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
    pub(crate) struct Signers {
        pub policy: Option<String>,
        pub public_keys: Vec<Signer>,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct Rule {
        pub sections: Vec<RequiredSections>,
        pub signers_names: Vec<String>,
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    pub(crate) struct Rules {
        pub signers: BTreeMap<String, Signers>,
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
    Any,
}

#[derive(Debug, Clone)]
struct Rule {
    pub sections: Vec<RequiredSections>,
    pub signers_names: Vec<String>,
}

#[derive(Debug, Copy, Clone)]
enum Policy {
    Any,
    All,
    Threshold(usize),
}

#[derive(Debug, Clone)]
struct Signers {
    pub policy: Policy,
    pub pks: PublicKeySet,
}

#[derive(Debug, Clone)]
pub struct Rules {
    signers_map: BTreeMap<String, Signers>,
    required_signatures: Vec<Rule>,
    rejected_signatures: Vec<Rule>,
}

fn signature_rules(
    required_signatures_raw: &Option<Vec<raw::Rule>>,
    signers: &BTreeMap<String, Signers>,
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
                "any" => sections.push(RequiredSections::Any),
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

        let mut signers_map = BTreeMap::new();
        for (signers_name_raw, signers_raw) in rules_raw.signers {
            let mut pks = PublicKeySet::empty();
            for public_key_raw in signers_raw.public_keys {
                pks.insert_any_file(&public_key_raw.file)?;
            }
            let policy = match &signers_raw.policy {
                Some(policy) => match policy.as_str() {
                    "any" => Policy::Any,
                    "all" => Policy::All,
                    x if x.starts_with("threshold(") && x.ends_with(')') => {
                        let threshold = x[10..x.len() - 1].parse::<usize>().map_err(|_| {
                            WSRError::ConfigError(format!("Invalid threshold: [{}]", x))
                        })?;
                        if threshold == 0 {
                            return Err(WSRError::ConfigError(format!(
                                "Invalid threshold: [{}]",
                                x
                            )));
                        }
                        Policy::Threshold(threshold)
                    }
                    x => {
                        return Err(WSRError::ConfigError(format!(
                            "Unexpected policy name: [{}]",
                            x
                        )))
                    }
                },
                None => Policy::Any,
            };
            let signers = Signers { policy, pks };
            signers_map.insert(signers_name_raw, signers);
        }

        let required_signatures = signature_rules(&rules_raw.required_signatures, &signers_map)?;
        let rejected_signatures = signature_rules(&rules_raw.rejected_signatures, &signers_map)?;

        let rules = Rules {
            signers_map,
            required_signatures,
            rejected_signatures,
        };
        Ok(rules)
    }

    fn _verify(
        &self,
        rules: &[Rule],
        reader: &mut (impl Read + Seek),
        detached_signature: Option<&[u8]>,
    ) -> Result<(), WSRError> {
        for rule in rules {
            for signer_name in &rule.signers_names {
                let signers = self.signers_map.get(signer_name).ok_or_else(|| {
                    WSRError::InternalError(format!("Signer not found: [{}]", signer_name))
                })?;
                let pks = &signers.pks;

                let predicate = move |section: &Section| {
                    for required_sections in &rule.sections {
                        match required_sections {
                            RequiredSections::Any => return true,
                            RequiredSections::StandardSections => {
                                if matches!(section, Section::Standard(_)) {
                                    return true;
                                }
                            }
                            RequiredSections::CustomSections(RequiredCustomSections::Eq(name)) => {
                                if let Section::Custom(custom_section) = section {
                                    if custom_section.name() == *name {
                                        return true;
                                    }
                                }
                            }
                            RequiredSections::CustomSections(RequiredCustomSections::Regex(rx)) => {
                                if let Section::Custom(custom_section) = section {
                                    let rx = match RegexBuilder::new(rx)
                                        .case_insensitive(false)
                                        .multi_line(false)
                                        .dot_matches_new_line(false)
                                        .size_limit(1_000_000)
                                        .dfa_size_limit(1_000_000)
                                        .nest_limit(1000)
                                        .build()
                                    {
                                        Ok(rx) => rx,
                                        Err(_) => return false,
                                    };
                                    if rx.is_match(custom_section.name()) {
                                        return true;
                                    }
                                }
                            }
                        };
                    }
                    false
                };
                let predicates = vec![Box::new(predicate)];

                reader.rewind()?;
                let res = match pks.verify_matrix(reader, detached_signature, &predicates) {
                    Ok(res) if !res.is_empty() => res,
                    _ => return Err(WSRError::VerificationError(signer_name.clone())),
                };
                let res = &res[0];
                match signers.policy {
                    Policy::All if res.len() != signers.pks.len() => {
                        return Err(WSRError::VerificationError(signer_name.clone()));
                    }
                    Policy::Any if res.is_empty() => {
                        return Err(WSRError::VerificationError(signer_name.clone()));
                    }
                    Policy::Threshold(threshold) if res.len() < threshold => {
                        return Err(WSRError::VerificationError(signer_name.clone()));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    pub fn verify(
        &self,
        reader: &mut (impl Read + Seek),
        detached_signature: Option<&[u8]>,
    ) -> Result<(), WSRError> {
        self._verify(&self.required_signatures, reader, detached_signature)?;

        if !self.rejected_signatures.is_empty()
            && self
                ._verify(&self.rejected_signatures, reader, detached_signature)
                .is_ok()
        {
            return Err(WSRError::RejectedSignaturesError);
        }
        Ok(())
    }
}
