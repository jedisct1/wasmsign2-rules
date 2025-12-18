use regex::RegexBuilder;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Seek};
use std::path::Path;
use wasmsign2::*;

mod error;

pub use error::*;

mod raw {
    use super::*;

    #[derive(Debug, Deserialize)]
    pub(crate) struct RequiredSections {
        pub r#type: String,
        pub matching: Option<String>,
        pub eq: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub(crate) struct Signer {
        pub file: String,
    }

    #[derive(Debug, Deserialize)]
    pub(crate) struct Signers {
        pub policy: Option<String>,
        pub public_keys: Vec<Signer>,
    }

    #[derive(Debug, Deserialize)]
    pub(crate) struct Rule {
        pub sections: Vec<RequiredSections>,
        pub signers_names: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
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
    rules_raw: &Option<Vec<raw::Rule>>,
    signers: &BTreeMap<String, Signers>,
) -> Result<Vec<Rule>, WSRError> {
    let Some(rules_raw) = rules_raw else {
        return Ok(vec![]);
    };
    let mut rules = vec![];
    for rule_raw in rules_raw {
        let mut sections = vec![];
        for section_raw in &rule_raw.sections {
            let section = match section_raw.r#type.as_str() {
                "standard" => RequiredSections::StandardSections,
                "any" => RequiredSections::Any,
                "custom" => match (&section_raw.matching, &section_raw.eq) {
                    (Some(rx), _) => {
                        RequiredSections::CustomSections(RequiredCustomSections::Regex(rx.clone()))
                    }
                    (_, Some(name)) => {
                        RequiredSections::CustomSections(RequiredCustomSections::Eq(name.clone()))
                    }
                    _ => continue,
                },
                x => {
                    return Err(WSRError::ConfigError(format!(
                        "Unexpected matcher name for a section set: [{x}]"
                    )))
                }
            };
            sections.push(section);
        }
        for signer_name in &rule_raw.signers_names {
            if !signers.contains_key(signer_name) {
                return Err(WSRError::ConfigError(format!(
                    "Signer name not defined: [{signer_name}]"
                )));
            }
        }
        rules.push(Rule {
            sections,
            signers_names: rule_raw.signers_names.clone(),
        });
    }
    Ok(rules)
}

impl Rules {
    pub fn from_yaml_file(file: impl AsRef<Path>) -> Result<Rules, WSRError> {
        let yaml = fs::read_to_string(file.as_ref())?;
        let rules_raw: raw::Rules = serde_yml::from_str(&yaml)?;

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
                            WSRError::ConfigError(format!("Invalid threshold: [{x}]"))
                        })?;
                        if threshold == 0 {
                            return Err(WSRError::ConfigError(format!("Invalid threshold: [{x}]")));
                        }
                        Policy::Threshold(threshold)
                    }
                    x => {
                        return Err(WSRError::ConfigError(format!(
                            "Unexpected policy name: [{x}]"
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
                    WSRError::InternalError(format!("Signer not found: [{signer_name}]"))
                })?;
                let pks = &signers.pks;

                let predicate = |section: &Section| {
                    rule.sections.iter().any(|req| match req {
                        RequiredSections::Any => true,
                        RequiredSections::StandardSections => {
                            matches!(section, Section::Standard(_))
                        }
                        RequiredSections::CustomSections(RequiredCustomSections::Eq(name)) => {
                            matches!(section, Section::Custom(cs) if cs.name() == *name)
                        }
                        RequiredSections::CustomSections(RequiredCustomSections::Regex(rx)) => {
                            let Section::Custom(cs) = section else {
                                return false;
                            };
                            RegexBuilder::new(rx)
                                .size_limit(1_000_000)
                                .dfa_size_limit(1_000_000)
                                .nest_limit(1000)
                                .build()
                                .map(|rx| rx.is_match(cs.name()))
                                .unwrap_or(false)
                        }
                    })
                };
                let predicates = [Box::new(predicate)];

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
