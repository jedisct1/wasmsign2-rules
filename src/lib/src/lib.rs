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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const TEST_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tmp");

    fn test_path(name: &str) -> String {
        format!("{TEST_DIR}/{name}")
    }

    #[test]
    fn test_parse_valid_config_any_policy() {
        let yaml = format!(
            r#"
signers:
  dev:
    policy: any
    public_keys:
      - file: {}
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - dev
"#,
            test_path("test1.pub"),
            test_path("test2.pub")
        );

        let rules: raw::Rules = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(rules.signers.len(), 1);
        assert!(rules.signers.contains_key("dev"));
        assert_eq!(rules.signers["dev"].policy, Some("any".to_string()));
        assert_eq!(rules.signers["dev"].public_keys.len(), 2);
    }

    #[test]
    fn test_parse_valid_config_all_policy() {
        let yaml = format!(
            r#"
signers:
  team:
    policy: all
    public_keys:
      - file: {}

required_signatures:
  - sections:
      - type: standard
    signers_names:
      - team
"#,
            test_path("test1.pub")
        );

        let rules: raw::Rules = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(rules.signers["team"].policy, Some("all".to_string()));
    }

    #[test]
    fn test_parse_valid_config_threshold_policy() {
        let yaml = format!(
            r#"
signers:
  reviewers:
    policy: threshold(2)
    public_keys:
      - file: {}
      - file: {}
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - reviewers
"#,
            test_path("test1.pub"),
            test_path("test2.pub"),
            test_path("test3.pub")
        );

        let rules: raw::Rules = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(
            rules.signers["reviewers"].policy,
            Some("threshold(2)".to_string())
        );
    }

    #[test]
    fn test_parse_section_types() {
        let yaml = format!(
            r#"
signers:
  dev:
    public_keys:
      - file: {}

required_signatures:
  - sections:
      - type: standard
      - type: any
      - type: custom
        eq: "name"
      - type: custom
        matching: "^[.]debug_.*"
    signers_names:
      - dev
"#,
            test_path("test1.pub")
        );

        let rules: raw::Rules = serde_yml::from_str(&yaml).unwrap();
        let sections = &rules.required_signatures.unwrap()[0].sections;
        assert_eq!(sections.len(), 4);
        assert_eq!(sections[0].r#type, "standard");
        assert_eq!(sections[1].r#type, "any");
        assert_eq!(sections[2].r#type, "custom");
        assert_eq!(sections[2].eq, Some("name".to_string()));
        assert_eq!(sections[3].r#type, "custom");
        assert_eq!(sections[3].matching, Some("^[.]debug_.*".to_string()));
    }

    #[test]
    fn test_load_rules_from_file() {
        let yaml = format!(
            r#"
signers:
  dev:
    policy: any
    public_keys:
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - dev
"#,
            test_path("test1.pub")
        );

        let config_path = test_path("test_config.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let rules = Rules::from_yaml_file(&config_path).unwrap();
        fs::remove_file(&config_path).unwrap();

        assert_eq!(rules.signers_map.len(), 1);
        assert!(rules.signers_map.contains_key("dev"));
    }

    #[test]
    fn test_invalid_policy_name() {
        let yaml = format!(
            r#"
signers:
  dev:
    policy: invalid_policy
    public_keys:
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - dev
"#,
            test_path("test1.pub")
        );

        let config_path = test_path("test_invalid_policy.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let result = Rules::from_yaml_file(&config_path);
        fs::remove_file(&config_path).unwrap();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, WSRError::ConfigError(_)));
    }

    #[test]
    fn test_invalid_threshold_zero() {
        let yaml = format!(
            r#"
signers:
  dev:
    policy: threshold(0)
    public_keys:
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - dev
"#,
            test_path("test1.pub")
        );

        let config_path = test_path("test_threshold_zero.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let result = Rules::from_yaml_file(&config_path);
        fs::remove_file(&config_path).unwrap();

        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_section_type() {
        let yaml = format!(
            r#"
signers:
  dev:
    public_keys:
      - file: {}

required_signatures:
  - sections:
      - type: unknown_type
    signers_names:
      - dev
"#,
            test_path("test1.pub")
        );

        let config_path = test_path("test_invalid_section.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let result = Rules::from_yaml_file(&config_path);
        fs::remove_file(&config_path).unwrap();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, WSRError::ConfigError(_)));
    }

    #[test]
    fn test_undefined_signer_reference() {
        let yaml = format!(
            r#"
signers:
  dev:
    public_keys:
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - nonexistent
"#,
            test_path("test1.pub")
        );

        let config_path = test_path("test_undefined_signer.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let result = Rules::from_yaml_file(&config_path);
        fs::remove_file(&config_path).unwrap();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, WSRError::ConfigError(_)));
    }

    #[test]
    fn test_verify_signed_module_success() {
        let yaml = format!(
            r#"
signers:
  dev:
    policy: any
    public_keys:
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - dev
"#,
            test_path("test1.pub")
        );

        let config_path = test_path("test_verify_success.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let rules = Rules::from_yaml_file(&config_path).unwrap();
        fs::remove_file(&config_path).unwrap();

        let wasm_bytes = fs::read(test_path("signed1.wasm")).unwrap();
        let mut reader = Cursor::new(wasm_bytes);

        let result = rules.verify(&mut reader, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_unsigned_module_fails() {
        let yaml = format!(
            r#"
signers:
  dev:
    policy: any
    public_keys:
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - dev
"#,
            test_path("test1.pub")
        );

        let config_path = test_path("test_verify_unsigned.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let rules = Rules::from_yaml_file(&config_path).unwrap();
        fs::remove_file(&config_path).unwrap();

        let wasm_bytes = fs::read(test_path("minimal.wasm")).unwrap();
        let mut reader = Cursor::new(wasm_bytes);

        let result = rules.verify(&mut reader, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), WSRError::VerificationError(_)));
    }

    #[test]
    fn test_verify_wrong_signer_fails() {
        let yaml = format!(
            r#"
signers:
  dev:
    policy: any
    public_keys:
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - dev
"#,
            test_path("test2.pub")
        );

        let config_path = test_path("test_verify_wrong_signer.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let rules = Rules::from_yaml_file(&config_path).unwrap();
        fs::remove_file(&config_path).unwrap();

        let wasm_bytes = fs::read(test_path("signed1.wasm")).unwrap();
        let mut reader = Cursor::new(wasm_bytes);

        let result = rules.verify(&mut reader, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_all_policy_success() {
        let yaml = format!(
            r#"
signers:
  team:
    policy: all
    public_keys:
      - file: {}
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - team
"#,
            test_path("test1.pub"),
            test_path("test2.pub")
        );

        let config_path = test_path("test_verify_all.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let rules = Rules::from_yaml_file(&config_path).unwrap();
        fs::remove_file(&config_path).unwrap();

        let wasm_bytes = fs::read(test_path("signed12.wasm")).unwrap();
        let mut reader = Cursor::new(wasm_bytes);

        let result = rules.verify(&mut reader, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_all_policy_missing_signature_fails() {
        let yaml = format!(
            r#"
signers:
  team:
    policy: all
    public_keys:
      - file: {}
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - team
"#,
            test_path("test1.pub"),
            test_path("test2.pub")
        );

        let config_path = test_path("test_verify_all_fail.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let rules = Rules::from_yaml_file(&config_path).unwrap();
        fs::remove_file(&config_path).unwrap();

        let wasm_bytes = fs::read(test_path("signed1.wasm")).unwrap();
        let mut reader = Cursor::new(wasm_bytes);

        let result = rules.verify(&mut reader, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_threshold_policy_success() {
        let yaml = format!(
            r#"
signers:
  team:
    policy: threshold(2)
    public_keys:
      - file: {}
      - file: {}
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - team
"#,
            test_path("test1.pub"),
            test_path("test2.pub"),
            test_path("test3.pub")
        );

        let config_path = test_path("test_verify_threshold.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let rules = Rules::from_yaml_file(&config_path).unwrap();
        fs::remove_file(&config_path).unwrap();

        let wasm_bytes = fs::read(test_path("signed12.wasm")).unwrap();
        let mut reader = Cursor::new(wasm_bytes);

        let result = rules.verify(&mut reader, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_threshold_policy_insufficient_fails() {
        let yaml = format!(
            r#"
signers:
  team:
    policy: threshold(2)
    public_keys:
      - file: {}
      - file: {}
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - team
"#,
            test_path("test1.pub"),
            test_path("test2.pub"),
            test_path("test3.pub")
        );

        let config_path = test_path("test_verify_threshold_fail.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let rules = Rules::from_yaml_file(&config_path).unwrap();
        fs::remove_file(&config_path).unwrap();

        let wasm_bytes = fs::read(test_path("signed1.wasm")).unwrap();
        let mut reader = Cursor::new(wasm_bytes);

        let result = rules.verify(&mut reader, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_rejected_signatures() {
        let yaml = format!(
            r#"
signers:
  allowed:
    public_keys:
      - file: {}
  banned:
    public_keys:
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - allowed

rejected_signatures:
  - sections:
      - type: any
    signers_names:
      - banned
"#,
            test_path("test1.pub"),
            test_path("test2.pub")
        );

        let config_path = test_path("test_rejected.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let rules = Rules::from_yaml_file(&config_path).unwrap();
        fs::remove_file(&config_path).unwrap();

        let wasm_bytes = fs::read(test_path("signed12.wasm")).unwrap();
        let mut reader = Cursor::new(wasm_bytes);

        let result = rules.verify(&mut reader, None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            WSRError::RejectedSignaturesError
        ));
    }

    #[test]
    fn test_no_required_signatures() {
        let yaml = format!(
            r#"
signers:
  dev:
    public_keys:
      - file: {}
"#,
            test_path("test1.pub")
        );

        let config_path = test_path("test_no_required.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let rules = Rules::from_yaml_file(&config_path).unwrap();
        fs::remove_file(&config_path).unwrap();

        let wasm_bytes = fs::read(test_path("minimal.wasm")).unwrap();
        let mut reader = Cursor::new(wasm_bytes);

        let result = rules.verify(&mut reader, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_default_policy_is_any() {
        let yaml = format!(
            r#"
signers:
  dev:
    public_keys:
      - file: {}
      - file: {}

required_signatures:
  - sections:
      - type: any
    signers_names:
      - dev
"#,
            test_path("test1.pub"),
            test_path("test2.pub")
        );

        let config_path = test_path("test_default_policy.yaml");
        fs::write(&config_path, &yaml).unwrap();

        let rules = Rules::from_yaml_file(&config_path).unwrap();
        fs::remove_file(&config_path).unwrap();

        let wasm_bytes = fs::read(test_path("signed1.wasm")).unwrap();
        let mut reader = Cursor::new(wasm_bytes);

        let result = rules.verify(&mut reader, None);
        assert!(result.is_ok());
    }
}
