# wasmsign2-rules

A rules-based signature verification tool for WebAssembly modules. Define signing policies in YAML and verify that WASM files meet your signature requirements.

## Features

- Define multiple signer groups with different public keys
- Flexible verification policies: require any, all, or a threshold of signatures
- Match signatures against specific WASM sections (standard, custom by name, or custom by regex)
- Support for rejected signatures (signatures that must NOT be present)
- Detached signature support

## Usage

```bash
wasmsign2-rules --rules policy.yaml --input module.wasm
```

With a detached signature:

```bash
wasmsign2-rules --rules policy.yaml --input module.wasm --signature-file module.wasm.sig
```

## Configuration

Policies are defined in YAML. Here's an example:

```yaml
signers:
  developers:
    policy: any
    public_keys:
      - file: /path/to/dev1.pub
      - file: /path/to/dev2.pub

  reviewers:
    policy: threshold(2)
    public_keys:
      - file: /path/to/reviewer1.pub
      - file: /path/to/reviewer2.pub
      - file: /path/to/reviewer3.pub

required_signatures:
  - sections:
      - type: standard
      - type: custom
        matching: "^[.]debug_.*"
      - type: custom
        eq: "producers"
    signers_names:
      - developers

  - sections:
      - type: any
    signers_names:
      - reviewers

rejected_signatures:
  - sections:
      - type: any
    signers_names:
      - untrusted
```

### Signer policies

- `any` - At least one signature from the group must verify (default)
- `all` - All public keys in the group must have valid signatures
- `threshold(N)` - At least N signatures from the group must verify

### Section types

- `standard` - Standard WASM sections (types, functions, memory, etc.)
- `custom` with `eq` - Custom section matching an exact name
- `custom` with `matching` - Custom section matching a regex pattern
- `any` - Any section

## Library usage

```rust
use wasmsign2_rules::Rules;
use std::fs::File;
use std::io::BufReader;

let rules = Rules::from_yaml_file("policy.yaml")?;
let mut reader = BufReader::new(File::open("module.wasm")?);
rules.verify(&mut reader, None)?;
```
