# Test vectors

Files here are read by the test suite at run time. Drop one in and the matching
test starts checking against it; leave it out and that test prints a skip
notice and passes.

That arrangement exists for a specific reason. Two algorithms in this workspace
are registered `experimental` rather than `available`:

| algorithm | what is verified | what is not |
|---|---|---|
| `ml-kem-768` | NTT against schoolbook multiplication, packing against a bit buffer, samplers against FIPS 203's pseudocode, key and ciphertext sizes against the standard | that the assembly computes what other implementations compute |
| `aes-256-gcm-siv` | POLYVAL against the GHASH construction of RFC 8452 Appendix A, AES against FIPS 197 | the same |

Neither gap is a code problem. Both are missing *files*, and supplying one
promotes the algorithm without anybody writing code.

## Format

```json
{
  "algorithm": "aes-kw",
  "source": "RFC 3394 sections 4.1 through 4.6",
  "cases": [
    { "key": "000102...", "pt": "00112233...", "ct": "1fa68b..." }
  ]
}
```

Every value is a hex string. Whitespace inside one is ignored, so vectors can
be pasted in the layout the source document uses. Which fields a case needs
depends on the algorithm — see the table below.

A file that is present but malformed fails the run rather than being skipped.
Someone went to the trouble of providing it, and quietly ignoring it would waste
that effort in the most confusing way available.

## Files the tests look for

| file | fields per case | where to get it |
|---|---|---|
| `aes-kw.json` | `key`, `pt`, `ct` | RFC 3394 section 4. **Bundled** — this one is in the repository, and is what proves the harness itself works |
| `aes-gcm-siv.json` | `key`, `nonce`, `aad`, `pt`, `ct` (ciphertext with the tag appended) | RFC 8452 Appendix C |
| `ml-kem-768-keygen.json` | `d`, `z`, `ek`, `dk` | ACVP `ML-KEM-keyGen-FIPS203`, `AFT` groups |
| `ml-kem-768-encap.json` | `ek`, `m`, `c`, `k` | ACVP `ML-KEM-encapDecap-FIPS203`, encapsulation `AFT` groups |

## Converting ACVP files

ACVP's own JSON nests differently for each algorithm and carries a good deal
that is irrelevant here, so the harness does not read it directly — a converter
that tracked every ACVP revision would be more code than the tests it feeds.
A few lines of `jq` do the job instead. For ML-KEM key generation:

```sh
jq '{
  algorithm: "ml-kem-768",
  source: "ACVP ML-KEM-keyGen-FIPS203",
  cases: [ .testGroups[] | select(.parameterSet == "ML-KEM-768")
           | .tests[] | {d, z, ek, dk} ]
}' ACVP-keyGen.json > testvectors/ml-kem-768-keygen.json
```

The `AFT` groups are the ones with expected outputs. If your file is a prompt
file without them, you need the matching `expectedResults` file and should join
the two on `tcId` first.

## Adding a new algorithm

Write the test beside the implementation, load with
`ac_vectors::VectorFile::load_or_report("name")`, and return early when it gives
`None`. The skip notice it prints is deliberate: a vector test that silently
passes with no input reports success for work nobody did.
