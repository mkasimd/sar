<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: Apache-2.0
-->

# CDC normative clarification proposal (decision support)

**Reference:** `SAR-M13b2-EVIDENCE-IMPLEMENTATION-001`
**Status:** Superseded in part. The Controller approved
`SAR-M13b2-CDC-NORMATIVE-CLARIFICATION-001` and
`SAR-M13b2-CDC-NORMATIVE-IMPLEMENTATION-001` encoded it in `specification.md`
Sections 20 and 21 (see the decision record below). Where this proposal differs
from the approved decision or the specification, the specification governs. This
document makes no CDC resolver, `CDC_MAP` or Recipe wire change, and resolver
implementation remains unauthorized.

Scope: Sections 20 and 21 of `specification.md`. Affected finding:
`M13-TRANSFORM-009` (CDC recipe resolution, mandatory for a Standard Profile
claim).

## 1. Ambiguities

### A1. Recipe hash algorithm selection

- §20.2: "The length and type of hashes in the recipe are determined by the
  `DEDUPLICATION` (Bit 29) setting." `DEDUPLICATION` is a Global Flag. It
  makes the LFH carry a `Hash Algo ID` and a 32-byte `Content Hash`, which
  describe the *final logical Entry*, not chunks.
- §21.1: `CDC_MAP` is "self-describing" through its header `Hash_Algorithm_ID`
  and fixes `Record_Size` at 48 with 32-byte hashes.
- A Recipe Entry's payload is "a contiguous array of binary hashes" with no
  header, so its element width and algorithm must come from somewhere
  external to the payload. The sources named (`DEDUPLICATION`, the `CDC_MAP`
  header, an external provider) are not reconciled, and a Recipe may be
  resolved by an external CAS that has no `CDC_MAP`.

### A2. Relationship to DEDUPLICATION

- It is unspecified whether Recipe Mode (`CDC Algo ID > 0`) requires
  `DEDUPLICATION` to be set.
- If it does, the same `Hash Algo ID` would serve as both the Recipe element
  hash and the Content Hash algorithm of the reconstructed Entry. These are
  different objects and may legitimately want different algorithms.
- The LFH `Content Hash` of a Recipe Entry is ambiguous: it could cover the
  Recipe payload or the resolved logical Entry. §13.1.3 places final logical
  integrity verification after CDC resolution, which suggests the latter.

### A3. Stored chunk representation at `CDC_MAP` offsets

- Records reference a "stored chunk payload" at `Member_Offset` with
  `Compressed_Size`. The field name suggests compression, but nothing says
  what the bytes at that offset are: a raw chunk, a compressed chunk (which
  codec, since there is no per-chunk algorithm field), an encrypted chunk
  (which key, nonce and AAD), or a full physical LFH plus payload.
- It is also unspecified whether the offset points to a standalone byte run
  or into the Payload Data of an existing Entry, and how an unpartitioned
  versus partitioned member boundary applies.

### A4. Interpretation and validation of stored-chunk hashes

- §21.1 verifies the hash "over the exact stored byte range", so the hash is
  over the stored representation. A Recipe hash that a CAS or recipe author
  computes is normally over the *logical chunk bytes*. If stored bytes are
  compressed or encrypted, the two differ and a Recipe cannot be matched to
  `CDC_MAP` records.
- It is unspecified whether the Recipe lookup key is the record `Hash`, whether
  duplicate hashes in one map are an error, and whether a resolved chunk's
  logical bytes must be re-hashed after decoding.

### A5. Application-provided chunk resolution

- §21.2 specifies only a URI string and `SAR_ERR_RECIPE_UNRESOLVABLE` (402).
  There is no provider interface, no required behavior on partial results, no
  maximum chunk size, count or total expansion bound, and no statement that
  parsing, listing and verification remain side-effect-free.
- Security text is permissive (SHOULD validate, MAY allowlist) and does not say
  whether resolution is off by default, nor whether a provider-returned chunk
  must be hash-verified before use.

## 2. Alternatives and recommendation

| Topic | Alternative 1 | Alternative 2 | Recommendation |
| --- | --- | --- | --- |
| A1 Recipe hash algorithm | Use the Entry's LFH `Hash Algo ID` | Use `CDC_MAP.Hash_Algorithm_ID`; external CAS supplies its own algorithm | Alt 2 for the local catalog (already self-describing); for external providers the resolver API states the algorithm. Recipe element width = 32 bytes in v1, matching `Record_Size` 48. |
| A2 DEDUPLICATION | Recipe Mode requires `DEDUPLICATION`; Recipe hash and Content Hash share one algorithm | Recipe Mode is independent; LFH `Content Hash` covers the *resolved logical Entry* if `DEDUPLICATION` is set | Alt 2: independent. State that `Content Hash` always covers the final logical Entry (consistent with §13.1.3), and reword §20.2 so it no longer refers to `DEDUPLICATION` for recipe hashes. |
| A3 Stored chunk bytes | Raw, uncompressed, unencrypted logical chunk bytes; `Compressed_Size` is then misnamed | A self-describing stored chunk: small chunk header (algorithm ID, flags) followed by the bytes | Smallest wire-neutral choice: Alt 1 with an explicit statement that chunk bytes at `Member_Offset` are raw logical bytes and `Compressed_Size` is their stored length (rename in a later revision). Per-chunk compression/encryption would need new wire semantics and is out of scope. |
| A4 Hash validation | Hash covers the stored range only (as today) | Hash covers the stored range and, because stored = logical under A3 Alt 1, also equals the logical-chunk hash | Follows from A3 Alt 1: the single hash serves both. Require re-verification of every resolved chunk against the Recipe hash before it is appended. Duplicate `Hash` values with differing locations: reject (`SAR_ERR_METADATA_CONFLICT`); identical duplicates tolerated. |
| A5 Resolver boundary | Normative provider protocol for `sarp+https` | Abstract application-provided resolver; SAR defines only the contract | Alt 2. Library contract: a caller-supplied resolver is the only way external chunks are fetched; no network access by default; `CDC_EXT_PROVIDER` is metadata, never an instruction to fetch; any resolved chunk must verify against the Recipe hash; resolver output bounded by chunk-size, chunk-count and total-expansion limits checked before allocation; unresolved hash returns `SAR_ERR_RECIPE_UNRESOLVABLE`. Parsing, listing and verification never invoke the resolver. |

## 3. Proposed normative edits (for Controller review)

1. Replace the §20.2 "Hash Algorithm" bullet: the Recipe element hash is the
   algorithm identified by the applicable catalog (`CDC_MAP.Hash_Algorithm_ID`
   or the external provider contract), 32 bytes in v1, independent of
   `DEDUPLICATION`.
2. Add to §20.2: Recipe Mode does not require `DEDUPLICATION`; when
   `DEDUPLICATION` is set the LFH `Hash Algo ID` / `Content Hash` cover the
   final logical Entry after CDC resolution.
3. Add to §21.1: bytes at `[Member_Offset, Member_Offset + Compressed_Size)`
   are the raw logical chunk bytes in v1; the hash covers those bytes.
4. Add to §20.3 / §21.2: every resolved chunk MUST be verified against its
   Recipe hash before use; resolution limits are enforced before allocation;
   external resolution MUST NOT occur during parsing, listing or verification.
5. Add duplicate-hash handling to §21.1 structural validation.

## 4. Impact if adopted

- **Wire:** none (clarifies existing fields). The `Compressed_Size` name
  remains until a later revision.
- **Implementation:** a bounded archive-level CDC resolver using `sar-cdc`
  helpers (`SAR-M13b2-GROUPWIDE-IMPLEMENTATION-001`); `FRAGMENT_GAP` for
  incomplete fragmented Recipes applies. Stream/session CDC and
  cross-Partition lookup remain open (M13b.4, M13b.3).
- **Gating (historical):** The Controller approved A1 to A5 and the normative
  alignment was integrated; Standard Profile CDC claims still require the
  remaining Section 12 obligations.

## 5. Decision record (`SAR-M13b2-CDC-NORMATIVE-CLARIFICATION-001`)

| Item | Encoded in `specification.md` |
| --- | --- |
| A1 | §20.2, §21.1: Recipe hash algorithm comes from `CDC_MAP.Hash_Algorithm_ID` or the explicit resolver contract, using the existing Section 9.4 registry; no new identifiers; ambiguous catalog selection is `SAR_ERR_METADATA_CONFLICT`. |
| A2 | §20.2: Recipe Mode does not require `DEDUPLICATION`; LFH `Hash Algo ID` / `Content Hash` cover the final logical Entry. |
| A3 | §21.1: `Member_Offset` starts raw logical chunk bytes; `Compressed_Size` is their stored length; no per-chunk compression, encryption or header in v1. |
| A4 | §20.3, §21.1: every resolved chunk is verified against its Recipe hash; conflicting duplicates are `SAR_ERR_METADATA_CONFLICT`; identical duplicates are tolerated. |
| A5 | §20.3, §21.2: resolution is explicitly configured and bounded; the URI is metadata only; parsing, listing and structural verification never resolve externally. |
