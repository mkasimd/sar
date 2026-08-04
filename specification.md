<!--
SPDX-FileCopyrightText: 2026 M. Kasim Doenmez
SPDX-License-Identifier: CC-BY-4.0
-->

# The Streamable Archive and Replication Protocol (SAR Protocol)
## Abstract
This document specifies the Streamable Archive and Replication Protocol (SAR Protocol) version 1.0. SAR is a binary container format designed for high-performance data serialization, streaming, and secure long-term storage providing a data replication protocol. SAR prioritizes minimal metadata overhead, deterministic parsing, and native support for modern cryptographic and compression primitives. It utilizes a bitmask-driven architectural design where the presence of metadata fields is strictly governed by global flags. This revision formalizes the distinction between compression and patching registries, enabling a dual-stage pipeline where a binary patch is itself compressed, while maintaining features such as `NO_INDEX` mode, the Padding & Empty-Area Protocol, and Key Management Systems (KMS).

## 1. Introduction
The Streamable Archive and Replication (SAR) Protocol is a binary container protocol for the representation, transport, replication, and archival of Application Data Objects. It is designed for deterministic parsing, low metadata overhead, forward-only processing, and optional random access while remaining independent of the underlying transport protocol or storage medium.

SAR defines a single binary representation that can operate in multiple modes. An implementation MAY produce a self-contained archive containing a trailing Central Dictionary (CD) to enable efficient random access, or operate in a sequential streaming mode optimized for ordered processing, resumable sessions, and constrained receiver state. Both modes utilize the same binary encoding rules and Application Data Object representation.

The protocol utilizes a global flag architecture in which archive-wide capabilities determine the presence and interpretation of subsequent metadata fields. This allows the binary overhead to remain proportional to the features actually utilized by the encoder while preserving deterministic parsing without heuristic interpretation.

SAR provides an interoperable binary representation for Application Data Objects that is usable across archival storage, replication, and Stateful Streaming Mode, allowing applications to process the same logical object consistently regardless of the underlying transport protocol or storage medium. This document specifies that representation together with the rules governing its serialization, transmission, reconstruction, validation, and interoperability. Implementations MAY construct and consume this representation transiently during transport or replication, or persist it directly for archival storage, without requiring Application Data Objects to be persistently represented in SAR.

## 2. Conventions and Definitions

### 2.1 Terminology
The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document are to be interpreted as described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals, as shown here.

Unless explicitly stated otherwise, all terms defined in this document apply equally to archival processing and Stateful Streaming Mode.

The following terminology is used throughout this specification:

* **Application Data Object:** A logically complete unit of application-defined information consisting of payload data together with any associated metadata required for identification, reconstruction, authentication, integrity verification, transformation, or interpretation.

* **Archive:** A SAR object intended for persistent storage consisting of a Global Header followed by a Data Area and, unless `NO_INDEX` is set, a Central Dictionary and Footer.

* **Entry:** A single logical Application Data Object represented by one LFH and its associated payload, or by a group of LFHs and payload fragments when `FILE_FRAGMENTATION` is enabled.

* **Full Logical Entry Path:** The canonical SAR path identifying an Entry. It consists of the LFH `Name String` when the LFH `Path String` is absent or empty, and otherwise consists of the LFH `Path String`, followed by `/`, followed by the LFH `Name String`.

* **Extraction Root:** The directory or filesystem scope selected by the caller or host application before materialization begins and beneath which selected Entries are materialized.

* **Payload:** The application-defined data represented by an Entry after all required transformations and reconstruction steps have completed successfully.

* **Fragment:** A portion of an Entry transmitted or stored independently for subsequent reassembly.

* **Partition:** One physical member of a partitioned SAR archive belonging to a common Partition Set.

* **Sender:** The implementation producing or transmitting SAR objects.

* **Receiver:** The implementation parsing, validating, reconstructing, or consuming SAR objects.

* **Stateful Streaming Mode:** The streaming mode defined in Section 18 in which Application Data Objects are exchanged over an established session while maintaining stream state.

* **Transformation:** Any operation altering the encoded representation of an Entry without changing its logical payload, including compression, encryption, delta encoding, fragmentation, or Forward Error Correction (FEC).

* **Structural Determinism:** The property that the presence, ordering, and interpretation of encoded fields are derived exclusively from the Global Flags and Entry Mode bits defined by this specification without heuristic interpretation.

Unless explicitly specified otherwise, references to "objects" within this document refer to Application Data Objects.

### 2.2 Data Representation
* **Endianness**: All multi-byte integers MUST be stored in **Little-Endian** byte order.

* **Strings**: All strings SHALL be encoded in **UTF-8**. Strings are preceded by a length field of variable size depending on the context: 2 bytes for LFH Name/Path, 4 bytes for Global Metadata (TLV), and 4 bytes for KMS Payloads. They MUST NOT be null-terminated.

* **Padding**: SAR headers are "packed." Implementations MUST NOT insert padding bytes between fields unless explicitly defined by the Padding & Empty-Area Protocol (Section 15).

## 3. Motivation and Scope

Existing Internet and storage ecosystems typically treat archival storage, content replication, synchronization, and real-time transport as separate problem domains.

As a result, end-to-end workflows frequently combine multiple independent formats and protocols. A deployment may, for example, utilize one format for archival storage, a transport protocol for network transfer, separate mechanisms for encryption, integrity verification, digital signatures, delta synchronization, deduplication, and recovery.

While each technology is effective within its intended domain, combining multiple representations often results in duplicated metadata, repeated validation logic, format translation, and independent security models.

SAR was designed to reduce this fragmentation.

Rather than defining separate representations for archival storage, replication, and stateful streaming, SAR defines a common representation for Application Data Objects that can be utilized consistently across those environments.

The same Application Data Object MAY therefore be:

* stored as an archive;
* transmitted using Stateful Streaming Mode;
* replicated incrementally;
* fragmented and subsequently reassembled;
* protected using cryptographic authentication, encryption, or Forward Error Correction (FEC); and
* retained for long-term storage.

The design goal is not to replace specialized transport protocols, archive formats, or storage systems in their primary deployment environments. Instead, SAR defines a common object representation and processing model that can operate consistently across transport and storage boundaries while remaining independent of the underlying transport protocol or storage medium.

### Interoperability

A primary design goal of SAR is predictable interoperability between independently developed implementations.

Many existing formats and protocols permit optional algorithms, feature subsets, or extension mechanisms that may reduce practical interoperability between otherwise conforming implementations.

SAR addresses this by defining explicit compliance profiles together with mandatory-to-implement behaviors and algorithm subsets.

Implementations conforming to the same compliance profile can therefore process the same Application Data Objects without requiring prior capability negotiation while remaining extensible through optional features and future extensions.

### Security and Integrity

SAR defines a unified security and integrity model that applies consistently to both archival storage and Stateful Streaming Mode.

Cryptographic authentication, encryption, integrity verification, digital signatures, fragmentation, Forward Error Correction (FEC), delta encoding, and Content-Defined Chunking (CDC) are represented within the same Application Data Object rather than delegated exclusively to transport-specific or storage-specific mechanisms.

This allows implementations to preserve security properties, validation behavior, and reconstruction semantics when Application Data Objects move between storage systems, removable media, and network transports.

### Intended Deployment

SAR is intended for environments in which storage, replication, and transport requirements overlap, including backup and recovery systems, firmware and software distribution, content replication, long-term archival storage, air-gapped data transfer, industrial telemetry, media distribution, and stateful data synchronization.

The protocol is designed to scale from resource-constrained implementations supporting a minimal interoperability profile to full-featured implementations supporting archival, replication, recovery, and Stateful Streaming Mode while maintaining profile-defined interoperability guarantees.


## 4. Archive Structure
A SAR archive consists of four sequential sections, unless the `NO_INDEX` flag is set:

1. **Global Header**: Entry point defining archive capabilities.
2. **Data Area**: Sequential File Headers and Payloads (including potential Empty Areas and Delta Patches).
3. **Central Dictionary (CD)**: Global metadata and random-access index.
4. **Footer**: Fixed 8-byte pointer to the Central Dictionary.

The CD is a post-hoc index and does not define the canonical structure of the archive, which is always derived from the Data Area. If the `NO_INDEX` flag is set, the CD and Footer are omitted.

## 5. Global Header & Extension
The Global Header is located at absolute offset **0**. It defines the archive's identity and the structural rules for all subsequent entries.

### 5.1 Header Layout
The archive begins with a fixed-size segment followed by the Global Flags field and any conditional Global Header extensions. For SAR version 1.0, the Global Flags field is exactly 4 bytes.

| Offset | Field | Size | Description |
| --- | --- | --- | --- |
| 0 | **Magic Number** | 4B | `0x53 0x41 0x52 0x21` ("SAR!"). |
| 4 | **Version** | 1B | Format version (e.g. 0x01). |
| 5 | **Reserved** | 1B | MUST be 0x0. |
| 6 | **Flags Size** | 2B | Size of Global Flags; MUST equal `4` for SAR version 1.0. |
| 8 | **Global Flags** | 4B | Little-endian bitmask defining the binary layout. |
|...| **Partition Descriptor** | 96B | Optional; presence governed by `PARTITIONED_ARCHIVE` (Bit 3). |
|...| **KMS Extension** | Var | Optional; Presence governed by Bit 10. |

### 5.2 Global Flags Registry

The SAR version 1.0 Global Flags field MUST be a 32-bit little-endian bitmask encoded in exactly 4 bytes. The `Flags Size` field MUST equal `4`.

All unassigned bits in the 32-bit Global Flags field are reserved. A SAR version 1.0 writer MUST set all reserved Global Flags bits to zero.

A decoder encountering a `Flags Size` value other than `4` in a SAR version 1.0 Global Header MUST reject the archive with `SAR_ERR_INVALID_LENGTH`.

A decoder encountering a nonzero reserved Global Flags bit MUST reject the archive with `SAR_ERR_RESERVED_VALUE`.

Certain combinations of assigned flags are invalid and MUST be rejected as defined by Section 13.4.


**Category A: Structural & Indexing**
| Bit | Name | Description |
| --- | --- | --- |
| 0 | `64BIT_SIZE` | All size/offset fields are 8 bytes (otherwise 4). |
| 1 | `NO_INDEX` | Sequential-only mode. No CD or Footer exists. |
| 2 | `OPT_PRESENT` | CD contains a variable-length Metadata Section (TLV). |
| 3 | `PARTITIONED_ARCHIVE` | The archive spans multiple physical files. |
| 4 | `FILE_FRAGMENTATION` | Individual files may be split into non-contiguous fragments. |
| 5 | `CDC_SUPPORT` | Enables support for Content-Defined Chunking. |
| 6 - 7 | `RESERVED` | MUST be zero. |

**Category B: Payload Transformations**
| Bit | Name | Description |
| --- | --- | --- |
| 8 | `COMPRESSED` | Compression fields present in Local File Headers. |
| 9 | `HAS_DELTA` | Incremental Mode. Entries may contain binary patches. |
| 10 | `ENCRYPTED` | Encryption fields present in Local File Headers. |
| 11 - 15 | `RESERVED` | MUST be zero. |

**Category C: Integrity & Security**
| Bit | Name | Description |
| --- | --- | --- |
| 16 | `HAS_GLOBAL_CRC32` | CD contains a 32-bit global archive CRC. |
| 17 | `PER_FILE_CRC` | Local File Headers include file-level CRC32. |
| 18 | `SIGNED` | CD includes signature TLV. **Requires Bit 2.** |
| 19 | `HAS_GLOBAL_EC` | CD contains Error Correction (EC) parity data. |
| 20 | `SELECTIVE_FEC` | LFH may contain Error Correction (EC) parity data.|
| 21 - 23 | `RESERVED` | MUST be zero. |

**Category D: Filesystem Metadata**
| Bit | Name | Description |
| --- | --- | --- |
| 24 | `HAS_PATH` | Local File Headers include relative directory paths. |
| 25 | `HAS_PERMS` | Local File Headers include 16-bit POSIX permissions. |
| 26 | `HAS_SYMLINKS` | Support for symbolic link entries. |
| 27 | `EXT_UID_GID` | Headers include 32-bit UID/GID fields (16-bit each). |
| 28 | `EXT_TIME` | Headers include 3x 64-bit Unix timestamps (m/a/ctime). |
| 29 | `DEDUPLICATION` | Headers include content-based hashes (e.g., BLAKE3). |
| 30 | `SPARSE_FILES` | Support for sparse filesystem holes. |
| 31 | `RESERVED` | MUST be zero. |

### 5.3 Global Header Extensions
If the `ENCRYPTED` flag (Bit 10) is set, the KMS Extension MUST be present, otherwise omitted. It provides the necessary parameters to derive or unwrap the keys used in the Data Area.

If the `PARTITIONED_ARCHIVE` glag (Bit 3) is set, the Partition Descriptor MUST be present, otherwise ommited.

#### 5.3.1 KMS_DATA Structure
| Field | Size | Description |
| --- | --- | --- |
| **KMS Mode ID** | 1B | Defines the method (See 3.3.2). |
| **KMS Payload Length**| 4B | Size of the following payload in bytes. |
| **KMS Payload** | Var | Mode-specific parameters (See 3.3.3). |

**Rules for KMS Parsing:**
* **Total Size**: The total size of the Global Header with KMS is `13 + Flags Size + KMS Payload Length` bytes.
* **Data Area Start**: If Bit 10 is set, the first LFH begins immediately at the end of the KMS Payload.
* **Omission**: If Bit 10 is NOT set, the KMS Extension is omitted entirely; the Data Area begins right after the Global Flags.
* **Integrity**: Unknown Mode IDs MUST trigger `SAR_ERR_RESERVED_VALUE`.

#### 5.3.2 KMS Mode Registry
| ID        | Name                        | Description                       |
| --- | --- | --- |
| 0x01      | **PBKDF2**                  | Password-based key derivation.    |
| 0x02      | **ARGON2**                  | Memory-hard password derivation.  |
| 0x03      | **ASYMMETRIC_WRAP**         | Encrypted master key wrapping.    |
| 0x04      | **TLS_EXPORTER**            | TLS exporter derivation.          |
| 0xF0-0xFF | **CUSTOM (RESERVED RANGE)** | Implementation-defined KMS modes. |

### 5.3.2.1 CUSTOM KMS Semantics
* Values in range `0xF0-0xFF` are reserved for **implementation-defined KMS behavior**.
* A CUSTOM KMS mode MUST be explicitly enabled by the application layer.
* Two SAR implementations MAY assign different semantics to the same CUSTOM ID.
* Interoperability is NOT guaranteed for CUSTOM modes unless out-of-band agreement exists.
* If a CUSTOM mode is encountered and not supported, implementations MUST return `SAR_ERR_UNSUPPORTED`.

#### 5.3.3 Mode-Specific Payload Structures
**Mode 0x01 - PBKDF2**
| Field | Size | Description |
| --- | --- | --- |
| PRF Algo ID | 1B | 0x01: HMAC-SHA256, 0x02: HMAC-SHA512, 0x03: HMAC-SHA3-256. |
| Salt Length | 1B | MUST be ≥ 16. |
| Salt | Var | Random binary salt. |
| Iterations | 4B | MUST be ≥ 100,000. |
| Derived Key Length | 2B | MUST match encryption algorithm requirements. |

**Mode 0x02 - ARGON2**
| Field | Size | Description |
| --- | --- | --- |
| Argon2 Variant | 1B | 0x01: Argon2d, 0x02: Argon2i, 0x03: Argon2id. |
| Version | 1B | 0x13 RECOMMENDED. |
| Salt Length | 1B | MUST be ≥ 16. |
| Salt | Var | Random binary salt. |
| Memory Cost (KiB) | 4B | MUST be ≥ 64 MiB. |
| Time Cost | 4B | Number of passes. |
| Parallelism | 2B | Number of threads. |
| Derived Key Length | 2B | MUST match algorithm requirements. |

**Mode 0x03 - ASYMMETRIC_WRAP**
| Field | Size | Description |
| --- | --- | --- |
| Wrap Algo ID | 1B | 0x01: RSA-OAEP-2048, 0x02: RSA-OAEP-4096, 0x03: X25519, 0x04: ML-KEM-768, 0x05: ML-KEM-1024. |
| Recipient Count | 1B | MUST be ≥ 1. |
| *Recipient Loop* | - | Repeat per Recipient: |
| - Recipient ID Len | 1B | Length of ID. |
| - Recipient ID | Var | Key ID / Fingerprint. |
| - Wrapped Key Len | 2B | Length of wrapped blob. |
| - Wrapped Key Blob | Var | The Wrapped Master Key. |

**Mode 0x04 - TLS_EXPORTER**
| Field                      | Size | Description                                                                |
|----------------------------|------|----------------------------------------------------------------------------|
| Exporter Label Length      | 1B   | Length of Exporter Label in bytes.                                         |
| Exporter Label             | Var  | ASCII-encoded TLS exporter label.                                          |
| Context Version            | 1B   | MUST be `0x01` for this profile.                                           |
| AEAD Algo ID               | 1B   | SAR AEAD algorithm ID.                                                     |
| KDF Algo ID                | 1B   | Optional post-export KDF; `0x00` means direct TLS exporter output profile. `0x01 - 0xFF`: RESERVED; nonzero values MUST return `SAR_ERR_RESERVED_VALUE`. |
| Global Header Hash Algo ID | 1B   | Hash algorithm used for Global Header binding.                             |
| Salt Length                | 1B   | MAY be `0`; length of non-secret salt/context bytes.                       |
| Salt                       | Var  | Non-secret salt/context bytes.                                             |
| Derived Key Length         | 2B   | MUST match the selected AEAD algorithm requirements.                       |
| Flags                      | 2B   | Profile flags; reserved bits MUST be zero.                                 |



#### 5.3.4 The Partition Descriptor
The Partition Descriptor Extension is present only when Global Flag Bit 3 (`PARTITIONED_ARCHIVE`) is set.

The Partition Descriptor provides archive-set identification, partition ordering, and partition integrity metadata required to reconstruct a partitioned SAR archive independently of file naming conventions, storage backends, or transport mechanisms.

All partitions belonging to the same partitioned archive MUST contain a valid Partition Descriptor and MUST share the same Partition Set UUID.

The Partition Descriptor SHALL be 96 bytes and SHALL be encoded as follows:

| Order | Field                   | Size | Description                                                                      |
| ----- | ----------------------- | ---- | -------------------------------------------------------------------------------- |
| 0     | Partition Set UUID      | 16B  | Identifies the logical archive set.                                              |
| 1     | Partition Index         | 4B   | Zero-based partition index.                                                      |
| 2     | Total Partitions        | 4B   | Total number of partitions belonging to the archive set.                         |
| 3     | Previous Partition Hash | 32B  | Hash of the previous partition's Data Area. Partition 0 MUST contain all zeroes. |
| 4     | Partition Hash          | 32B  | Hash of this partition's Data Area.                                              |
| 5     | Reserved                | 8B   | Reserved for future use. Encoders MUST set all bytes to `0x00`.                  |

If `PARTITIONED_ARCHIVE` is set, each partition MUST contain a fixed-size Partition Descriptor immediately after Global Flags.

All partitions belonging to the same archive set MUST carry the same Partition Set UUID.

Each partition MUST declare its zero-based Partition Index and Total Partitions value.

All partitions except the final partition MUST set `NO_INDEX` and MUST NOT contain a Central Dictionary or Footer.

The final partition MUST contain a Central Dictionary and Footer if `NO_INDEX` is unset.

If `NO_INDEX` is set, no partition SHALL contain a Central Dictionary or Footer.

Filesystem-based partition sets SHOULD use deterministic names of the form:

`[Archive_Name].sar.[3-byte zero-padded index]`

Implementations MUST NOT rely on filenames as the sole mechanism for partition discovery, validation, or reconstruction.

Partition discovery, verification, incomplete-set handling, degraded recovery behavior, and integrity validation requirements are defined in Section 19.4.


### 5.4 Version Compatibility

* Parsers MUST reject archives with a higher major version than supported.
* Minor or compatible revisions MAY be accepted only if their Global Header and Global Flags semantics are backward-compatible with the supported version.
* The Global Header Version defines the LFH structure, the permitted `Flags Size`, the Global Flags assignments, and the associated structural and transformation semantics.
* For SAR version 1.0, `Flags Size` MUST equal `4`. A wider or shorter Global Flags field is not a valid SAR version 1.0 extension.
* A future SAR format version MAY define a different `Flags Size` or additional Global Flags assignments. Such definitions do not alter the SAR version 1.0 requirements in this section.
* The Central Dictionary Version defines only the CD layout and MAY evolve independently.

## 6. Local File Header (LFH)
Each entry in the Data Area begins with an LFH. The sequence of fields is deterministic based on the Global Flags.

### 6.1 LFH Field Sequence
The sequence of fields is strictly deterministic and the presence of LFH fields is governed by Global Flags. The Entry Mode bits solely determine whether the data in the affected fields is utilized or ignored such that those fields are treated as reserved / zero (see 4.2). Parsers MUST evaluate the Global Flags in the following order to calculate the current header's size.

| Order | Field | Size | Condition |
| --- | --- | --- | --- |
| 1 | Header Size | 4B | Always |
| 2 | Entry Mode | 2B | Always |
| 3 | Stream ID | 2B | Always |
| 4 | Sequence No | 2B | Always |
| 5 | Uncompressed Size | 4/8B | Always |
| 6 | Payload Size | 4/8B | Always |
| 7 | Comp Algo ID | 1B | `COMPRESSED` (Bit 8) |
| 8 | Patch Algo ID | 1B | `HAS_DELTA` (Bit 9) |
| 9 | Encr Algo ID | 1B | `ENCRYPTED` (Bit 10) |
| 10 | CDC Algo ID | 1B | `CDC_SUPPORT` (Bit 5) |
| 11 | FEC Algo ID | 1B | `SELECTIVE_FEC` (Bit 20) |
| 12 | Fragment ID | 4B | `FILE_FRAGMENTATION` (Bit 4) |
| 13 | Fragment Index | 4B | `FILE_FRAGMENTATION` (Bit 4) |
| 14 | Fragment Descriptor | 12B | `FILE_FRAGMENTATION` (Bit 4) |
| 15 | IV / Nonce | 24B | `ENCRYPTED` (Bit 10) |
| 16 | Delta Base Hash | 32B | `HAS_DELTA` (Bit 9) |
| 17 | File CRC32 | 4B | `PER_FILE_CRC` (Bit 17) |
| 18 | Content Hash | 32B | `DEDUPLICATION` (Bit 29) |
| 19 | UID / GID | 4B | `EXT_UID_GID` (Bit 27) |
| 20 | Timestamps | 24B | `EXT_TIME` (Bit 28) |
| 21 | Permissions | 2B | `HAS_PERMS` (Bit 25) |
| 22 | Name Length | 2B | Always |
| 23 | Path Length | 2B | `HAS_PATH` (Bit 24) |
| 24 | Sparse Map Size | 4B | `SPARSE_FILES` (Bit 30) |
| 25 | FEC Size | 3B | `SELECTIVE_FEC` (Bit 20) |
| 26 | Name String | Var | Always |
| 27 | Path String | Var | `HAS_PATH` (Bit 24) |
| 28 | Sparse Map | Var | `SPARSE_FILES` (Bit 30) |
| 29 | FEC Value | Var | `SELECTIVE_FEC` (Bit 20) |
| 30 | Payload Data | Var | Size = Payload Size |

The physical layout and byte alignment of the LFH are strictly dependent on the evaluation of the Condition column. Fields whose conditions evaluate to false **MUST NOT** be present in the header byte sequence.

The presence and value semantics of fields are governed by the following rules:

* **Fixed-Sized Conditional Fields:** If a governing condition is met, all corresponding fixed-size fields **MUST** be present in the header. These fields **MAY** contain a value of zero, which **MAY** denote a feature-specific state rather than field absence.
* **Variable-Sized Fields:** The presence of a variable-sized field is jointly governed by its condition and its corresponding size or length field.
  * A variable-sized field **MUST** be present if and only if its structural condition is met **AND** its corresponding size field contains a non-zero value.
  * If its corresponding size field evaluates to zero, the variable-sized field **MUST NOT** be present in the header, regardless of whether its governing Global Flag is set.

NOTE:
For example, if `Name Length` is zero, `Name String` is omitted from the byte sequence; however, because the condition for `Name Length` is "Always", the length field itself is still present.

#### 6.1.1 Header Size and Payload Position Semantics
`Header Size` SHALL define the declared size, in bytes, of the LFH from the first byte of the `Header Size` field through the final byte before Payload Data.

Payload Data SHALL begin at:

LFH_Start + Header Size

The next LFH, if present, SHALL begin at:

LFH_Start + Header Size + Payload Size

Encoders MUST set Header Size such that it exactly equals the LFH size obtained from the Global Flags and declared LFH length fields.

Decoders MAY use `Header Size` directly to locate Payload Data and the next LFH.

Decoders MAY instead compute the LFH size from the Global Flags and all declared LFH length fields present in the LFH.

If an implementation computes the LFH size and the computed value does not match `Header Size`, it MUST return `SAR_ERR_INVALID_LENGTH`.

Implementations MUST validate that `Header Size` is not smaller than the fixed LFH prefix size implied by the Global Flags.

If `Header Size` is smaller than the fixed LFH prefix size implied by the Global Flags, implementations MUST return `SAR_ERR_INVALID_LENGTH`.

If `Header Size` causes the header or payload to exceed archive bounds, implementations MUST return `SAR_ERR_BOUNDS` or `SAR_ERR_TRUNCATED` as appropriate.

#### 6.1.2 Size Semantics and Transform Finality

The `Uncompressed Size` field MUST represent the size, in bytes, of the fully reconstructed logical file after all applicable transformations have been reversed during decoding.

For encoding, transformations SHALL be applied in the following order where applicable:

1. Patch application (`HAS_DELTA`)
2. Compression (`IS_COMPRESSED`)
3. Encryption (`IS_ENCRYPTED`)

For decoding, transformations SHALL be reversed in the following order:

1. Decryption (`IS_ENCRYPTED`)
2. Decompression (`IS_COMPRESSED`)
3. Patch application (`HAS_DELTA`)

The `Uncompressed Size` field therefore represents the size of the logical file after completion of the canonical decode pipeline and not the size of any intermediate representation.

Implementations MUST validate that the reconstructed output length exactly matches `Uncompressed Size`.

Any mismatch MUST result in the most specific applicable error code corresponding to the stage at which reconstruction failed.

#### 6.1.3 Fragment Descriptor Semantics
When `FILE_FRAGMENTATION` is enabled, the **Fragment Descriptor** field SHALL be present in the LFH. All LFHs sharing the same Fragment ID belong to the same logical object.

Multiple LFHs belonging to one Fragment ID do not create separate Full Logical Entry Path occurrences.

The descriptor is structured as:

| Subfield | Size | Description |
| --- | --- | --- |
| Absolute Offset | 8B   | Byte offset within logical reassembled stream |
| Fragment Size   | 4B   | Size of this fragment in bytes             |

**Rationale**

* Replaces ambiguous "offset-only" interpretation.
* Enables **stream reassembly without external state assumptions**.
* Eliminates dependency on LFH ordering for reconstruction correctness.

**Constraints**

* Fragment Size is independent of Payload Size and refers to the logical fragment size after completion of the canonical decode pipeline.
* Absolute Offset SHALL refer to the byte offset within the fully reconstructed logical object after completion of the canonical decode pipeline.
* Fragment Size SHALL refer to the fragment length within the fully reconstructed logical object after completion of the canonical decode pipeline.
* Overlapping descriptors MUST trigger `SAR_ERR_INVALID_MAP`.

Within one logical archive, or within one active Stateful Streaming stream context, all LFHs sharing one Fragment ID represent one Entry. Individual fragments MUST NOT be treated as separate Entries for Full Logical Entry Path ordering or final-state determination.

Fragment Index 0 establishes the Name String, Path String, and canonical Entry-order position of the fragmented Entry.

If a later fragment contains a Name String or Path String, the value MUST match the corresponding Fragment Index 0 value. A mismatch MUST return `SAR_ERR_METADATA_CONFLICT` or another more specific applicable error.

A fragmented Entry participates in final-state determination only after successful complete reconstruction or degraded reconstruction permitted by `LOSS_TOLERANT`.

An incomplete fragment set that cannot produce either result MUST NOT supersede an earlier complete Entry at the same Full Logical Entry Path.
This rule does not permit an implementation to report successful complete processing when the incomplete fragment set requires an error or incomplete result under the fragmentation, recovery, or `LOSS_TOLERANT` requirements.

These rules do not permit duplicate Fragment Index values, overlapping Fragment Descriptors, or any other invalid fragment map.

#### 6.1.4 Forward Error Correction (FEC)

When `SELECTIVE_FEC` global flag is set, the corresponding LFH fields MUST be present according to the following specifications. The corresponding LFH fields MUST follow the specifications set for the `RECOVERY` block in the Central Dictionary (Section 9.2) such that the fields MUST match the specifications therein as follows.

| LFH Field   | TLV Field                             |
| ----------- | ------------------------------------- |
| FEC Algo ID | TLV Type ID as defined in Section 9.2 |
| FEC Size    | TLV Size                              |
| FEC Value   | TLV Value                             |

When `SELECTIVE_FEC` is set, the FEC Algo ID field SHALL identify the FEC algorithm using the same RECOVERY algorithm identifiers defined in Section 9.2.

The value `0x00` means that FEC is disabled for this LFH. If FEC Algo ID is `0x00`, FEC Size MUST be zero and FEC Value MUST be omitted.

Values `0x11` through `0x16` have the meanings defined for RECOVERY TLVs in Section 9.2. The value `0x10` is RESERVED and MUST NOT be used. All other values are RESERVED unless assigned by a future revision of this specification.

FEC Size SHALL be encoded as a 24-bit unsigned little-endian integer. The maximum encodable FEC Value length is 16,777,215 bytes.

If FEC Algo ID is non-zero, FEC Size MUST be greater than zero and FEC Value MUST contain the algorithm-specific configuration, metadata, and parity data defined for the selected RECOVERY algorithm in Section 9.2.

Implementations that support `SELECTIVE_FEC` MUST support Reed-Solomon (`0x11`) and XOR (`0x14`).

Implementations that encounter a supported FEC feature using an unsupported FEC algorithm ID MUST return `SAR_ERR_UNSUPPORTED`.

Implementations encountering a reserved FEC algorithm ID MUST return `SAR_ERR_RESERVED_VALUE`.

##### FEC Implementation

Selective FEC protects the recoverable encoded payload bytes of the corresponding LFH.

If the LFH is not AEAD-encrypted, the recoverable encoded payload bytes are the entire Payload Data field exactly as stored in the SAR byte stream.

When `SELECTIVE_FEC` and AEAD encryption are both active for an LFH, FEC parity SHALL be computed over the AEAD ciphertext only and SHALL NOT include the AEAD authentication tag.

For AEAD-encrypted LFHs, `Payload Data` is parsed as:

```text
Payload Data = Ciphertext || Tag
```

Selective FEC protects only:

```text
Ciphertext = Payload Data[0 : Payload Size - TagLen]
```

The authentication tag is not FEC-protected. After FEC repair, the decoder MUST verify the AEAD authentication tag using the AAD rules in Section 13.2.1 before releasing plaintext or applying decompression, patching, or state-mutating operations.

If an AEAD authentication tag is missing or corrupted, Selective FEC cannot recover that tag; the decoder MUST return `SAR_ERR_AUTH_FAILED` after unsuccessful tag verification.

SAR FEC recovery is erasure recovery unless an algorithm-specific section explicitly defines correction of unknown errors. The decoder MUST know which source symbols, blocks, bytes, fragments, or encoded byte ranges are missing or unusable before invoking FEC recovery.

If missing or unusable symbol positions cannot be determined, the decoder MUST return `SAR_ERR_RECOVERY_UNAVAILABLE` or `SAR_ERR_EC_FAILED`, whichever is more specific to the failure stage.

For LFH Selective FEC, missing or unusable positions SHALL be derived from the unavailable or corrupted encoded Payload Data byte ranges within the corresponding LFH. For fragmented entries, missing or unusable positions MAY additionally be derived from Fragment Index and Fragment Descriptor metadata when the FEC algorithm operates over fragment-aligned symbols or blocks.

#### 6.1.5 Name and Path Semantics

The LFH `Path String` identifies the directory containing the Entry. The LFH `Name String` identifies the final path component.

The `Name String`:

* MUST NOT be empty;
* MUST NOT contain `/`;
* MUST NOT contain `\`; and
* MUST NOT contain U+0000.

The `Path String`, when present and non-empty:

* MUST use `/` as the path-component separator;
* MUST NOT begin or end with `/`;
* MUST NOT contain `\` or U+0000;
* MUST NOT contain an empty component;
* MUST NOT contain a `.` component; and
* MUST NOT contain a `..` component.

The Full Logical Entry Path is the `Name String` when the `Path String` is absent or empty. Otherwise, it is the `Path String`, followed by `/`, followed by the `Name String`.

Backslash is not valid in an LFH Name String or Path String. Applications archiving filesystems that permit backslash in filename components SHOULD reject such source names or apply an explicit reversible application-layer mapping before encoding. SAR defines no backslash escape mechanism.

Implementations MUST NOT normalize, rewrite, escape, substitute, or otherwise alter a nonconforming Name String or Path String to make it conforming.

A writer receiving a nonconforming Name String or Path String MUST return `SAR_ERR_INVALID_INPUT` and MUST NOT emit the affected Entry.

A reader encountering a nonconforming encoded Name String or Path String MUST return `SAR_ERR_MALFORMED`.

Multiple complete Entries MAY have the same Full Logical Entry Path. Repeated Full Logical Entry Paths are valid.

For archives, canonical Entry order is physical LFH order in the Data Area. The first LFH follows the Global Header and its extensions. Each subsequent LFH begins at the next-LFH position determined under Section 6.1.1 from the preceding LFH and its Payload Data. Central Dictionary order MUST NOT alter canonical Entry order.

For a complete valid partitioned archive, partition Data Areas are ordered by ascending Partition Index. Missing, duplicate, inconsistent, or otherwise invalid partitions remain governed by Section 19.

For Stateful Streaming Mode, canonical Entry order is the order in which valid Entry LFHs occur in the reliable byte stream within the active session context. Sequence No validation MUST NOT reorder LFHs or redefine that order.

A fragmented Entry occupies the canonical Entry-order position established by Fragment Index 0.

The same final-state rules apply to indexed archives, `NO_INDEX` archives, partitioned archives, and Stateful Streaming Mode.

Complete Entries are applied in canonical Entry order.

A complete Entry replaces an earlier Entry at the same Full Logical Entry Path.

If a non-directory Entry replaces a directory, all earlier descendants of that directory are removed from the final logical state.

If a directory Entry replaces another Entry, existing compatible descendants remain.

If a later Entry requires an ancestor that is absent or is a non-directory, that ancestor becomes an implicit directory and the earlier non-directory object is removed from the final logical state.

An implicit directory has no explicit SAR metadata unless a directory Entry supplies that metadata.

The last complete directory Entry at a Full Logical Entry Path determines the final explicit metadata of that directory.

The final logical state is the state remaining after all complete Entries have been applied in canonical Entry order.

Implementations MAY process Entries internally in another order, provided that the observable successful result is identical to canonical sequential application.

After a complete Entry, or a degraded reconstructed Entry permitted by
`LOSS_TOLERANT`, establishes another occurrence of an existing Full
Logical Entry Path, an implementation MAY report `SAR_WARN_DUPLICATE`.

Individual fragments belonging to one fragmented Entry MUST NOT
independently cause `SAR_WARN_DUPLICATE` to be reported.

Reporting this warning MUST NOT alter archive or stream validity, Entry
processing, canonical Entry order, final logical state, output, or
operation success.


### 6.2 The Entry Mode Flags
While Global Flags determine which LFH entries must be present and what the archive itself may contain (or will never contain), the Entry Mode specifies whether the corresponding fields in the LFH is applicable or not.

If the corresponding Entry Mode Flag is unset, the corresponding LFH field MUST still be physically present in the bitstream (as dictated by Global Flags) but its content MUST be ignored by the parser.

The 16-bit Entry Mode is split into two functional bytes. The lower byte defines the object's physical state, while the upper byte defines the stream's logical operation. It MUST be structured as follows:

| Bit(s) | Name | Description |
| --- | --- | --- |
| 0 | `IS_SYMLINK` | Payload contains a target path string. |
| 1 | `IS_DIRECTORY` | Marks entry as a directory; Payload Data MUST be 0. |
| 2 | `IS_ENCRYPTED` | If unset, Payload MUST be interpreted as PLAINTEXT. |
| 3 | `IS_COMPRESSED` | If unset, Payload MUST be interpreted as STORE. |
| 4 | `HIDDEN_ATTR` | Sets the filesystem "hidden" attribute. |
| 5 | `IS_FRAGMENT` | Set if this LFH describes a piece of a larger file, not a whole file. |
| 6 | `LAST_FRAGMENT` | Set if this is the final piece required to complete the logical file. |
| 7 | `LOSS_TOLERANT` | Entry or fragment group permits degraded reconstruction if fragments are missing or unrecoverable. |
| 8-11 | `OP_CODE` | Command Enumeration (Context dependent on Bit 13). |
| 12 | RESERVED | Reserved. |
| 13 | `SESSION_CONTROL` | Context Toggle: If set, Op-Codes are session-level. |
| 14 | `ATOMIC_WRITE` | Verify CRC before unlinking/committing old data. |
| 15 | `FORCE_SYNC` | Bypasses local conflict resolution. |

#### 6.2.1 Global vs Entry Flag Consistency Rules
The Global Flags define **capability and structural schema**, while Entry Mode flags define **per-entry usage** of those capabilities.

The following rules are mandatory:

1. **Capability Constraint**

   * `IS_COMPRESSED` MUST NOT be set unless `COMPRESSED` (Global Bit 8) is set.
   * `IS_ENCRYPTED` MUST NOT be set unless `ENCRYPTED` (Global Bit 10) is set.

   Violations MUST result in `SAR_ERR_FLAG_CONFLICT`.

2. **Field Presence vs Usage**

   * If a Global Flag enables a feature, all associated LFH fields MUST be physically present in every entry.
   * Entry Mode flags determine whether those fields are **semantically active** or treated as inert.

3. **Compression Override**

   * If `COMPRESSED` is set globally but `IS_COMPRESSED` is unset:

     * `Comp Algo ID` MUST be present.
     * The effective compression algorithm SHALL be treated as STORE (0x00), regardless of the value present in the Comp Algo ID field.

4. **Encryption Override**

   * If `ENCRYPTED` is set globally but `IS_ENCRYPTED` is unset:

     * Encryption fields MUST be present.
     * The effective encryption algorithm SHALL be treated as PLAINTEXT (0x00), regardless of the value present in the Encr Algo ID field.
    
5. **Fragmentation Behavior**
   * `IS_FRAGMENT` MUST NOT be set unless `FILE_FRAGMENTATION` is set globally.
   * `LAST_FRAGMENT` MUST NOT be set unless `IS_FRAGMENT` is also set.
      
    Violation MUST result in SAR_ERR_FLAG_CONFLICT.

#### 6.2.2 LOSS_TOLERANT behavior
If LOSS_TOLERANT is set, implementations MAY continue reconstruction
despite fragment loss, recovery failure, or unavailable recovery data,
provided a meaningful degraded logical object can still be produced.

Successful degraded reconstruction MUST return SAR_WARN_INCOMPLETE.

LOSS_TOLERANT MUST NOT override failures arising from decryption,
authentication, signature verification, decompression, patch
application, structural corruption, or any other condition that
prevents deterministic reconstruction of the logical object.

Such failures MUST be reported using the corresponding error code even when
LOSS_TOLERANT is set.

### 6.3 OP_CODE Registry
These commands are processed ONLY if Stateful Streaming Mode is active (see 16.1).

#### 6.3.1 Filesystem Mode (`SESSION_CONTROL` == 0)
The Filesystem Mode deals with standard replication and archival operations. It is utilized if `SESSION_CONTROL` Entry Mode is unset.

| Value | Name | Payload / Logical Behavior |
| --- | --- | --- |
| `0x0` | DATA_WRITE | Standard creation/update or Delta Patch. |
| `0x1` | DELETE | Unlinks the target path. Payload Size MUST be 0. |
| `0x2` | RENAME | Name/Path String = Old Path; Payload = New Path String. |
| `0x3` | META_PROBE | Validates Base Hash presence; No write occurs. |
| `0x4` | SYNC_BARRIER | Signals transaction end; forces hardware disk flush. |
| `0x5 - 0xF` | RESERVED | Reserved for future filesystem opcodes. |

#### 6.3.2 Session Mode (`SESSION_CONTROL` == 1)
The Session Mode deals with management of the stateful streaming connection (Section 18). It is utilized if `SESSION_CONTROL` Entry Mode is set.

| Value | Name | Payload / Logical Behavior |
| --- | --- | --- |
| `0x0` | `SESSION_INIT` | Handshake or session reinitialization. |
| `0x1` | `SESSION_CLOSE` | Gracefully terminates the session associated with the Stream ID. |
| `0x2` | `SESSION_RESUME` | Validates the Session UUID after a transport drop. |
| `0x3` | `SESSION_HEARTBEAT` | Keep-alive; validates sequence and Stream ID continuity. Payload Size MUST be 0. |
| `0x4` | `SESSION_STATUS` | Status notification. Payload MUST contain a SAR Stream Status Frame. |
| `0x5` | `SESSION_ACK` | Acknowledgement notification. Payload MUST contain a SAR Stream Acknowledgement Frame. |
| `0x6` | `SESSION_METADATA` | Updates application metadata associated with the active stream. |
| `0x7` | `SESSION_CAPABILITIES` | Reports supported session-control capabilities. |
| `0x8-0xF` | RESERVED | Reserved for future session-control opcodes. |

## 7. Central Dictionary (CD)
The CD is the primary management structure for random access and archive-wide metadata. It is OMITTED if `NO_INDEX` (Bit 1) is set.

| Field | Size | Condition | Description |
| --- | --- | --- | --- |
| Version | 1B | Always | Central Dictionary format version (independent of archive version |
| Reserved | 7B | Always | Padding block reserved for future use |
| File Count | 4/8B | Always | Supports 64-bit unsigned integer if `64BIT_SIZE` set (otherwise 32-bits) |
| Partition ID | 2B | `PARTITIONED_ARCHIVE` | The ID of the current physical file (0-indexed). |
| Total Partitions | 2B | `PARTITIONED_ARCHIVE` | Total number of physical files in this SAR set. |
| Global CRC | 4B | `HAS_GLOBAL_CRC32` | CRC32 of all payloads combined. |
| MetaSize | 4B | `OPT_PRESENT` | Total size of the Metadata Section in bytes. |
| Metadata | Var | `OPT_PRESENT` | TLV Blocks (See Section 7). |
| Offsets | Var | Always | Array of `File Count` * 4/8B absolute pointers. |

## 8. Registries
### 8.1 Compression Algorithms (`SAR_L_COMP`)
* `0x00`: **STORE** (Raw data; no compression)
* `0x01`: **DEFLATE** (Standard RFC 1951)
* `0x02`: **ZSTD** (Zstandard - Recommended for balance)
* `0x03`: **LZ4** (High-speed compression)
* `0x04`: **BROTLI** (Text optimized)
* `0x05`: **XZ** (LZMA2 - Maximum ratio)
* `0xF0-0xFF`: **CUSTOM** (Implementation-defined range)

#### 8.1.1 CUSTOM Compression Semantics
* Values in `0xF0-0xFF` define user or vendor-specific compression algorithms.
* Implementations MUST NOT assume cross-compatibility.
* If unsupported, MUST return `SAR_ERR_UNSUPPORTED`.
* CUSTOM compression MAY require external metadata negotiated outside SAR.

### 8.2 Encryption Algorithms (`SAR_L_ENCR`)
* `0x00`: **PLAINTEXT** (No transformation; skip IV parsing/apply identity)
* `0x01`: **AES256_GCM** (Authenticated Encryption)
* `0x02`: **CHACHA20** (RFC 8439 ChaCha20 Stream Cipher)
* `0x03`: **AES256_CBC** (Block Cipher - Legacy Support)
* `0x04`: **XCHACHA20_POLY** (XChaCha20-Poly1305 - Recommended AEAD)
* `0x05`: **CHACHA20_POLY1305** (ChaCha20-Poly1305 AEAD)
* `0x20-0x3F`: RESERVED for post-quantum encryption and KEM algorithms.
* `0x40-0x5F`: RESERVED for experimental algorithms.
* `0x60-0xEF`: RESERVED for future standardization.
* `0xF0-0xFF`: **CUSTOM** (Implementation-defined range)

Any algorithm identifier not explicitly assigned in this section is RESERVED.

Implementations encountering a reserved value MUST return SAR_ERR_RESERVED_VALUE.

If decryption or authentication later fails, implementations MUST return SAR_ERR_DECRYPT_FAILED or SAR_ERR_AUTH_FAILED as appropriate.

#### 8.2.1 CUSTOM Encryption Semantics
* Values in `0xF0-0xFF` define user-defined encryption schemes.
* MUST require matching external specification between encoder and decoder.
* If the required CUSTOM encryption specification is unavailable or unsupported, implementations MUST return SAR_ERR_UNSUPPORTED. 
* CUSTOM encryption MUST NOT be assumed secure or standardized.

#### 8.2.2 IV / Nonce Field Semantics

The LFH IV / Nonce field SHALL always occupy 24 bytes when the
`ENCRYPTED` flag is set.

Encryption algorithms SHALL interpret the field as follows:

| Algorithm | IV / Nonce Length |
|-----------|-------------|
| PLAINTEXT  | 0 bytes  |
| AES256_GCM | 12 bytes |
| CHACHA20 | 12 bytes |
| AES256_CBC | 16 bytes |
| XCHACHA20_POLY | 24 bytes |
| CHACHA20_POLY1305 | 12 bytes |

For algorithms requiring fewer than 24 bytes, the IV or nonce SHALL
occupy the first N bytes of the field.

All remaining bytes SHALL be set to 0x00 by the encoder.

Unused bytes are RESERVED.

For PLAINTEXT, all 24 bytes of the IV / Nonce field SHALL be set to 0x00 by the encoder and SHALL be ignored by the decoder.

Decoders MUST ignore unused bytes when constructing the IV or nonce.

Implementations operating in strict validation mode MAY verify that
all reserved bytes are set to 0x00.

If strict validation mode is enabled, non-zero unused bytes MUST
result in `SAR_ERR_MALFORMED`.

For AEAD algorithms, encoders MUST NOT reuse the same nonce with the same encryption key. Within a single archive, every AEAD-encrypted LFH using the same derived encryption key MUST use a unique nonce.

If an encoder detects that a nonce would be reused with the same encryption key, it MUST abort archive creation and return `SAR_ERR_NONCE_REUSE`.

Reuse of a key/nonce pair compromises confidentiality and integrity.

Nonce uniqueness requirements apply to encoders.

Decoders are not required to detect nonce reuse and MUST NOT assume that repeated nonce values alone constitute a protocol violation, as different entries MAY utilize different encryption keys.

NOTE:
Encryption algorithms providing confidentiality only (e.g.
AES256_CBC and CHACHA20) do not provide authenticity or integrity
protection.

Implementations MAY successfully decrypt data using an incorrect key,
resulting in corrupted or otherwise invalid output.

Applications requiring reliable key validation and tamper detection
SHOULD use an authenticated encryption algorithm such as `AES256_GCM`,
`CHACHA20_POLY1305`, or `XCHACHA20_POLY1305`.

#### 8.2.3 Default Encryption Algorithm Selection

When an implementation creates an encrypted SAR archive and no specific encryption algorithm has been explicitly selected by the invoking application, configuration, profile, or user, the implementation MUST select an AEAD-capable encryption algorithm.

Implementations SHOULD prefer `AES256_GCM` as the default AEAD algorithm.

Implementations MAY provide configuration mechanisms allowing an alternate AEAD-capable algorithm to be selected as the implementation default.

Non-AEAD algorithms (e.g., `AES256_CBC`, `CHACHA20`) MUST NOT be selected as defaults for newly created encrypted archives unless explicitly requested by the invoking application, configuration, profile, or user.

### 8.3 OS Origin Mapping (`OS_ORIGIN`)
* `0x00`: **UNKNOWN**
* `0x01`: **LINUX**
* `0x02`: **WINDOWS**
* `0x03`: **MACOS**
* `0x04`: **BSD_UNIX**
* `0x05`: **IOT_EMBEDDED**
* `0xFF`: **OTHER**

### 8.4 Patching Algorithms (`SAR_L_PATCH`)

Patching algorithms are used only when `HAS_DELTA` (Bit 9) is set. The algorithm identifier is stored in the LFH **Patch Algo ID** field.

| ID          | Name          | Description                                       |
| ----------- | ------------- | ------------------------------------------------- |
| `0x00`      | `STORE_PATCH` | Self-contained full-target patch payload.         |
| `0x01`      | `VCDIFF`      | RFC 3284 VCDIFF delta stream.                     |
| `0x02`      | `BSDIFF`      | SAR BSDIFF v1 delta payload.                      |
| `0x03`      | `ZSTD_PATCH`  | Zstandard dictionary-based patch profile.         |
| `0x04-0xEF` | Reserved      | Reserved for future SAR-defined patch algorithms. |
| `0xF0-0xFF` | `CUSTOM`      | Implementation-defined range.                     |

Implementations that support delta patch processing (`HAS_DELTA`) MUST implement:

* `STORE_PATCH` (`0x00`);
* `VCDIFF` (`0x01`).

Support for `BSDIFF` (`0x02`) and `ZSTD_PATCH` (`0x03`) is OPTIONAL.

Implementations encountering an assigned but unsupported patch algorithm identifier MUST return `SAR_ERR_UNSUPPORTED`.

Implementations encountering a reserved patch algorithm identifier MUST return `SAR_ERR_RESERVED_VALUE`.

#### Patch Transformation Domain

Patch algorithms operate on decoded patch payload bytes.

Patch application occurs after FEC repair, AEAD authentication/decryption, decompression, and fragment reassembly, and before sparse reconstruction.

The delta transformation order is:

```text
Decode:
  FEC repair, if applicable
  Fragment reassembly, if applicable
  AEAD authentication and decryption, if applicable
  Decompression, if applicable
  Patch application
  Sparse reconstruction, if applicable
```

Encoding uses the reverse order:

```text
Encode:
  Target logical data
  Patch payload generation
  Compression, if applicable
  Encryption, if applicable
  Fragmentation/FEC, if applicable
```

Patch algorithms MUST operate on logical patch payload bytes after SAR decompression. Patch algorithms MUST NOT define or apply an additional hidden compression layer unless explicitly defined by the patch algorithm profile.

For `STORE_PATCH`, `VCDIFF`, and `BSDIFF`, compression is handled exclusively by the SAR compression layer.

Therefore:

* `STORE_PATCH` payloads MAY be SAR-compressed.
* `VCDIFF` payloads MAY be SAR-compressed.
* `BSDIFF` payloads MAY be SAR-compressed.
* Encoders implementing `BSDIFF` MUST produce SAR BSDIFF v1 payloads using the `SARBSD01` format without internal bzip2 compression.
* `ZSTD_PATCH` is reserved for a future dictionary-based patch profile and MUST define its own dictionary semantics before use.

#### Base and Reconstruction Input Requirements

Patch algorithms are classified by whether they require external reconstruction input.

`STORE_PATCH` (`0x00`) is self-contained. It does not require a base object, dictionary, or external reconstruction input.

`VCDIFF` (`0x01`) and `BSDIFF` (`0x02`) are base-object patch algorithms. Patch application requires the bytes of the identified base object.

`ZSTD_PATCH` (`0x03`) is a dictionary-based patch algorithm. Patch application requires the identified dictionary bytes and any additional reconstruction input defined by the `ZSTD_PATCH` profile.

For `STORE_PATCH`, the `Delta Base Hash` field SHOULD be set to all zero bytes to indicate that no base object is required.

For any patch algorithm that requires a base object, dictionary, or other external reconstruction input, an all-zero `Delta Base Hash` MUST be treated as missing reconstruction input and MUST result in `SAR_ERR_BASE_MISSING` if patch application is attempted.

Implementations MUST NOT interpret an all-zero `Delta Base Hash` as "skip delta" for `VCDIFF`, `BSDIFF`, `ZSTD_PATCH`, or custom patch algorithms.

The `Delta Base Hash` field identifies the expected reconstruction input. Unless a hash algorithm is explicitly specified by this specification or by a negotiated extension, implementations MUST treat the field as an opaque identity value and MUST NOT guess the hash algorithm.

Implementations MUST NOT perform automatic filesystem lookup, network access, external CAS lookup, or provider access during patch application unless such behavior is explicitly requested by an application layer and bounded by implementation policy.

#### Patch Output Size

For all patch algorithms, the reconstructed output size MUST equal the LFH `Uncompressed Size` field after patch application.

If the reconstructed output size differs from LFH `Uncompressed Size`, the decoder MUST return `SAR_ERR_PATCH_FAILED`.

Implementations MUST enforce configured `ResourceLimits` before allocating the reconstructed target buffer.

#### Patch Error Behavior

Malformed patch payloads MUST return `SAR_ERR_PATCH_FAILED`.

Missing required base objects, dictionaries, or reconstruction inputs MUST return `SAR_ERR_BASE_MISSING`.

Resource-limit violations MUST return `SAR_ERR_LIMIT_EXCEEDED`.

`LOSS_TOLERANT` MUST NOT suppress patch failures.

Implementations MUST NOT release finalized reconstructed output after patch failure.

#### VCDIFF Secondary Compression

SAR `VCDIFF` uses RFC 3284 as a patch payload format. SAR compression wraps the VCDIFF payload externally through the normal SAR compression layer.

Implementations MUST NOT rely on VCDIFF-internal secondary compression for SAR `VCDIFF`.

VCDIFF streams requiring unsupported secondary compressors MUST return `SAR_ERR_UNSUPPORTED`.

#### 8.4.1 CUSTOM Patch Semantics

For custom patch algorithms, the following rules apply:

* `CUSTOM` patch semantics MAY operate on arbitrary binary diff models.
* `CUSTOM` patch semantics MAY be used without explicit application-layer negotiation in controlled or closed environments where both encoder and decoder implementations are known to support the same custom algorithm. In interoperable or heterogeneous environments, explicit negotiation is RECOMMENDED.
* Unknown or unnegotiated custom patch algorithms MUST fail with `SAR_ERR_UNSUPPORTED`.
* Custom patch algorithms that require external reconstruction input MUST follow the base/reconstruction-input rules in Section 8.4.

#### 8.4.2 STORE_PATCH (`0x00`)

`STORE_PATCH` is the baseline delta patch algorithm.

For `STORE_PATCH`, the patch payload is the complete target logical byte sequence.

No copy instructions, base reads, external dictionaries, or external base-object lookups are performed by the `STORE_PATCH` algorithm.

When applying `STORE_PATCH`, the decoder SHALL treat the decoded patch payload as the reconstructed target logical data.

`STORE_PATCH` does not require base object bytes to be available for patch application.

If `Delta Base Hash` is nonzero, implementations MAY expose it as metadata or use it for diagnostics, but `STORE_PATCH` application MUST NOT fail solely because the base object is unavailable.

For `STORE_PATCH`, a malformed payload is one whose decoded payload length does not exactly equal LFH `Uncompressed Size`, or whose decoded payload cannot be obtained because FEC repair, decryption, decompression, or an earlier decoding stage failed.

#### 8.4.3 VCDIFF (`0x01`)

`VCDIFF` (`0x01`) uses the RFC 3284 VCDIFF delta format.

The decoded patch payload is an RFC 3284 VCDIFF delta stream.

`VCDIFF` is a base-object patch algorithm. Patch application requires explicit base object bytes.

If patch application is attempted without base object bytes, the decoder MUST return `SAR_ERR_BASE_MISSING`.

If the LFH `Delta Base Hash` field is all zero bytes, the decoder MUST return `SAR_ERR_BASE_MISSING`.

The decoder MUST reject malformed VCDIFF headers, windows, variable-length integers (varints), instructions, copy ranges, or truncated streams with `SAR_ERR_PATCH_FAILED`.

The decoder MUST enforce configured `ResourceLimits` for:

* VCDIFF input size;
* VCDIFF window count;
* VCDIFF instruction count;
* decoded target window size;
* reconstructed target size;
* total patch working set.

Resource-limit violations MUST return `SAR_ERR_LIMIT_EXCEEDED`.

#### 8.4.4 BSDIFF (`0x02`)

`BSDIFF` (`0x02`) uses the SAR BSDIFF v1 profile.

SAR BSDIFF v1 is a SAR-native binary patch format derived from the classic bsdiff control/diff/extra model, but it does not embed bzip2 compression inside the patch payload.

Compression of BSDIFF patch payloads is handled exclusively by the SAR compression layer.

Encoders implementing `BSDIFF` MUST produce SAR BSDIFF v1 payloads using the `SARBSD01` magic and uncompressed Control, Diff, and Extra blocks.

Decoders MAY support legacy classic BSDIFF40 payloads for interoperability. If a decoder encounters the `BSDIFF40` magic value, it MAY interpret the payload as a classic BSDIFF40 patch, including bzip2-compressed Control, Diff, and Extra blocks, and process it accordingly.

Support for decoding classic BSDIFF40 is OPTIONAL. Implementations that do not support BSDIFF40 decoding MUST treat such payloads as malformed and return `SAR_ERR_PATCH_FAILED`.

#### SAR BSDIFF v1 Payload Format

The decoded BSDIFF patch payload has the following structure:

```text
Header || Control_Block || Diff_Block || Extra_Block
```

This structure is observed after all earlier SAR decoding transforms have completed.

##### Header

The header is 32 bytes:

| Field                  | Size    | Description                                             |
| ---------------------- | ------- | ------------------------------------------------------- |
| `Magic`                | 8 bytes | ASCII string `SARBSD01`.                                |
| `Control_Block_Length` | 8 bytes | Length in bytes of the uncompressed control block.      |
| `Diff_Block_Length`    | 8 bytes | Length in bytes of the uncompressed diff block.         |
| `New_File_Size`        | 8 bytes | Size in bytes of the reconstructed target logical data. |

`Control_Block_Length`, `Diff_Block_Length`, and `New_File_Size` use the SAR BSDIFF signed 64-bit integer encoding.

For SAR BSDIFF v1, these values MUST be non-negative.

Negative block lengths or target sizes MUST be rejected with `SAR_ERR_PATCH_FAILED`.

`New_File_Size` MUST equal the LFH `Uncompressed Size` after patch application. If it does not match, the decoder MUST return `SAR_ERR_PATCH_FAILED`.

##### Blocks

After the header, the decoded patch payload contains:

```text
Control_Block: uncompressed control triples
Diff_Block:    uncompressed diff bytes
Extra_Block:   uncompressed extra bytes
```

`Extra_Block` begins immediately after:

```text
32 + Control_Block_Length + Diff_Block_Length
```

The end of `Extra_Block` is the end of the decoded BSDIFF patch payload.

All offset and length calculations MUST use checked arithmetic.

##### Control Triples

The Control Block contains a sequence of triples:

```text
(diff_len, extra_len, seek_adjust)
```

Each field uses the SAR BSDIFF signed 64-bit integer encoding.

The Control Block length MUST be a multiple of 24 bytes.

Patch application proceeds as follows:

1. Read `diff_len` bytes from the Diff Block.
2. Add each diff byte to the corresponding byte from the current base position, modulo 256, and append the result to the output.
3. Advance the base position by `diff_len`.
4. Read `extra_len` bytes from the Extra Block and append them to the output.
5. Advance the base position by `seek_adjust`.
6. Repeat until exactly `New_File_Size` output bytes have been produced.

The decoder MUST reject with `SAR_ERR_PATCH_FAILED`:

* invalid magic (except for optionally supported `BSDIFF40`);
* negative `Control_Block_Length`;
* negative `Diff_Block_Length`;
* negative `New_File_Size`;
* Control Block length not divisible by 24;
* malformed or truncated control triples;
* negative `diff_len`;
* negative `extra_len`;
* control triples that cause output to exceed `New_File_Size`;
* reads beyond the Diff Block;
* reads beyond the Extra Block;
* trailing unused Diff Block bytes;
* trailing unused Extra Block bytes;
* base reads before byte offset `0`;
* output size not exactly equal to `New_File_Size`.

If a diff operation references base bytes beyond the end of the base object, missing base bytes SHALL be treated as `0x00`.

##### BSDIFF Resource Limits

Implementations MUST enforce configured `ResourceLimits` for:

* decoded BSDIFF patch payload size;
* Control Block size;
* Diff Block size;
* Extra Block size;
* control triple count;
* base size;
* reconstructed target size;
* total patch working set.

Resource-limit violations MUST return `SAR_ERR_LIMIT_EXCEEDED`.

Missing base data MUST return `SAR_ERR_BASE_MISSING`.

#### 8.4.5 ZSTD_PATCH (`0x03`)

`ZSTD_PATCH` (`0x03`) is reserved for a SAR-defined Zstandard dictionary-based patch profile.

The exact dictionary identity, dictionary source, dictionary verification method, payload format, and reconstruction semantics are not defined in this version of the specification.

Implementations encountering `ZSTD_PATCH` without support for a negotiated or future standardized profile MUST return `SAR_ERR_UNSUPPORTED`.

#### 8.4.6 SAR BSDIFF Signed Integer Encoding

SAR BSDIFF v1 uses the classic bsdiff signed 64-bit integer encoding.

This encoding is not two's complement. Instead, it uses a sign-magnitude representation with a 63-bit magnitude and a separate sign bit.

An integer is encoded in 8 bytes:

* Bytes 0 through 6 contain the lower 56 bits of the magnitude in little-endian order.
* Byte 7 contains:

  * Bits 0-6: the upper 7 bits of the magnitude.
  * Bit 7: the sign bit.

Decoding:

1. Interpret bits 0-6 of byte 7 together with all bits of bytes 0 through 6 as a 63-bit unsigned magnitude in little-endian order.
2. If bit 7 of byte 7 is set, the decoded value is negative.
3. Otherwise, the decoded value is non-negative.

This differs from two's complement encoding: negative values are not formed by bit inversion and addition, but by applying a sign to the decoded magnitude.

Decoders MUST reject integer values that cannot be represented safely in the implementation's checked arithmetic.

Fields that represent lengths or sizes MUST be non-negative.

### 8.5 CDC Algorithms (`SAR_L_CDC`)
Used only when `CDC_SUPPORT` (Bit 5) is set. This ID is stored in the **CDC Algo ID** field of the LFH.

* `0x00`: **LITERAL_MODE** (Deduplication disabled for this entry; Payload is literal data).
* `0x01`: **RABIN** (Rabin Fingerprinting based CDC).
* `0x02`: **FASTCDC** (Gear-hash based high-speed CDC).
* `0x03`: **BUZHASH** (Buzhash based CDC).
* `0x04 - 0xEF`: **RESERVED**
* `0xF0-0xFF`: **CUSTOM** (Implementation-defined range).

Implementations that support CDC processing (`CDC_SUPPORT`) MUST implement:

* `FASTCDC` (`0x02`)

Support for `RABIN` (`0x01`) and `BUZHASH` (`0x03`) is OPTIONAL.

Implementations encountering an assigned but unsupported CDC algorithm identifier MUST return `SAR_ERR_UNSUPPORTED`.

Implementations encountering a reserved CDC algorithm identifier MUST return `SAR_ERR_RESERVED_VALUE`.

A reader MUST distinguish CDC metadata parsing from CDC boundary regeneration. The stored CDC metadata present in the archive is authoritative for parsing and interpretation. A writer's choice of FASTCDC parameters or profile MUST NOT by itself cause a parsing failure so long as the stored CDC metadata is well-formed and self-consistent.

## 9. Metadata TLV Section (Global Scope)
If `OPT_PRESENT` (Bit 2) is set, metadata is stored in Type-Length-Value blocks. Each block MUST follow this structure:

* **Type ID**: 1 byte.
* **Length**: 4 bytes (Little-Endian, declaring the size in Bytes of the following value field).
* **TLV Value**: Variable length data.

If the TLV block does not end on an 8-byte boundary, zero padding bytes MUST be appended after the TLV Value field. Padding SHALL be calculated relative to the beginning of the TLV block, starting at the Type ID field. The total TLV block size, including Type ID, Length, Value, and padding, SHALL be a multiple of 8 bytes. Padding bytes MUST be set to 0x00 and MUST NOT be included in the TLV Length field.

### 9.1 Metadata Type Registry (`SAR_G_META`)
The Type IDs MUST be set such that the IDs in the range of 0x00 - 0x0F are utilized for a specific type each and the IDs in the range of 0x10 - 0xFF are utilized such that the most-significant nibble (4 bits) determines the TLV type and the least-significant nibble SHOULD enumerate between differing implementations, algorithms or specific sub-types.

The authoritative registry for the Type ID SHOULD solely be this specification and MUST be set as follows.

| ID | Name | Type | Description |
| --- | --- | --- | --- |
| 0x00 | RESERVED | Reserved. |
| 0x01 | `CTIME` | uint64_t | Archive creation timestamp. |
| 0x02 | `COMMENT` | string | UTF-8 Archive comment. |
| 0x03 | `AUTHOR` | string | UTF-8 Creator/Author name. |
| 0x04 | `OS_ORIGIN` | uint8_t | Environment mapping (See section 6.3). |
| 0x05 - 0x0F | RESERVED | Reserved for future use. |
| 0x10 - 0x1F | `RECOVERY` | blob | Erasure Coding (EC) parity data. |
| 0x20 - 0x2F | `SIGNATURE` | blob | Digital Signature data. |
| 0x30 - 0x3F | `DATA_HASH` | struct | Hash of Data Area (REQUIRED if SIGNED). |
| 0x40 | `CDC_MAP` | blob | CDC Map / Catalog. |
| 0x41 | `CDC_EXT_PROVIDER` | string | UTF-8 URI for an external CDC provider. |
| 0x42 - 0x4E | RESERVED | Reserved for future CDC metadata assignments. |
| 0x4F | `CDC_CUSTOM` | blob | Implementation-defined CDC metadata extension. |
| 0x50 - 0xFF | RESERVED | Reserved for future use. |

When a string is carried within a TLV Value field, the TLV Length field defines the string length. No additional string-length field SHALL be present.

### 9.2 Data Recovery (ID 0x10 - 0x1F)

The `RECOVERY` block adds error correction parity data over a byte-exact protected portion of the archive. The Central Dictionary and Footer are not part of the protected byte sequence.

For a RECOVERY TLV, the protected byte sequence SHALL be the exact byte sequence beginning at the first byte of Global Flags and ending at the final byte before the Central Dictionary.

This range includes Global Flags, any Global Header extensions, all Local File Headers, all Payload Data, Empty Areas, and all explicitly encoded padding bytes before the Central Dictionary.

This range excludes Magic Number, Version, Reserved, Flags Size, the Central Dictionary, and the Footer.

The algorithm used SHALL be identified by the least-significant nibble (4 bits) of the one-octet TLV Type field:

* `0x10`: Reserved.
* `0x11`: Reed-Solomon.
* `0x12`: LDPC.
* `0x13`: RaptorQ.
* `0x14`: XOR.
* `0x15`: RLC/RLNC.
* `0x16`: Polar Codes.

All other values in the range `0x10` through `0x1F` are RESERVED for future assignment.

Implementations that support RECOVERY TLV processing MUST implement both Reed-Solomon (`0x11`) and XOR (`0x14`).

Support for LDPC (`0x12`), RaptorQ (`0x13`), RLNC (`0x15`), and Polar Codes (`0x16`) is OPTIONAL.

Implementations encountering an assigned but unsupported RECOVERY algorithm identifier MUST return `SAR_ERR_UNSUPPORTED`.

Implementations encountering a reserved RECOVERY algorithm identifier MUST return `SAR_ERR_RESERVED_VALUE`.

The TLV Length field MUST declare the size in bytes of the TLV Value field, excluding any TLV padding bytes. The TLV Length value `0xFFFFFFFF` is RESERVED and MUST NOT be used. Implementations encountering a TLV Length value of `0xFFFFFFFF` MUST return `SAR_ERR_RESERVED_VALUE`.

The TLV Value field MUST contain:

1. The algorithm-specific configuration.
2. Any algorithm-required metadata.
3. The parity data.

The parity data SHALL immediately follow the final metadata field.

SAR RECOVERY is erasure recovery unless an algorithm-specific section explicitly defines correction of unknown errors. The decoder MUST know which source symbols, blocks, bytes, fragments, or protected byte ranges are missing or unusable before invoking RECOVERY decoding.

If missing or unusable positions cannot be determined, the decoder MUST return `SAR_ERR_RECOVERY_UNAVAILABLE` or `SAR_ERR_EC_FAILED`, whichever is more specific to the failure stage.

For each FEC algorithm, the maximum protected payload size of a single FEC Value or RECOVERY TLV is limited by the smallest of:

1. the algorithm-specific source-size limit;
2. the maximum representable Original Protected Length;
3. the maximum representable group, block, stripe, symbol, or code-block count fields;
4. the maximum encodable FEC Value or TLV Value length; and
5. implementation-defined memory, storage, and processing limits.

The maximum protected payload size applies to one FEC scope only. Larger objects MAY be protected by dividing the object into multiple independent FEC scopes.
.


#### 9.2.1 Algorithm-Specific Configuration
The algorithm-specific configuration consists of exactly two bytes. Byte 0 and Byte 1 SHALL be interpreted according to the selected RECOVERY algorithm as defined in the following subsections. Unless explicitly stated otherwise, the two configuration bytes SHALL be interpreted independently and are not subject to endianness conversion.

##### Reed-Solomon (0x11)
Let k be the number of data symbols and n be the total number of symbols.

Byte 0 SHALL encode k.
Byte 1 SHALL encode n - k.

k SHALL be in the range 1-255.
n - k SHALL be in the range 1-255.
n SHALL equal k + (n - k).

Implementations encountering a value of 0x00 for either k or (n - k) MUST return SAR_ERR_RESERVED_VALUE.

Implementations MUST reject Reed-Solomon RECOVERY blocks whose decoded n value exceeds implementation-supported limits.
Such failures MUST return SAR_ERR_LIMIT_EXCEEDED.

Implementations MAY reject Reed-Solomon RECOVERY blocks that exceed implementation-defined memory, storage, or processing limits.

Implementations SHALL perform all size calculations in a manner that prevents integer overflow. If overflow is detected, the implementation MUST return SAR_ERR_OVERFLOW.

A Minimal Interoperable Profile supporting Reed-Solomon MUST support values of k in the range 1 through 255 inclusive and values of (n - k) in the range 1 through 32 inclusive.
This profile supports Reed-Solomon configurations with up to 32 parity symbols.

Example: For k=10, n=15
* Byte 0: 0x0A
* Byte 1: 0x05

###### Reed-Solomon Implementation

SAR Reed-Solomon FEC SHALL use systematic Reed-Solomon over GF(2^8).

The finite field SHALL use primitive polynomial 0x11D and primitive
element 0x02.

Each Reed-Solomon symbol SHALL be a byte vector of Symbol Size bytes.
Reed-Solomon coding SHALL be applied independently at each byte offset
within the Symbol Size across k data symbols to produce n-k parity
symbols.

The Reed-Solomon code SHALL be systematic: the first k symbols are the
source data symbols unchanged, followed by n-k parity symbols.

The Reed-Solomon generator SHALL be constructed using a Vandermonde
matrix over GF(2^8). For parity symbol r and data symbol c, where r and
c are zero-based, the coefficient SHALL be:

    α^((r + 1) × c)

where α is the primitive element 0x02.

The protected byte sequence SHALL be divided into groups of k data
symbols. Each data symbol SHALL contain Symbol Size bytes. The final
group SHALL be right-padded with zero bytes until it contains exactly k
complete data symbols.

The parity data SHALL contain only the n-k parity symbols for each group.
Parity symbols SHALL be encoded in ascending parity-symbol order. Groups
SHALL be encoded in ascending group order.

The decoder SHALL use Original Protected Length to remove padding after
successful recovery.

###### Reed-Solomon Encoding

For Reed-Solomon, the TLV Value or FEC Value SHALL be encoded as:

```text
Config[2] ||
Symbol Size[4] ||
Original Protected Length[8] ||
Group Count[4] ||
Parity Data[variable]
```

where:

`Config[2]` is Byte 0 = k and Byte 1 = n-k.

`Symbol Size` is a uint32 little-endian value in bytes. Symbol Size MUST be greater than zero.

`Original Protected Length` is a uint64 little-endian value in bytes.

`Group Count` is a uint32 little-endian value.

`Parity Data` contains:

```text
Group Count × (n-k) × Symbol Size
```

bytes.

Implementations MUST verify that:

```text
Group Count == ceil(Original Protected Length / (k × Symbol Size))
```

and that:

```text
Parity Data Length == Group Count × (n-k) × Symbol Size
```

Any mismatch MUST return `SAR_ERR_INVALID_LENGTH`.

The maximum protected payload size of a single Reed-Solomon FEC Value or RECOVERY TLV is additionally limited by:

```text
Group Count × k × Symbol Size
```

A Minimal Interoperable Profile supporting Reed-Solomon MUST support Symbol Size values of 1024 bytes, 4096 bytes, and 16384 bytes.


##### LDPC (0x12)

| Order | Value            |
| ----- | ---------------- |
| 0     | Code rate        |
| 1     | Block size index |

Byte 0 encodes the code rate. The code rate MUST be encoded with the most-significant nibble representing the rate numerator and the least-significant nibble representing the rate denominator.

Numerator SHALL be greater than or equal to 1.

Denominator SHALL be greater than or equal to 2.

Numerator SHALL be less than Denominator.

Implementations encountering an invalid code-rate encoding MUST return `SAR_ERR_MALFORMED`.

Byte 1 encodes the block size index.

Block size index values are defined by the registry below.

| Index | Block Size |
| ----- | ---------- |
| 0x00  | 64 B       |
| 0x01  | 128 B      |
| 0x02  | 256 B      |
| 0x03  | 512 B      |
| 0x04  | 1 KB       |
| 0x05  | 2 KB       |
| 0x06  | 4 KB       |
| 0x07  | 8 KB       |
| 0x08  | 16 KB      |
| 0x09  | 32 KB      |
| 0x0A  | 64 KB      |
| 0x0B  | 128 KB     |
| 0x0C  | 256 KB     |

Any index values not explicitly assigned in this registry are RESERVED.

Implementations encountering a reserved value MUST return `SAR_ERR_RESERVED_VALUE`.

The number of parity blocks per LDPC group SHALL be derived from the code rate as follows:

```text
Parity Blocks = ceil(Data Blocks × (Denominator - Numerator) / Numerator)
```

Implementations MUST reject LDPC RECOVERY blocks whose decoded block size, data block count, parity block count, or matrix size exceeds implementation-supported limits. Such failures MUST return `SAR_ERR_LIMIT_EXCEEDED`.

Implementations MAY reject LDPC RECOVERY blocks that exceed implementation-defined memory, storage, or processing limits.

Implementations SHALL perform all size calculations in a manner that prevents integer overflow. If overflow is detected, the implementation MUST return `SAR_ERR_OVERFLOW`.

A Minimal Interoperable Profile supporting LDPC MUST support code rates 1/2, 2/3, and 4/5, block size indices from `0x02` through `0x0A` inclusive, and Data Block Count values from 1 through 255 inclusive.

Examples:

* Byte 0: `0x12` means rate 1/2.
* Byte 0: `0x23` means rate 2/3.
* Byte 0: `0x45` means rate 4/5.
* Byte 1: `0x06` means block size 4 KB.

###### LDPC Implementation

SAR LDPC FEC SHALL be a systematic binary erasure code operating on byte-vector blocks.

Each LDPC data block and parity block SHALL contain exactly Block Size bytes.

LDPC parity generation SHALL operate over `GF(2)`, where addition is bitwise XOR.

The protected byte sequence SHALL be divided into LDPC groups. Each LDPC group contains Data Block Count data blocks. The final data block SHALL be right-padded with zero bytes to Block Size. The final LDPC group SHALL be right-padded with zero-valued data blocks until it contains exactly Data Block Count data blocks.

For each LDPC group, the encoder SHALL generate Parity Block Count parity blocks.

The LDPC parity-check structure SHALL be derived deterministically from the following values:

```text
Matrix Seed
Data Block Count
Parity Block Count
LDPC Column Weight
```

`Matrix Seed` is a uint64 little-endian value encoded in the LDPC metadata.

`LDPC Column Weight` is a uint8 value encoded in the LDPC metadata and SHALL be in the range 2 through 8 inclusive.

The parity matrix SHALL be generated using the SAR deterministic matrix generator defined below.

For each data block index `d`, where `d` is zero-based in `[0, Data Block Count)`, the encoder SHALL select `LDPC Column Weight` distinct parity block indices. Each selected parity block SHALL XOR the corresponding data block into its parity value.

The selected parity block indices for data block `d` SHALL be generated by repeated evaluation of the following deterministic function:

```text
candidate_j = SAR_PRNG64(Matrix Seed, d, attempt) mod Parity Block Count
```

where `attempt` starts at zero and increments by one until `LDPC Column Weight` distinct parity block indices have been selected.

`SAR_PRNG64(seed, d, attempt)` SHALL be SplitMix64 over the uint64 value:

```text
seed XOR (uint64(d) << 32) XOR uint64(attempt)
```

using the following SplitMix64 procedure:

```text
x = input + 0x9E3779B97F4A7C15
x = (x XOR (x >> 30)) * 0xBF58476D1CE4E5B9
x = (x XOR (x >> 27)) * 0x94D049BB133111EB
x = x XOR (x >> 31)
```

All arithmetic SHALL be performed modulo 2^64.

Parity blocks SHALL initially be all zero bytes. For every selected parity block index, the corresponding data block SHALL be XORed into that parity block.

Parity data SHALL contain only the generated parity blocks. Parity blocks SHALL be encoded in ascending parity block order. LDPC groups SHALL be encoded in ascending group order.

Decoders SHALL reconstruct missing data blocks by solving the binary linear erasure system defined by the deterministic parity matrix and the available data and parity blocks. Decoders MAY use peeling, Gaussian elimination over `GF(2)`, or any equivalent method that produces the same recovered data.

If the missing blocks cannot be uniquely recovered from the available equations, the decoder MUST return `SAR_ERR_EC_FAILED`.

The decoder SHALL use Original Protected Length to remove padding after successful recovery.

###### LDPC Encoding

For LDPC, the TLV Value or FEC Value SHALL be encoded as:

```text
Config[2] ||
Block Size[4] ||
Original Protected Length[8] ||
Data Block Count[4] ||
Group Count[4] ||
Matrix Seed[8] ||
LDPC Column Weight[1] ||
Parity Data[variable]
```

where:

`Config[2]` is Byte 0 = Code Rate and Byte 1 = Block Size Index.

`Block Size` is a uint32 little-endian value in bytes and MUST match the selected Block Size Index. Block Size MUST be greater than zero.

`Original Protected Length` is a uint64 little-endian value in bytes.

`Data Block Count` is a uint32 little-endian value. Data Block Count MUST be greater than zero.

`Group Count` is a uint32 little-endian value.

`Matrix Seed` is a uint64 little-endian value used by the deterministic LDPC matrix generator.

`LDPC Column Weight` is a uint8 value in the range 2 through 8 inclusive.

`Parity Data` contains:

```text
Group Count × Parity Block Count × Block Size
```

bytes.

Implementations MUST verify that:

```text
Group Count == ceil(Original Protected Length / (Data Block Count × Block Size))
```

and that:

```text
Parity Data Length == Group Count × Parity Block Count × Block Size
```

Any mismatch MUST return `SAR_ERR_INVALID_LENGTH`.

##### RaptorQ (0x13)

| Order | Value                         |
| ----- | ----------------------------- |
| 0     | Symbol-size exponent index    |
| 1     | Source symbol count indicator |

Byte 0 SHALL encode the symbol-size exponent index.

The Symbol Size SHALL be calculated as:

```text
Symbol Size = 2^(Byte0 + 8)
```

Valid values for Byte 0 are `0x00` through `0x14` inclusive. This corresponds to symbol sizes ranging from 256 bytes through 256 MiB.

All other values are RESERVED.

Byte 1 encodes the source symbol count `K` if the value is non-zero.

Values `0x01` through `0xFF` encode `K` directly.

A value of `0x00` SHALL indicate Extended-K encoding. When Byte 1 is `0x00`, `K` SHALL be encoded in the RaptorQ metadata as a uint32 little-endian value.

Implementations encountering an invalid symbol-size exponent index MUST return `SAR_ERR_RESERVED_VALUE`.

Implementations MUST reject RaptorQ RECOVERY blocks whose decoded Symbol Size, K value, repair symbol count, or effective protected size exceeds implementation-supported limits. Such failures MUST return `SAR_ERR_LIMIT_EXCEEDED`.

Implementations MAY reject RaptorQ RECOVERY blocks that exceed implementation-defined memory, storage, or processing limits.

Implementations SHALL perform all size calculations in a manner that prevents integer overflow. If overflow is detected, the implementation MUST return `SAR_ERR_OVERFLOW`.

K MUST be in the range 1 through 56,403 inclusive. Implementations encountering a K value greater than 56,403 MUST return `SAR_ERR_LIMIT_EXCEEDED`.

A Minimal Interoperable Profile supporting RaptorQ MUST support Byte 0 values from `0x00` through `0x0E` inclusive, corresponding to Symbol Size values from 256 bytes through 4 MiB, and K values from 1 through 255 inclusive.

Example:

* Byte 0: `0x04` means Symbol Size = 4096 bytes.
* Byte 1: `0x20` means K = 32 source symbols.

###### RaptorQ Implementation

SAR RaptorQ FEC SHALL use the RaptorQ forward error correction code as defined by RFC 6330.

One SAR RaptorQ TLV Value or FEC Value SHALL describe exactly one RFC 6330 source block.

SAR RaptorQ symbols SHALL be byte-vector symbols of Symbol Size bytes.

The protected byte sequence SHALL be divided into source symbols in ascending byte order. The final source symbol SHALL be right-padded with zero bytes to Symbol Size.

The number of source symbols `K` SHALL be the decoded K value from Config[2] or Extended-K metadata.

Source symbols SHALL use Encoding Symbol IDs `0` through `K - 1`.

The encoder SHALL generate Repair Symbol Count repair symbols using Encoding Symbol IDs beginning at First Repair ESI.

Repair symbols SHALL use Encoding Symbol IDs:

```text
First Repair ESI
First Repair ESI + 1
...
First Repair ESI + Repair Symbol Count - 1
```

`First Repair ESI` MUST be greater than or equal to `K`.

Repair symbols SHALL be encoded in ascending Encoding Symbol ID order.

Encoders SHOULD choose Symbol Size such that the protected byte sequence fits into one RFC 6330 source block without exceeding K = 56,403.

Larger objects SHOULD be protected using multiple SAR FEC scopes or archive-level segmentation.

Decoders SHALL use the encoded K value, Symbol Size, Original Protected Length, First Repair ESI, Repair Symbol Count, the available source symbols, and the encoded repair symbols to perform RaptorQ decoding according to RFC 6330.

The decoder SHALL use Original Protected Length to remove padding after successful recovery.

If RaptorQ decoding fails, the decoder MUST return `SAR_ERR_EC_FAILED`.


###### RaptorQ Encoding

For RaptorQ, the TLV Value or FEC Value SHALL be encoded as:

```text
Config[2] ||
Original Protected Length[8] ||
K Extended[0 or 4] ||
First Repair ESI[4] ||
Repair Symbol Count[4] ||
Repair Data[variable]
```

where:

`Config[2]` is Byte 0 = Symbol-size exponent index and Byte 1 = K indicator.

`Original Protected Length` is a uint64 little-endian value in bytes.

`K Extended` is present only when Config Byte 1 is `0x00`. When present, it is a uint32 little-endian value and SHALL encode K.

`First Repair ESI` is a uint32 little-endian value.

`Repair Symbol Count` is a uint32 little-endian value.

`Repair Data` contains:

```text
Repair Symbol Count × Symbol Size
```

bytes.

Implementations MUST verify that:

```text
K == ceil(Original Protected Length / Symbol Size)
```

and that:

```text
First Repair ESI >= K
```

and that:

```text
Repair Data Length == Repair Symbol Count × Symbol Size
```

Any mismatch MUST return `SAR_ERR_INVALID_LENGTH`.

##### XOR (0x14)
| Order | Value |
| --- | --- |
| 0     | Stripe size (data blocks per stripe) |
| 1     | Block size index |

Byte 0 encodes the stripe size, defined as the number of data blocks per XOR stripe.

Values 0x01 through 0xFF encode the stripe size directly.

A value of 0x00 is RESERVED and MUST result in SAR_ERR_RESERVED_VALUE.

Byte 1 encodes the block size index.

Block size index values are defined by the registry below.

The effective stripe size SHALL be calculated as:

Effective Stripe Size = Stripe Size × Block Size

Block size index registry:

| Index | Block Size |
| --- | --- |
| 0x00  | 256 B      |
| 0x01  | 512 B      |
| 0x02  |  1 KB      |
| 0x03  |  2 KB      |
| 0x04  |  4 KB      |
| 0x05  |  8 KB      |
| 0x06  | 16 KB      |
| 0x07  | 32 KB      |
| 0x08  | 64 KB      |

Any index values not explicitly assigned in this registry are RESERVED.

Implementations encountering a reserved value MUST return SAR_ERR_RESERVED_VALUE.

Implementations MAY reject XOR RECOVERY blocks whose Effective Stripe Size exceeds implementation-defined memory, storage, or processing limits.

Implementations SHALL perform all size calculations in a manner that prevents integer overflow. If overflow is detected, the implementation MUST return SAR_ERR_OVERFLOW.

A Minimal Interoperable Profile supporting XOR RECOVERY MUST support stripe sizes from 1 through 32 inclusive and block size indices from 0x00 through 0x06 inclusive.
This corresponds to block sizes ranging from 256 bytes through 16 KB.


Example:
* Byte 0: 0x04 (stripe size = 4 data blocks)
* Byte 1: 0x04 (block size = 4 KB)

This example represents XOR recovery over stripes of 4 data blocks, where each data block has a size of 4 KB.

###### XOR Implementation

SAR XOR FEC SHALL provide recovery from at most one missing or corrupted
data block per stripe.

The protected byte sequence SHALL be divided into consecutive data blocks
of Block Size bytes. A stripe consists of Stripe Size data blocks. The
XOR parity block for a stripe SHALL be computed as the bitwise XOR of all
data blocks in that stripe.

The final data block SHALL be right-padded with zero bytes to Block Size.
The final stripe SHALL be right-padded with zero-valued data blocks until
it contains exactly Stripe Size data blocks.

The parity data SHALL contain one parity block per stripe, encoded in
ascending stripe order.

###### XOR Encoding
For XOR, the TLV Value or FEC Value SHALL be encoded as:

```text
Config[2] ||
Original Protected Length[8] ||
Stripe Count[4] ||
Parity Data[variable]
```

where:

Config[2] is Byte 0 = Stripe Size and Byte 1 = Block Size Index.
Original Protected Length is a uint64 little-endian value in bytes.
Stripe Count is a uint32 little-endian value.
Parity Data contains Stripe Count × Block Size bytes.

Implementations MUST verify that:

Stripe Count == ceil(Original Protected Length / (Stripe Size × Block Size))

and that:

Parity Data Length == Stripe Count × Block Size

Any mismatch MUST return SAR_ERR_INVALID_LENGTH.

If more than one data block in the same stripe is missing or corrupted,
the decoder MUST return SAR_ERR_EC_FAILED.

##### RLC/RLNC (0x15)

| Order | Value                      |
| ----- | -------------------------- |
| 0     | RFC 8681 Scheme ID         |
| 1     | Symbol size exponent index |

Byte 0 SHALL identify the RFC 8681 Random Linear Code scheme used by this FEC scope.

The following values are defined:

| Value           | Scheme                      |
| --------------- | --------------------------- |
| `0x00`          | RESERVED                    |
| `0x01`          | RFC 8681 RLC over `GF(2)`   |
| `0x02`          | RFC 8681 RLC over `GF(2^8)` |
| `0x03` - `0xFF` | RESERVED                    |

Byte 1 SHALL encode the symbol-size exponent index.

The Symbol Size SHALL be calculated as:

```text
Symbol Size = 2^(Byte1 + 8)
```

Valid values for Byte 1 are `0x00` through `0x14` inclusive. This corresponds to Symbol Size values ranging from 256 bytes through 256 MiB.

All other values are RESERVED.

Implementations encountering a reserved Scheme ID or symbol-size exponent index MUST return `SAR_ERR_RESERVED_VALUE`.

A Minimal Interoperable Profile supporting RLC/RLNC MUST support:

* RFC 8681 RLC over `GF(2^8)` using Scheme ID `0x02`;
* Symbol Size values corresponding to Byte 1 values `0x00` through `0x0E` inclusive, meaning 256 bytes through 4 MiB;
* Window Size values from 1 through 255 inclusive;
* Repair Symbol Count values from 1 through 32 inclusive.

Support for RFC 8681 RLC over `GF(2)` is OPTIONAL.

Implementations MAY support larger Window Size values, larger Symbol Size values, and larger Repair Symbol Count values.

###### RLC/RLNC Implementation

SAR RLC/RLNC FEC SHALL use the Sliding Window Random Linear Code defined by RFC 8681.

Unless explicitly stated otherwise in this section, encoding, decoding, coefficient generation, finite-field arithmetic, code-density behavior, and repair-symbol interpretation SHALL follow RFC 8681.

One SAR RLC/RLNC TLV Value or FEC Value SHALL describe exactly one SAR RLC/RLNC FEC scope.

The protected byte sequence SHALL be divided into source symbols in ascending byte order. Each source symbol SHALL contain exactly Symbol Size bytes.

The final source symbol SHALL be right-padded with zero bytes to Symbol Size.

`Original Protected Length` SHALL be used to remove padding after successful recovery.

For SAR archive and file-entry recovery, the RFC 8681 sliding window SHALL be initialized over the protected byte sequence in ascending source-symbol order.

The first source symbol in the FEC scope SHALL have Source Symbol Identifier `0`.

Each subsequent source symbol SHALL increment the Source Symbol Identifier by one.

Repair symbols SHALL be encoded in ascending Repair Symbol Record order.

Each Repair Symbol Record SHALL carry the RFC 8681 information needed by the decoder to identify the repair symbol, its coding window, its coding coefficients, and the repair-symbol payload.

If RFC 8681 decoding fails, or if the available source and repair symbols are insufficient to recover the missing source symbols, the decoder MUST return `SAR_ERR_EC_FAILED`.

###### RLC/RLNC Encoding

For RLC/RLNC, the TLV Value or FEC Value SHALL be encoded as:

```text
Config[2] ||
Original Protected Length[8] ||
Source Symbol Count[4] ||
Repair Symbol Count[4] ||
Repair Symbol Records[variable]
```

where:

`Config[2]` is Byte 0 = RFC 8681 Scheme ID and Byte 1 = Symbol-size exponent index.

`Original Protected Length` is a uint64 little-endian value in bytes.

`Source Symbol Count` is a uint32 little-endian value and MUST equal:

```text
ceil(Original Protected Length / Symbol Size)
```

`Repair Symbol Count` is a uint32 little-endian value.

Each Repair Symbol Record SHALL be encoded as:

```text
RFC8681 Repair Header Length[2] ||
RFC8681 Repair Header[variable] ||
Repair Symbol[Symbol Size]
```

where:

`RFC8681 Repair Header Length` is a uint16 little-endian value.

`RFC8681 Repair Header` is the RFC 8681 repair-symbol header or equivalent RFC 8681 repair-symbol metadata required to decode the repair symbol.

`Repair Symbol` is the RFC 8681 repair-symbol payload and SHALL be exactly Symbol Size bytes.

Implementations MUST verify that:

```text
Source Symbol Count == ceil(Original Protected Length / Symbol Size)
```

and that each Repair Symbol Record is fully contained within the declared TLV Value or FEC Value.

Any mismatch MUST return `SAR_ERR_INVALID_LENGTH`.

The maximum protected payload size of a single RLC/RLNC FEC Value or RECOVERY TLV is limited by:

```text
Source Symbol Count × Symbol Size
```

For LFH Selective FEC, encoders MUST choose Repair Symbol Count, RFC8681 Repair Header Length, and Symbol Size such that the encoded Repair Symbol Records fit within the 24-bit FEC Size field.

For RECOVERY TLVs, encoders MUST choose Repair Symbol Count, RFC8681 Repair Header Length, and Symbol Size such that the encoded Repair Symbol Records fit within the RECOVERY TLV Length field.


##### Polar Codes (0x16)

| Order | Value                           |
| ----- | ------------------------------- |
| 0     | Codeword length exponent        |
| 1     | Information-bit count indicator |

Byte 0 encodes the codeword-length exponent `m`.

The codeword length `N` SHALL be calculated as:

```text
N = 2^m
```

where N is measured in bits.

Valid values for m are `0x08` through `0x18` inclusive.

All other values are RESERVED.

Byte 1 encodes the information-bit count K if the value is non-zero.

Values `0x01` through `0xFF` encode K directly.

A value of `0x00` SHALL indicate Extended-K encoding. When Byte 1 is `0x00`, K SHALL be encoded in the Polar metadata as a uint32 little-endian value.

K SHALL be greater than zero and less than N.

Implementations encountering an invalid m value or invalid K value MUST return `SAR_ERR_RESERVED_VALUE` or `SAR_ERR_MALFORMED` as appropriate.

Implementations MUST reject Polar Codes RECOVERY blocks whose decoded N value, K value, codeword count, or effective protected size exceeds implementation-supported limits.
Such failures MUST return `SAR_ERR_LIMIT_EXCEEDED`.

Implementations MAY reject Polar Codes RECOVERY blocks that exceed implementation-defined memory, storage, or processing limits.

Implementations SHALL perform all size calculations in a manner that prevents integer overflow. If overflow is detected, the implementation MUST return `SAR_ERR_OVERFLOW`.

A Minimal Interoperable Profile supporting Polar Codes MUST support m values from `0x08` through `0x10` inclusive.

Example:

* Byte 0: `0x0C` means N = 4096 bits.
* Byte 1: `0x80` means K = 128 information bits.

###### Polar Codes Implementation

SAR Polar Codes SHALL use binary systematic polar encoding over `GF(2)`.

The polar transform SHALL use the Arıkan kernel:

```text
F = [[1, 0],
     [1, 1]]
```

The length-N generator matrix SHALL be:

```text
G_N = B_N × F^(⊗m)
```

where:

* `N = 2^m`.
* `F^(⊗m)` is the m-fold Kronecker power of F.
* `B_N` is the bit-reversal permutation for length N.

All arithmetic SHALL be over `GF(2)`.

Information-bit positions SHALL be selected using the Polarization Weight method.

For each bit index i in `[0, N)`, define the binary expansion of i as:

```text
i = Σ b_j × 2^j
```

where `b_j` is either 0 or 1.

The polarization weight of i SHALL be:

```text
PW(i) = Σ b_j × β^j
```

where:

```text
β = 2^(1/4)
```

The K bit positions with the largest PW(i) values SHALL be used as information-bit positions.

Ties SHALL be resolved by selecting the lower bit index first.

All non-information positions SHALL be frozen bits and SHALL be set to zero.

The protected byte sequence SHALL be converted into a bit sequence using most-significant-bit-first order within each byte.

The bit sequence SHALL be divided into code blocks of K information bits.

The final information block SHALL be right-padded with zero bits until it contains exactly K information bits.

For each information block, the encoder SHALL produce one systematic polar codeword of N bits.

The parity data SHALL contain only the parity bits, not the systematic information bits.

Parity bits SHALL be extracted from each codeword by taking the encoded bits at all frozen positions in ascending bit-index order.

Polar code blocks SHALL be encoded in ascending block order.

Decoders SHALL reconstruct missing or corrupted information bits using the encoded parity bits, the deterministic information-position set, and the available protected data bits.

Decoders MAY use successive cancellation, successive cancellation list decoding, Gaussian elimination over `GF(2)`, or any equivalent method that produces the same recovered information bits.

If the missing or corrupted bits cannot be uniquely recovered, the decoder MUST return `SAR_ERR_EC_FAILED`.

The decoder SHALL use Original Protected Length to remove padding after successful recovery.

###### Polar Codes Encoding

For Polar Codes, the TLV Value or FEC Value SHALL be encoded as:

```text
Config[2] ||
Original Protected Length[8] ||
K Extended[0 or 4] ||
Code Block Count[4] ||
Parity Data Bit Length[4] ||
Parity Data[variable]
```

where:

`Config[2]` is Byte 0 = m and Byte 1 = K indicator.

`Original Protected Length` is a uint64 little-endian value in bytes.

`K Extended` is present only when Config Byte 1 is `0x00`. When present, it is a uint32 little-endian value and SHALL encode K.

`Code Block Count` is a uint32 little-endian value.

`Parity Data Bit Length` is a uint32 little-endian value and SHALL equal:

```text
Code Block Count × (N - K)
```

`Parity Data` contains the parity bits packed most-significant-bit first within each byte.

If the number of parity bits is not a multiple of 8, the final byte SHALL be right-padded with zero bits. Padding bits SHALL be ignored by decoders and MUST be set to zero by encoders.

Implementations MUST verify that:

```text
Code Block Count == ceil((Original Protected Length × 8) / K)
```

and that:

```text
Parity Data Bit Length == Code Block Count × (N - K)
```

and that:

```text
Parity Data Length == ceil(Parity Data Bit Length / 8)
```

Any mismatch MUST return `SAR_ERR_INVALID_LENGTH`.


### 9.3 Signature (ID 0x20 - 0x2F)
The `SIGNATURE` block MUST fulfil the requirements as outlined in section 11.3.

The algorithm used MUST be set by the least-significant nibble (4 bits) of the 1 byte TLV Type ID:

 * `0x20`: RESERVED and MUST NOT be utilized
 * `0x21`: OpenPGP‑RSA‑PSS
 * `0x22`: OpenPGP‑EdDSA (Ed25519)
 * `0x23`: RSA‑PSS (ASN.1‑DER)
 * `0x24`: Ed25519 (raw)
 * `0x25`: Schnorr (secp256k1)
 * `0x26`: Dilithium‑2
 * `0x27`: Falcon‑512
 * `0x28`: Falcon‑1024
 * `0x29`: SPHINCS+‑256s

Any herein not explicitly noted ID values are RESERVED and MAY be used in future revisions.

The TLV Length field MUST declare the size of the signature value and the TLV Value field MUST hold the signature.

Implementations that support signature processing (`SIGNED`) MUST implement:

* `Ed25519 (raw)` (`0x24`)

Support for all other signature algorithms is OPTIONAL.

Implementations encountering an assigned but unsupported signature algorithm identifier MUST return `SAR_ERR_UNSUPPORTED`.

Implementations encountering a reserved signature algorithm identifier MUST return `SAR_ERR_RESERVED_VALUE`.

### 9.4 Data Integrity Hashing (ID 0x30 - 0x3F)
The `DATA_HASH` block anchors the Central Dictionary to the Data Area. When the `SIGNED` flag is set, this block MUST be present to ensure that the files themselves have not been swapped or altered. Also see section 11.3.

The algorithm used MUST be set by the least-significant nibble (4 bits) of the 1 byte TLV Type ID:
 * `0x30`: SHA256
 * `0x31`: BLAKE3
 * `0x32`: SHA3_256

Any herein not explicitly noted ID values are RESERVED and MAY be used in future revisions.

The TLV Length field MUST match the digest size of the selected hashing algorithm and the TLV Value field MUST hold the hash value.

Implementations that support DATA_HASH processing MUST implement:

* `SHA256` (`0x30`)
* `BLAKE3` (`0x31`)

Support for `SHA3_256` (`0x32`) is OPTIONAL.

Implementations encountering an assigned but unsupported hashing algorithm identifier MUST return `SAR_ERR_UNSUPPORTED`.

Implementations encountering a reserved hashing algorithm identifier MUST return `SAR_ERR_RESERVED_VALUE`.

### 9.5 CDC Metadata (ID `0x40-0x4F`)

The `0x40-0x4F` Metadata TLV range is reserved for CDC cataloging, recipe resolution, and external-provider metadata.

The detailed semantics and value layouts for CDC metadata TLVs are defined in **Section 21, CDC Cataloging and Metadata**.

The CDC metadata TLV Type IDs are assigned as follows:

| TLV Type ID | Name               | Description                                       | Value layout            |
| ----------- | ------------------ | ------------------------------------------------- | ----------------------- |
| `0x40`      | `CDC_MAP`          | Embedded CDC catalog for self-contained archives. | See Section 21.1.       |
| `0x41`      | `CDC_EXT_PROVIDER` | URI for an external chunk provider.               | See Section 21.2.       |
| `0x42-0x4E` | RESERVED           | Reserved for future CDC metadata assignments.     | N/A                     |
| `0x4F`      | `CDC_CUSTOM`       | Implementation-defined CDC metadata extension.    | Implementation-defined. |

Implementations encountering an assigned but unsupported CDC metadata TLV Type ID MUST return `SAR_ERR_UNSUPPORTED`.

Implementations encountering a reserved CDC metadata TLV Type ID MUST return `SAR_ERR_RESERVED_VALUE`.


## 10. Error and Status Mapping
Standardized status, warning, and error return values for SAR API implementations and session status reporting:

| Value | Constant | Meaning |
|---------|----------|---------|
| 0 | `SAR_OK` | Success. |
| -1 | `SAR_ERR_GENERIC` | Unspecified failure. |
| 1 | `SAR_ERR_NOT_FOUND` | Entry, file, stream, metadata object, or referenced resource not found. |
| 2 | `SAR_ERR_INVALID_MAGIC` | Header magic mismatch or archive corruption detected during format identification. |
| 3 | `SAR_ERR_IO` | Hardware, network, storage, filesystem, or transport-layer I/O error. |
| 4 | `SAR_ERR_CRC_MISMATCH` | CRC validation failed. |
| 5 | `SAR_ERR_AUTH_FAILED` | Authentication failed during cryptographic verification. |
| 6 | `SAR_ERR_MALLOC` | Memory allocation or memory exhaustion failure. |
| 7 | `SAR_ERR_UNSUPPORTED` | Valid SAR feature, flag, profile, algorithm, or extension is not implemented by the current implementation. |
| 8 | `SAR_ERR_FLAG_CONFLICT` | Invalid flag combination or required dependency missing. |
| 9 | `SAR_ERR_PATCH_FAILED` | Binary patch application failed or base-file verification failed. |
| 10 | `SAR_ERR_BASE_MISSING` | Required base file is unavailable or its identity cannot be verified. |
| 11 | `SAR_ERR_INVALID_MAP` | Declared offset, length, extent, or mapping exceeds permitted bounds. |
| 12 | `SAR_ERR_NO_SPACE` | Insufficient storage space on the destination filesystem or device. |
| 13 | `SAR_ERR_PARTITION_MISSING` | Required archive partition or physical volume is not present. |
| 14 | `SAR_ERR_FRAGMENT_GAP` | One or more fragments are missing. Ignored when `LOSS_TOLERANT` is enabled. |
| 15 | `SAR_ERR_REASSEMBLY_BUFFER_FULL` | Reassembly buffers exceeded implementation-supported limits. |
| 16 | `SAR_ERR_PARTITION_MISMATCH` | Partition identifier, UUID, archive identifier, or magic value does not match the expected archive set. |
| 17 | `SAR_ERR_FRAGMENT_TIMEOUT` | Required fragment did not arrive before the configured timeout expired. |
| 18 | `SAR_WARN_INCOMPLETE` | Non-fatal warning: object reconstructed with missing fragments, missing data, or degraded recovery quality. |
| 19 | `SAR_ERR_RECIPE_UNRESOLVABLE` | One or more hashes referenced by a CDC recipe could not be resolved from the CDC catalog. |
| 20 | `SAR_ERR_CDC_MISMATCH` | Reassembled CDC object hash does not match the declared Content Hash. |
| 21 | `SAR_ERR_EC_FAILED` | Error-correction decoding failed or recovery was unsuccessful. |
| 22 | `SAR_ERR_TRUNCATED` | Archive, stream, header, metadata, or payload terminated unexpectedly before completion. |
| 23 | `SAR_ERR_MALFORMED` | Archive structure, metadata structure, or protocol structure is syntactically invalid. |
| 24 | `SAR_ERR_BOUNDS` | Declared offset, length, count, size, or computed range exceeds valid bounds. |
| 25 | `SAR_ERR_RESERVED_VALUE` | Encountered a reserved, prohibited, or unassigned registry value. |
| 26 | `SAR_ERR_OVERFLOW` | Integer overflow or arithmetic overflow detected during processing. |
| 27 | `SAR_ERR_LIMIT_EXCEEDED` | Implementation-defined limit exceeded (memory, size, count, nesting depth, fragment count, etc.). |
| 28 | `SAR_ERR_INVALID_ALIGNMENT` | Required alignment or padding constraints are violated. |
| 29 | `SAR_ERR_INVALID_LENGTH` | Length field is inconsistent with the declared structure or payload. |
| 30 | `SAR_ERR_CHECKSUM_MISMATCH` | Non-cryptographic checksum validation failed. |
| 31 | `SAR_ERR_HASH_MISMATCH` | Cryptographic hash validation failed. |
| 32 | `SAR_ERR_DECRYPT_FAILED` | Decryption operation failed. |
| 33 | `SAR_ERR_SIGNATURE_FAILED` | Digital signature validation failed. |
| 34 | `SAR_ERR_ANCHOR_HASH_FAILED` | Anchor Hash validation failed. |
| 35 | `SAR_ERR_INVALID_VERSION` | Archive version, profile version, or protocol version is unsupported or invalid. |
| 36 | `SAR_ERR_KEY_MISSING` | Required decryption, signing, or verification key is unavailable. |
| 37 | `SAR_ERR_KEY_REJECTED` | Provided cryptographic key is invalid, revoked, expired, or incompatible. |
| 38 | `SAR_ERR_STREAM_CLOSED` | Stream terminated unexpectedly before completion. |
| 39 | `SAR_ERR_STREAM_STATE` | Invalid stream state, stream lifecycle violation, protocol sequencing error, or Stream ID conflict. |
| 40 | `SAR_ERR_METADATA_MISSING` | Required metadata field, TLV, or structure is absent. |
| 41 | `SAR_ERR_METADATA_CONFLICT` | Metadata fields contain conflicting or mutually exclusive information. |
| 42 | `SAR_ERR_RECOVERY_UNAVAILABLE` | Recovery data is required but unavailable. |
| 43 | `SAR_ERR_RECOVERY_CORRUPTED` | Recovery metadata or parity data is corrupted or unusable. |
| 44 | `SAR_ERR_COMPRESSION_FAILED` | Compression operation failed. |
| 45 | `SAR_ERR_DECOMPRESSION_FAILED` | Decompression operation failed. |
| 46 | `SAR_ERR_WRITE_PROTECTED` | Archive, partition, stream, or destination is write-protected. |
| 47 | `SAR_ERR_ALREADY_EXISTS` | Requested object already exists and overwrite is not permitted. |
| 48 | `SAR_ERR_CANCELLED` | Operation was cancelled by the user or host application. |
| 49 | `SAR_ERR_TIMEOUT` | General operation timeout occurred. |
| 50 | `SAR_ERR_INTERNAL` | Internal implementation error or invariant violation. |
| 51 | `SAR_ERR_NONCE_REUSE` | AEAD nonce reuse detected for the same encryption key. |
| 52 | `SAR_ERR_TOO_MANY_STREAMS` | Implementation-defined concurrent or active stream limit exceeded. |
| 53 | `SAR_ERR_PATH_COLLISION` | During materialization, distinct Full Logical Entry Paths map to the same destination filesystem object. |
| 54 | `SAR_WARN_DUPLICATE` | Optional non-fatal diagnostic indicating that a repeated Full Logical Entry Path occurrence was encountered. |
| 55 | `SAR_ERR_PATH_ESCAPE` | During materialization, an Entry destination or effective symbolic-link target escapes the selected scope, or confinement cannot be established. |
| 56 | `SAR_ERR_INVALID_INPUT` | Nonconforming caller-supplied input to an encoder or API operation. |


Values in this registry MAY be used as local API return values and MAY also be carried in `SESSION_STATUS` frames where session status reporting is supported.

SAR_ERR_UNSUPPORTED SHALL be returned only when a SAR-defined feature, algorithm, profile, or extension is valid according to this specification but is not implemented by the current implementation.

Reserved, malformed, prohibited, or syntactically invalid values SHALL use the corresponding specific error codes defined in this section.

If an implementation encounters archive behavior, field combinations, or value semantics not defined by this specification, it MUST NOT infer semantics. The implementation MUST fail closed and return the most specific applicable error code. If no more specific error code applies, it MUST return SAR_ERR_MALFORMED.

If the behavior is defined by a valid but unsupported SAR extension, implementations MUST return SAR_ERR_UNSUPPORTED.

## 11. Abstract Stream Processing Model
### 11.1 SAR Byte Stream Definition
A **SAR Byte Stream** is defined as a logically contiguous, ordered sequence of octets that constitute one or more SAR archives encoded in sequence.

The SAR Byte Stream is a **logical input abstraction** and is independent of any physical transport mechanism, session semantics, or reliability guarantees.

An implementation conforming to this specification:

1. **MUST** process the SAR Byte Stream as a strictly forward-moving sequence of bytes.
2. **MUST NOT** require backward seeking within the stream for correct parsing of SAR structures.
3. **MUST** derive all structural interpretation exclusively from:

   * Global Header (Section 5)
   * Global Flags (Section 5.2)
   * Local File Headers (Section 6)
   * Central Dictionary, when present (Section 7)

The SAR Byte Stream definition does **not** imply any requirements regarding:

* transport-layer reliability
* session persistence
* retransmission semantics
* delivery guarantees
* ordering guarantees beyond byte-sequential consumption

These properties, where applicable, are defined exclusively in Section 18 (Stream Persistence and Stateful Streaming Mode).

### 11.2 Stream Parsing Execution Model
A conforming SAR implementation **MUST implement** a deterministic stream parsing state machine operating over the SAR Byte Stream.

The parsing state machine consists of the following phases:

#### 11.2.1 Global Header Resolution Phase
Upon initialization of the SAR Byte Stream parser, the implementation:

1. **MUST** parse the Global Header at stream offset zero.
2. **MUST** determine structural interpretation rules from Global Flags (Section 5.2).
3. **MUST** establish all conditional field layouts for Local File Headers prior to parsing any LFH entries.

#### 11.2.2 Sequential Entry Parsing Phase
Following successful Global Header resolution, the parser:

1. **MUST** process Local File Headers sequentially in stream order.
2. **MUST** compute the exact LFH size based on Global Flags prior to consuming variable-length fields.
3. **MUST** advance the stream position strictly as defined in section 6.1.1.
5. **MUST NOT** reorder entries during parsing.
6. **MUST NOT** infer missing entries except as explicitly defined by error handling rules in Section 8.

#### 11.2.3 Transformation Resolution Phase
After LFH parsing and payload acquisition, the implementation:

1. **MUST** apply transformations strictly in accordance with Section 13.1 (Transformation Pipeline).
2. **MUST** ensure transformation ordering consistency across all entries.
3. **MUST NOT** apply transformations in any order other than the canonical pipeline defined in Section 13.1.

### 11.3 Relationship to Stateful Streaming Mode
This section defines the **stateless stream parsing model only**.

All semantics involving:

* session continuity
* stream resumption
* ordering validation beyond byte stream continuity
* failure recovery across discontinuities
* application-layer sequencing
* idempotency guarantees
* atomic persistence behavior

are defined exclusively in:

> **Section 18 - Stream Persistence and Stateful Streaming Mode**

Implementations **MUST NOT** conflate the SAR Byte Stream model defined in this section with Stateful Streaming semantics defined in Section 18.


## 12. Compliance Profiles

SAR defines multiple compliance profiles to facilitate interoperability across implementations ranging from resource-constrained embedded systems to full-featured archival and replication platforms.

All profiles remain bitstream-compatible and SHALL follow the parsing, validation, security, and error-handling requirements defined elsewhere in this specification.

### 12.1 Standard Compliance Profile

The Standard Compliance Profile represents a fully conformant SAR implementation.

A Standard implementation MUST satisfy all requirements of both the Minimal Interoperable Archive Profile (Section 12.2) and the Minimal Interoperable Streaming Profile (Section 12.3).

In addition, Standard implementations MUST support all SAR-defined core feature sets defined by this specification as listed below:

* Compression
* Encryption
* CDC
* Delta Patching
* Fragmentation
* Sparse reconstruction
* Stateful Streaming
* Digital Signatures
* Data Integrity Hashing
* LOSS_TOLERANT processing according to Section 19.4.5.
* FEC / Recovery encoding and decoding according to sections 6.1.4 and 9.2

The following algorithms MUST be supported:

| Feature        | Required Algorithms                                  |
| -------------- | ---------------------------------------------------- |
| Compression    | STORE (`0x00`), DEFLATE (`0x01`), ZSTD (`0x02`)      |
| Encryption     | AES256_GCM (`0x01`), XCHACHA20_POLY (`0x04`)         |
| FEC / Recovery | Reed-Solomon (`0x11`), XOR (`0x14`)                  |
| CDC            | FASTCDC (`0x02`)                                     |
| Delta          | STORE_PATCH (`0x00`), VCDIFF (`0x01`)                |
| Signatures     | Ed25519 (raw) (`0x24`), RSA-PSS (ASN.1-DER) (`0x23`) |
| Hashing        | SHA256 (`0x30`), BLAKE3 (`0x31`)                     |

Additional algorithms defined by this specification MAY be implemented.

Algorithms not listed as required for the Standard Compliance Profile are OPTIONAL unless explicitly designated as mandatory elsewhere in this specification.

Implementations encountering assigned but unsupported optional algorithms MUST return `SAR_ERR_UNSUPPORTED`.

Implementations encountering reserved algorithm identifiers MUST return `SAR_ERR_RESERVED_VALUE`.

For Stateful Streaming Mode (Section 18), Standard implementations MUST support the SAR-over-TCP transport binding.

For Stateful Streaming Mode (Section 18), Standard implementations SHOULD support the SAR-over-QUIC transport binding.

### 12.2 Minimal Interoperable Archive Profile

The Minimal Interoperable Archive Profile is intended for resource-constrained systems that require SAR archive interoperability but do not require Stateful Streaming Mode.

A Minimal Interoperable Archive implementation MUST implement:

1. LFH Parsing and validation.
2. Header Size and Payload Size processing.
3. Sequential archive processing.
4. Central Dictionary processing when present.
5. NO_INDEX archive processing.
6. Filename extraction.
7. Error code mappings applicable to implemented features.
8. Flag dependency validation.
9. AEAD authentication verification according to Section 13.2.

The following algorithms MUST be supported:

| Feature     | Required Algorithms              |
| ----------- | -------------------------------- |
| Compression | STORE (`0x00`), DEFLATE (`0x01`) |
| Encryption  | AES256_GCM (`0x01`)              |

Support for ZSTD (`0x02`) is RECOMMENDED but OPTIONAL.

Stateful Streaming Mode (Section 18) is OPTIONAL.

### 12.3 Minimal Interoperable Streaming Profile

The Minimal Interoperable Streaming Profile is intended for resource-constrained systems that require real-time replication and streaming but do not require support for archive-oriented SAR features.
The Minimal Interoperable Streaming Profile is not a subset of the Minimal Interoperable Archive Profile and is optimized for interoperability within Stateful Streaming Mode (Section 18) rather than general-purpose archival processing.

A Minimal Interoperable Streaming implementation MUST implement:

1. LFH Parsing and validation.
2. Header Size and Payload Size processing.
3. NO_INDEX stream processing.
4. Stream ID handling.
5. Sequence Number handling.
6. SESSION_INIT processing.
7. SESSION_CLOSE processing.
8. SESSION_HEARTBEAT processing.
9. SESSION_CAPABILITIES processing
10. Session timeout handling.
11. Stream state validation.
12. Error code mappings applicable to implemented features.
13. Flag dependency validation.
14. AEAD authentication verification according to Section 13.2.
15. Forward Error Correction (FEC) encoding and decoding.
16. Delta patch processing.
17. `LOSS_TOLERANT` processing according to Section 19.4.5.
18. Fragmentation according to Sections 19.2 and 19.5.
19. Sparse file reconstruction according to Sections 17 and 19.6.

The following algorithms MUST be supported:

| Feature        | Required Algorithms                 |
| -------------- | ----------------------------------- |
| Compression    | STORE (`0x00`), DEFLATE (`0x01`)    |
| Encryption     | AES256_GCM (`0x01`)                 |
| FEC / Recovery | Reed-Solomon (`0x11`), XOR (`0x14`) |
| Delta | STORE_PATCH (`0x00`), VCDIFF (`0x01`) |

Minimal Interoperable Streaming implementations MUST support `LOSS_TOLERANT` Entry Mode semantics as defined in Sections 6.2.2 and 19.4.5.

If `LOSS_TOLERANT` is set, missing or unrecoverable fragments MAY be discarded and streaming MAY continue, provided the affected payload type or transformation chain defines safe partial-output semantics.

If degraded reconstruction succeeds, the implementation MUST report `SAR_WARN_INCOMPLETE`.

If `LOSS_TOLERANT` is not set, missing or unrecoverable fragments MUST result in `SAR_ERR_FRAGMENT_GAP`, `SAR_ERR_RECOVERY_CORRUPTED`, or another more specific applicable error code.

Support for the following session-control messages is OPTIONAL:

* `SESSION_ACK`
* `SESSION_STATUS`
* `SESSION_RESUME`
* `SESSION_METADATA`

Bidirectional control and bidirectional streaming support are OPTIONAL.

If an implementation advertises or accepts `BIDIRECTIONAL_CONTROL_REQUESTED`, `BIDIRECTIONAL_CONTROL_REQUIRED`, `BIDIRECTIONAL_STREAM_REQUESTED`, or `BIDIRECTIONAL_STREAM_REQUIRED`, the implementation MUST implement `SESSION_STATUS` transmission over the negotiated reverse-direction control channel.

Implementations supporting session recovery SHOULD support `SESSION_RESUME`.

Implementations supporting acknowledgement-based session diagnostics SHOULD support `SESSION_ACK`.

For Stateful Streaming Mode (Section 18), Minimal Interoperable Streaming implementations MUST support the SAR-over-TCP transport binding. Support for SAR-over-QUIC transport binding is OPTIONAL.

Other transport bindings MAY be implemented, but support for such bindings does not satisfy the required baseline transport interoperability requirement.

### 12.4 Unsupported Features

Implementations MAY support only the features required by their selected compliance profile.

If an implementation supports a feature but encounters an assigned algorithm identifier that is not implemented by the selected profile, it MUST return `SAR_ERR_UNSUPPORTED`.

If an implementation encounters a reserved algorithm identifier, it MUST return `SAR_ERR_RESERVED_VALUE`.

If an implementation encounters a valid SAR feature that is not implemented by the selected profile, it MUST return `SAR_ERR_UNSUPPORTED`, unless a more specific error code applies.

If the size of an unsupported structure can be determined safely from the LFH and Global Flags, implementations MAY perform Transparent Skip by using the `Header Size` and `Payload Size` fields without interpreting the skipped metadata.

Transparent Skip MUST NOT be used for transformations required to reconstruct payload contents, including compression, encryption, delta patching, CDC reconstruction, or Forward Error Correction (FEC) encoding and decoding.

Unknown or reserved structural features MUST NOT be skipped and MUST result in `SAR_ERR_UNSUPPORTED`, `SAR_ERR_RESERVED_VALUE`, or another more specific error code as applicable.

## 13. Security and Integrity
## 13.1 Transformation Sequence (Canonical Pipeline)
SAR defines a strict and unambiguous transformation pipeline for all payload data. Implementations MUST adhere to this order to ensure interoperability.

### 13.1.1 Logical Model
All transformations operate on the logical file data in the following conceptual order:

```
Logical Data → Patch → Compress → Encrypt
```

FEC in contrast is not a payload transformation that changes the logical payload. FEC protects the encoded SAR byte sequence selected by its scope. When FEC protects Payload Data, FEC encoding SHALL be applied after compression and encryption during encoding. During decoding, FEC repair SHALL be performed before decryption, decompression, and patch application.

### 13.1.2 Encoding Procedure (Writer Side)
When creating an archive entry:

1. **Patch Stage (Optional)**
   If `HAS_DELTA` is set, the encoder MUST:

   * Compute a binary delta between the base object and the target data.
   * The result of this stage is the **patch payload**, representing the logical transformation.

   If `HAS_DELTA` is not set, the input data proceeds unchanged.

2. **Compression Stage (Optional)**
   If `IS_COMPRESSED` is set:

   * The encoder MUST compress the output of the previous stage using `Comp Algo ID`.

   If `IS_COMPRESSED` is not set:

   * The data MUST be treated as `STORE` (no compression), even if the `COMPRESSED` global flag is enabled.

3. **Encryption Stage (Optional)**
   If `IS_ENCRYPTED` is set:

   * The encoder MUST encrypt the output of the compression stage using the selected encryption algorithm.

### 13.1.3 Decoding Procedure (Reader Side)
To reconstruct the original data, implementations MUST apply the inverse operations in strict reverse order:

```
Decrypt → Decompress → Apply Patch
```

1. **Decryption**
   If `IS_ENCRYPTED` is set:

   * The payload MUST be decrypted before any further processing.
   * For AEAD modes, authentication MUST be verified before proceeding.

2. **Decompression**
   If `IS_COMPRESSED` is set:

   * The payload MUST be decompressed using `Comp Algo ID`.

3. **Patch Application**
   If `HAS_DELTA` is set:

   * The patch MUST be applied to the resolved base object using `Patch Algo ID`.
   * The result MUST match `Uncompressed Size`.

After completion of the final decoding stage, the reconstructed logical object MUST exactly match `Uncompressed Size` regardless of whether patching was performed.
Also consider section 17.4.3 with regards to integrity verification and section 17.4.4 with regards to error correction.

### 13.1.4 Invariants
* Patch algorithms MUST operate on **uncompressed logical data**, never on compressed streams.
* Compression MUST NOT be applied to already encrypted data.
* Decryption MUST occur before any decompression or patch processing.
* The output of the final stage MUST represent the fully reconstructed logical file.

### 13.2 Authenticated Encryption (AEAD)
When `ENCRYPTED` is set, AEAD algorithms (e.g., `AES256_GCM`, `XCHACHA20_POLY`, `CHACHA20_POLY1305`) MUST verify the authentication tag before decompression to prevent "Decompression Bomb" attacks and chosen-ciphertext exploits.

#### 13.2.1 AEAD Additional Authenticated Data (AAD) Binding
To provide integrity protection over LFH metadata (not just payload confidentiality), implementations using an AEAD-capable encryption algorithm MUST bind the LFH fields to the AEAD authentication tag via the Additional Authenticated Data (AAD) mechanism.

**AAD Construction**

The AAD for a given LFH MUST be constructed as follows:

* All bytes of the Global Header from archive offset 0 through the final byte of the Global Flags field, in their encoded on-wire representation.
* All bytes of the LFH from the first byte of the `Header Size` field through the last byte of the LFH header, in their encoded on-wire representation, except that when SELECTIVE_FEC is active and FEC Algo ID is non-zero, the FEC Size field and FEC Value field SHALL be excluded from the AAD.

This is equivalent to the concatenation of:

* bytes in range `[0, GlobalHeader_End)`
* bytes in range `[LFH_Start, LFH_Start + Header Size)`, excluding the `FEC Size` field and `FEC Value` field when `SELECTIVE_FEC` is active and `FEC Algo ID` is non-zero.

where `GlobalHeader_End` denotes the first byte immediately following the Global Flags field.

The KMS Extension, if present, SHALL NOT be included in AAD.

The `FEC Algo ID` field, if present, SHALL remain included in AAD.

**Normative Requirements**

* Encoders MUST pass this AAD to the AEAD encryption operation when generating the ciphertext and authentication tag.
* Decoders MUST pass the same AAD to the AEAD cipher when verifying the authentication tag. Verification MUST occur before decompression, patch application, or any state-mutating operation.
* If authentication tag verification fails, the implementation MUST return `SAR_ERR_AUTH_FAILED` and MUST NOT proceed with any further processing of the payload or LFH metadata.

#### 13.2.2 AEAD Tag Placement and Payload Parsing
For AEAD algorithms (e.g. `AES256_GCM`, `XCHACHA20_POLY`, `CHACHA20_POLY1305`), the per-entry authentication tag (computed over ciphertext and AAD) MUST be encoded at the **end** of `Payload Data` using this layout:

`Payload Data = Ciphertext || Tag`

For the AEAD algorithms currently defined in this specification, `Tag` length is 16 bytes (`TagLen = 16`). Future AEAD algorithms MAY define authentication tag lengths other than 16 bytes. Such algorithms MUST explicitly define their tag length in the corresponding algorithm specification.

Encoders MUST append the tag after ciphertext and MUST NOT place the tag at the start of `Payload Data` or in any out-of-band location.

Decoders MUST parse `Payload Data` as:

* `Ciphertext`: bytes `[Payload_Start, Payload_Start + Payload Size - TagLen)`
* `Tag`: bytes `[Payload_Start + Payload Size - TagLen, Payload_Start + Payload Size)`

All byte ranges above use start-inclusive, end-exclusive interval semantics (`[start, end)`).

If `Payload Size < TagLen`, implementations MUST return `SAR_ERR_INVALID_LENGTH`.

Decoders MUST verify only the suffix `Tag` defined above. Prefix-tag layouts are non-conformant and MUST be rejected as `SAR_ERR_MALFORMED`.

For AEAD algorithms, LFH `Payload Size` SHALL include both the ciphertext and the authentication tag.

The authentication tag SHALL NOT be included in LFH `Uncompressed Size`.

**Non-AEAD Ciphers**

Encryption algorithms that do not provide authentication (e.g., `AES256_CBC`, `CHACHA20`) offer no integrity protection over LFH fields or payload. Implementations using these algorithms MUST rely on external
authentication mechanisms (e.g., transport-layer TLS, archive
signatures, or authenticated storage) to detect tampering.

Per-file CRC MAY detect accidental corruption but does not provide
cryptographic integrity protection.

Applications requiring reliable tamper detection SHOULD use an AEAD algorithm such as `XCHACHA20_POLY`, `AES256_GCM`, or `CHACHA20_POLY1305`.

#### 13.2.3 Authenticated Header Validation

When `ENCRYPTED` is set and at least one entry uses an AEAD-capable encryption algorithm, implementations SHOULD verify at least one AEAD-protected LFH entry before trusting security-relevant Global Flags or Central Dictionary metadata.

Until successful AEAD authentication has occurred, implementations SHOULD treat the following Global Flags as untrusted:

* `SIGNED`
* `OPT_PRESENT`
* `HAS_GLOBAL_CRC32`
* `HAS_GLOBAL_EC`

Implementations performing random access MAY parse the first LFH solely for the purpose of locating and verifying the authentication tag prior to trusting Central Dictionary metadata.

Applications or deployment profiles requiring signed archives MUST enforce signature verification independently of the archive-provided `SIGNED` flag.

### 13.3 Digital Signatures and Binding
To ensure global payload integrity, the `DATA_HASH` (ID `0x30 - 0x3F`) MUST be present and included in the signed CD when the `SIGNED` flag is set. The signature MUST be calculated over the entire Central Dictionary excluding the SIGNATURE TLV itself. Implementations MUST NOT trust or act upon Central Dictionary offsets or metadata until signature verification (if SIGNED) and DATA_HASH validation have successfully completed. If SIGNED is not set, implementations SHOULD treat the Central Dictionary as untrusted and MAY validate entries against the Data Area before use. Also see section 9.5.

#### 13.3.1 Signature Scope and Threat Model
The SAR signature (when `SIGNED` is set) covers the Central Dictionary, which in turn anchors the Data Area via the `DATA_HASH` TLV. The Global Header (including Global Flags and KMS Extension) is intentionally outside the signature scope. This is a deliberate design choice, because the Central Dictionary is fully optional in SAR (`NO_INDEX` mode), and because:

* * If AEAD encryption is in use (`ENCRYPTED` flag set), the Global Header and LFH metadata are authenticated through the AEAD AAD construction defined in Section 13.2.1. Modifications to cryptographic parameters within the KMS Extension will generally result in key derivation, decryption, or authentication failure. However, the KMS Extension itself is not directly authenticated by the AEAD tag.
* If AEAD encryption is NOT in use, the integrity of the Global Header fields is not cryptographically guaranteed by either the signature or the AEAD mechanism. In this threat model, an adversary capable of modifying the archive file can alter Global Flags or KMS parameters without detection unless the archive is protected at a higher layer (e.g., TLS transport, filesystem integrity).

Implementations and deployers MUST account for this boundary when assessing the security posture of a SAR-based system. Where end-to-end integrity of the complete archive structure (including Global Header) is required, deployments SHOULD combine `SIGNED` (Bit 18) with an AEAD-capable encryption algorithm.

### 13.4 Flag Dependency and Conflict Rules
Failure to meet these SHALL result in `SAR_ERR_FLAG_CONFLICT` (8).

1. **Signature Anchor**: If `SIGNED` (Bit 18) is set, `OPT_PRESENT` (Bit 2) MUST be set **AND** `DATA_HASH` (ID 0x30 - 0x3F) MUST be present in the CD.
2. **Encryption Anchor**: If `ENCRYPTED` (Bit 10) is set, the `KMS_DATA` Global Extension MUST be present (Also see section 5.3.1).
3. **Index Conflict**: If `NO_INDEX` (Bit 1) is set, the following MUST NOT be set: `OPT_PRESENT`, `HAS_GLOBAL_CRC32`, `HAS_GLOBAL_EC`, `SIGNED`.

### 13.5 Delta Security
When `HAS_DELTA` (Bit 9) is utilized, the `Delta Base Hash` in the LFH MUST be verified against the hash of the local base file before the patching algorithm is executed. If the base hash does not match, the implementation MUST return `SAR_ERR_PATCH_FAILED` (9). In streaming mode, if the Base Hash is unknown, the parser MUST buffer the patch or return a specific error `SAR_ERR_BASE_MISSING` (10).

### 13.6 Path Handling and Installation Profiles

Before materialization, the caller or host application MUST select an Extraction Root or an explicitly authorized installation scope.

Archive or stream metadata MUST NOT select or change the Extraction Root or authorized installation scope.

The following extraction profiles are defined:

* `0x00 SANDBOXED`: Entries are materialized beneath the selected Extraction Root.
* `0x01 SYSTEM_INSTALL`: Entries may be materialized within an installation scope explicitly authorized by the caller or host application.
* Custom profiles MAY define additional path-mapping rules.

Selection of `SYSTEM_INSTALL` or another privileged scope MUST be explicit. An LFH Name String, Path String, empty destination value, leading separator, drive prefix, share prefix, or device prefix MUST NOT implicitly select a privileged or unconfined scope.

All profiles remain subject to Section 22.4.


## 13.7 Global Invariants (Normative)
This section defines mandatory invariants that apply to all SAR archives. These rules ensure deterministic parsing, structural consistency, and interoperability across implementations. Any violation of these invariants MUST result in a parsing failure unless explicitly stated otherwise.

### 13.7.1 Structural Determinism
1. **Global Schema Authority**
   The Global Flags SHALL define the complete structural schema of all Local File Headers (LFHs). Implementations MUST NOT infer field presence or layout from Entry Mode flags or payload content.

2. **Deterministic Header Size**
   Given a fixed set of Global Flags, the size and layout of every LFH MUST be fully deterministic prior to reading any variable-length fields.

3. **Forward-Only Parsing**
   Implementations MUST be able to parse the Data Area in a single forward pass without backtracking, except when explicitly using the Central Dictionary for random access.

### 13.7.2 Offset and Boundary Integrity
1. **Monotonic Advancement**
   For each entry, the parser MUST advance the read pointer as defined in section 6.1.1. Zero or negative advancement MUST be treated as an error.

2. **Bounds Enforcement**
   All structures (headers, payloads, metadata, and Central Dictionary) MUST reside entirely within the archive boundaries.

3. **Central Dictionary Pointer Validity**
   If present, the Footer pointer to the Central Dictionary MUST:

   * Be greater than or equal to the end of the Data Area
   * Be strictly less than the total archive size
     Violations MUST result in an error.

### 13.7.3 Flag Consistency
1. **Global Dominance**
   Entry Mode flags MUST NOT enable features that are disabled at the Global Flag level.

2. **Mandatory Field Presence**
   If a Global Flag enables a field, that field MUST be physically present in every LFH, regardless of whether it is semantically used.

3. **Semantic Override Only**
   Entry Mode flags MAY alter the interpretation of a field but MUST NOT remove, reorder, or redefine its presence.

### 13.7.4 Transformation Pipeline Invariant
1. **Canonical Encoding Order**
   Payload data MUST be transformed in the following order: `Stored Payload = Encrypt(Compress(Patch(Data)))`

2. **Canonical Decoding Order**
   Payload data MUST be reconstructed in the following order: `Data = ApplyPatch(Decompress(Decrypt(Payload)))`

3. **Processing Requirements**
* Decryption MUST occur before any other transformation.
* Decompression MUST occur before patch application.
* Patch algorithms MUST operate on fully decompressed logical data.
* Compression MUST NOT be applied to encrypted data.

### 13.7.5 Identity and Referential Integrity
1. **Fragment Uniqueness**
   The tuple `(Fragment ID, Fragment Index)` MUST uniquely identify a fragment within the archive. Duplicate indices for the same Fragment ID MUST result in an error.

2. **Delta Base Resolution**
   The `Delta Base Hash` MUST uniquely identify a valid base object. If no matching base is found, or multiple matches exist, the operation MUST fail.

3. **Central Dictionary Authority**
   If a Central Dictionary is present:
   * It SHALL be the authoritative structure for random-access operations.
   * All offsets and metadata MUST correspond exactly to entries in the Data Area.
   * Implementations MUST validate that:
     * Each referenced offset points to a valid LFH
     * The LFH content matches the metadata (size, name, etc.)
   If any mismatch is detected, the implementation MUST return an error.

### 13.7.6 Sparse and Fragmentation Interaction
1. **Reconstruction Order**
   When both sparse files and fragmentation are used, reconstruction MUST follow this order:

   ```
   Fragment Reassembly → Logical Payload → Sparse Reconstruction → Final File
   ```

2. **Sparse Map Scope**
   The Sparse Map SHALL describe the layout of the fully reconstructed file and MUST NOT apply to individual fragments.

3. **Sparse Map Location Constraint**
   The Sparse Map MUST appear only in the fragment with `Fragment Index = 0`. Presence in any other fragment MUST result in `SAR_ERR_INVALID_MAP`.

4. **Dependency Enforcement**
   If both `SPARSE_FILES` and `FILE_FRAGMENTATION` are enabled, implementations MUST complete fragment reassembly before applying sparse reconstruction.

### 13.7.7 Empty Area Invariant
1. **Identification Rule**: An entry with `Name Length == 0` and `IS_FRAGMENT == 0` MUST be interpreted as an Empty Area.

2. **Isolation Requirement** Empty Areas MUST NOT:
** Be referenced in the Central Dictionary
** Participate in hashing, delta processing, or fragmentation logic

### 13.7.8 Versioning Invariant
1. **Global Version Scope**
   The Global Header Version defines:

   * LFH structure
   * Global Flag semantics
   * Transformation rules

2. **Central Dictionary Version Scope**
   The Central Dictionary Version defines only the layout of the Central Dictionary.

3. **Compatibility Requirements**

   * Implementations MUST reject archives with unsupported Global Header versions.
   * Implementations MAY process newer Central Dictionary versions only if they can be safely parsed without ambiguity.

### 13.7.9 Streaming Safety Invariant
1. **NO_INDEX Validity**
   Archives using `NO_INDEX` MUST remain fully parseable without reliance on a Central Dictionary. In `NO_INDEX` mode, the Data Area is the sole authoritative source of truth. No external or inferred index structures SHALL be required or assumed.

2. **Entry Independence**
   Each LFH MUST be independently parseable based solely on the Global Flags and its local data.

3. **Error Containment**
   Errors encountered while processing an entry MUST NOT compromise the ability to continue parsing subsequent entries, unless the error is classified as fatal.

## 14. Footer (Fixed: 8 Bytes)
The Footer is located at the final 8 bytes of the archive and provides a pointer to the start of the Central Dictionary.

### 14.1 Structure
| Field | Size | Description |
| --- | --- | --- |
| CD Offset | 8B   | Unsigned 64-bit integer indicating the absolute byte offset of the Central Dictionary |

### 14.2 Presence Rules
* The Footer MUST be present if and only if `NO_INDEX` (Bit 1) is **not** set.
* If `NO_INDEX` is set, the Footer MUST be omitted.

### 14.3 Alignment and Padding
To ensure consistent layout and compatibility with memory-mapped access:

1. The Central Dictionary MUST end on an 8-byte boundary.

2. If the Central Dictionary does not naturally align:

   * Padding bytes MUST be inserted between the end of the Central Dictionary and the Footer.
   * Padding bytes MUST be set to `0x00`.

3. The Footer MUST immediately follow this padding.

Padding bytes inserted for alignment are considered part of the Central Dictionary region for the purposes of signature calculation, but are not part of the logical Central Dictionary structure.

### 14.4 Offset Semantics
* The `CD Offset` MUST point to the **first byte of the Central Dictionary**, not including any padding.
* The offset MUST satisfy:

  * `CD Offset ≥ End of Data Area`
  * `CD Offset < Total Archive Size - 8`

### 14.5 Integrity and Signing Scope
When the `SIGNED` flag (Bit 18) is set:

1. The **entire Central Dictionary**, including:

   * Header fields
   * Metadata (TLV blocks)
   * Offset array

   MUST be included in the signature calculation.

2. Any alignment padding bytes between the Central Dictionary and Footer:

   * MUST be included in the signature calculation.

3. The Footer itself:

   * MUST NOT be included in the signature.

Overall, the signature scope SHALL cover the byte range from the start of the Central Dictionary up to (but excluding) the Footer, including any alignment padding.

### 14.6 Validation Requirements
Implementations MUST:

* Verify that the Footer offset points to a valid Central Dictionary structure.
* Ensure that the Central Dictionary does not overlap with the Footer.
* Reject archives where:

  * The offset points outside the file bounds
  * The Central Dictionary cannot be fully parsed

If the Footer offset points outside the archive bounds, implementations MUST return SAR_ERR_BOUNDS.

If the Central Dictionary overlaps with the Footer, implementations MUST return SAR_ERR_BOUNDS.

If the Central Dictionary cannot be fully read, implementations MUST return SAR_ERR_TRUNCATED.

If the Central Dictionary is present but structurally invalid, implementations MUST return SAR_ERR_MALFORMED.

## 15. Padding, Empty-Area & Symlinks
To allow for archive efficiency (e.g., in-place file deletion or pre-allocation for future updates), SAR introduces the Empty Area Entry. This allows a creator to leave "slack" in the Data Area without breaking sequential parsing. SAR also allows archiving symlink files in a simple way without breaking the general SAR-structure.

### 15.1 Definition of an Empty Area
An Empty Area is represented by a valid LFH that points to a "null" file.

* **Name Length**: MUST be set to `0`.
* **Path Length**: MUST be set to `0` (if `HAS_PATH` is set).
* **Payload Size**: Specifies the size of the empty payload area in bytes.
* **Other Header Fields**: All other fields (CRC, IV, Timestamps, etc.) MUST be set to `0`. Especially `IS_FRAGMENT` MUST be set to 0.
* **Payload**: The payload consists of `Payload Size` bytes of arbitrary data or `0x00` padding.

### 15.2 Mandatory Extraction Behavior for Empty Areas
All SAR parsers MUST be able to identify and skip Empty Areas.

* A parser encountering an LFH with `Name Length == 0` AND `IS_FRAGMENT == 0` SHALL interpret this as an Empty Area.
* The parser MUST skip `Payload Size` bytes to arrive at the next header.
* Empty Areas MUST NOT be included in the `File Count` of the Central Dictionary.

### 15.3 Definition of a symlink file

An Entry whose `IS_SYMLINK` Entry Mode bit is set represents a symbolic link. Its reconstructed Payload Data contains the symbolic-link target encoded as UTF-8.

A symbolic-link target MUST NOT contain U+0000.

The Full Logical Entry Path identifies the symbolic-link object. The payload identifies its target.

A symbolic-link target MAY be absolute, relative, parent-traversing, dangling, platform-specific, or directed to an object that has not yet been materialized. These properties do not make the Entry malformed.

A writer receiving a target that is not valid UTF-8 or contains U+0000 MUST return `SAR_ERR_INVALID_INPUT` and MUST NOT emit the affected Entry.

A reader encountering an encoded target that is not valid UTF-8 or contains U+0000 MUST return `SAR_ERR_MALFORMED`.

Readers MUST preserve valid symbolic-link targets without normalization or rewriting.

Writers MUST preserve valid symbolic-link targets supplied by the caller.

Reading, listing, verifying, copying, or transforming an Entry MUST NOT fail solely because its symbolic-link target cannot be safely materialized under a particular local extraction policy.

Symbolic-link materialization is governed by Section 22.4.


## 16. Binary Delta & Patching Protocol
The Delta protocol enables efficient storage of multi-versioned files by storing only the differences between a current file and its predecessor. This section is consistent with and subordinate to the canonical transformation pipeline defined in Section 13.1.

### 16.1 Process Logic
By separating `Comp Algo ID` and `Patch Algo ID`, SAR version 1.0 supports **Compressed Binary Patches**.

1. Identify that the `HAS_DELTA` flag is active.
2. Retrieve the `Delta Base Hash` from the LFH.
3. Locate the base file and verify its hash.
4. If `IS_COMPRESSED` is set, decompress the payload using `Comp Algo ID`.
5. Apply the patching algorithm specified in the `Patch Algo ID` field (Section 8.4) to the (decompressed) patch and the base file.
6. The resulting uncompressed data size MUST match the `Uncompressed Size` field in the LFH.

## 17. Sparse File Reconstruction Algorithm
This section defines the mandatory procedure for reconstructing files when the `SPARSE_FILES` flag (Global Bit 30) and the corresponding `IS_DIRECTORY` (Entry Mode Bit 1) is NOT set.

### 17.1 Theory of Operation
Sparse file support allows SAR to archive large files containing "holes" (long sequences of null bytes) without physically storing those zeros. The reconstruction process uses a "Scatter-Gather" approach: the Payload Data (the "Gathered" data) is read sequentially and "Scattered" into a new file at specific offsets defined by the Sparse Map.

### 17.2 Sparse Map Interpretation
The `Sparse Map` field in the LFH consists of a contiguous array of Fragment Descriptors. The number of descriptors is determined by dividing the `Sparse Map Size` field value by the descriptor size.

**Descriptor Size**:

* If `64BIT_SIZE` (Bit 0) is **OFF**: 8 bytes (`uint32_t offset`, `uint32_t length`).
* If `64BIT_SIZE` (Bit 0) is **ON**: 16 bytes (`uint64_t offset`, `uint64_t length`).

Each descriptor defines a range of valid data. Any gap between the end of one fragment and the start of the next (or between the start of the file and the first fragment) MUST be interpreted as a "hole" consisting of null bytes (0x00).

### 17.3 Reconstruction Procedure
Implementations MUST follow these steps to ensure filesystem integrity:

1. **File Creation**: Create a new file handle. The file's initial size SHOULD be set to the `Uncompressed Size` field to pre-allocate space or define the "Apparent Size."
2. **Payload Preparation**: If `IS_COMPRESSED` (Entry Mode Bit 3) is set, decompress the Payload Data into a temporary buffer or a streaming pipe.
3. **Iteration**: For each descriptor in the Sparse Map:
* **Seek**: Move the file pointer of the target file to the descriptor's `offset`.
* **Write**: Read `length` bytes from the (decompressed) payload and write them to the target file.
4. **Truncation**: After the final fragment is written, the implementation MUST ensure the file is exactly `Uncompressed Size` bytes long (e.g., using `ftruncate` or equivalent). This is critical if the file ends with a "hole."

### 17.4 Implementation Considerations
#### 17.4.1 Native Sparse Support
On systems supporting sparse files (e.g., Linux with `lseek(SEEK_HOLE)`, Windows with `FSCTL_SET_SPARSE`), implementations SHOULD utilize system calls to mark the file as sparse. This prevents the OS from physically writing zeros to the disk for the "holes", preserving the storage efficiency of the archive.

#### 17.4.2 Non-Sparse Fallback
If the host filesystem does not support sparse files, the implementation MUST manually fill the holes with null bytes or rely on standard file-seeking behavior which typically pads skipped ranges with zeros on most modern Operating Systems.

#### 17.4.3 Integrity Verification
The `File CRC32` and `Content Hash` fields MUST be calculated against the **fully reconstructed file** (including holes). Implementations MUST NOT calculate hashes based only on the stored payload fragments, as this would fail to detect corruption in the sparse structure itself.

#### 17.4.4 Error Correction
The `SELECTIVE_FEC` and `HAS_GLOBAL_EC` MUST be calculated against the **fully reconstructed file** (including holes). Any error correction operation SHOULD be applied only if an integrity verification operation (section 17.4.3) fails.

### 17.5 Error Conditions
* **SAR_ERR_INVALID_MAP**: Triggered if any descriptor `offset + length` exceeds the `Uncompressed Size`.
* **SAR_ERR_NO_SPACE**: Triggered if the host filesystem has insufficient space to expand the sparse file to its apparent size.

### 17.6 Transformation Ordering and Sparse Applicability
When `SPARSE_FILES`, `COMPRESSED`, and/or `HAS_DELTA` are simultaneously enabled, implementations MUST apply transformations in the following canonical order before sparse reconstruction:

1. Fragment Reassembly (`FILE_FRAGMENTATION`, if enabled)
2. Decryption (`ENCRYPTED`, if enabled)
3. Decompression (`COMPRESSED`, if enabled)
4. Patch Application (`HAS_DELTA`, if enabled)
5. Sparse Reconstruction (`SPARSE_FILES`, if enabled)

Sparse reconstruction MUST operate exclusively on the fully materialized logical file after all prior transformations have completed.

Sparse maps MUST NOT reference compressed, encrypted, or delta-encoded representations.

## 18. Stream Persistence and Session Recovery
This section governs the behavior of SAR when utilized as a real-time, state-aware replication journal over persistent connections.

### 18.1 Stateful Streaming Mode Activation

Stateful Streaming Mode is active for a SAR stream only if all of the following conditions are met:

1. Global Flag Bit 1 (`NO_INDEX`) is set.
2. The `Stream ID` LFH field contains a non-zero value.
3. A valid `SESSION_INIT` control message (Entry Mode Bit 13 set, `OP_CODE = 0x00`) has been successfully processed for the corresponding Stream ID.

In Stateful Streaming Mode, a transport connection MAY carry multiple SAR streams.

Each SAR stream:

* MUST be identified by a non-zero Stream ID.
* MUST begin with a SAR Global Header.
* MUST establish a session by means of a valid `SESSION_INIT` message.
* MUST maintain independent Global Flags, KMS state, Session UUID, Sequence Number state, and LFH parsing context.

A Stream ID MUST NOT be reused while an active session remains bound to that Stream ID on the same transport connection.

A new SAR Global Header received on an established transport connection SHALL be interpreted as the beginning of a new SAR stream only if it is followed by a valid `SESSION_INIT` message utilizing a Stream ID that is not currently active.

If the new SAR Global Header is not followed by a valid `SESSION_INIT`, the implementation MUST NOT bind a new stream.

If the referenced Stream ID is already active, the implementation MUST reject the new stream, MUST NOT bind the requested Stream ID, and MUST treat the condition as `SAR_ERR_STREAM_STATE`.

If bidirectional control is active, the implementation MUST transmit a `SESSION_STATUS` message with `STATUS_CODE = SAR_ERR_STREAM_STATE`.

For SAR-over-TCP transport bindings, if the implementation cannot determine the end of the invalid stream without fully accepting it, the implementation MUST close the transport connection.

Implementations MAY enforce an implementation-defined limit on the number of active SAR streams associated with a single transport connection.

If accepting a new SAR stream would exceed this limit, the implementation MUST reject the new stream and MUST NOT bind the requested Stream ID.

If bidirectional control is active, the implementation MUST transmit a `SESSION_STATUS` message with `STATUS_CODE = SAR_ERR_TOO_MANY_STREAMS`.

If bidirectional control is not active, the implementation MAY close the transport connection.

If the transport connection remains open, the implementation MUST discard or reject the new stream according to the applicable transport binding. For SAR-over-TCP transport bindings, if the implementation cannot safely determine the end of the rejected stream, the implementation MUST close the transport connection.

A Stream ID rejected with `SAR_ERR_TOO_MANY_STREAMS` MUST remain unbound and MUST NOT be treated as active.

For SAR-over-QUIC transport bindings, an implementation MAY reset, discard, or reject only the affected QUIC stream where supported by the transport API, rather than closing the entire transport connection.

For SAR-over-TCP transport bindings, SAR streams MUST NOT be byte-interleaved. A new stream MAY begin only after the preceding stream has terminated via `SESSION_CLOSE` or otherwise reached its end.

For SAR-over-QUIC transport bindings, SAR streams MAY be mapped to independent QUIC streams and MAY operate concurrently.

### 18.2 Session Lifecycle and Binding
For session lifecycle and binding purposes, `SESSION_CONTROL` entries MUST be utilized as defined in section 6.3.

`SESSION_INIT`, `SESSION_CLOSE`, `SESSION_HEARTBEAT`, and `SESSION_CAPABILITIES` are baseline session-control messages and do not require capability advertisement.

An endpoint MUST NOT transmit an optional session-control message for which this specification defines a capability flag unless the endpoint has advertised that capability in its own `SESSION_CAPABILITIES`, except when transmitting a mandatory message required to terminate or reject the session.

#### 18.2.1 Initialization and UUID Binding

A session is established by transmitting a `SESSION_INIT` entry.

The payload of `SESSION_INIT` MUST consist of a 16-byte Session UUID followed by a 2-byte Session Flags field.

For session binding:

* the `Stream ID` LFH field is the active session handle within the transport connection;
* the Session UUID is the unique identity of that session;
* the tuple `(transport connection, Stream ID, Session UUID)` identifies the active SAR session state.

Upon receipt of a valid `SESSION_INIT`, the receiving endpoint MUST bind the Stream ID to the supplied Session UUID and initialize session state for that Stream ID.

A Stream ID that is already active on the same transport connection MUST NOT be rebound by a new `SESSION_INIT`.

A duplicate `SESSION_INIT` for an already-active Stream ID on the same transport connection MUST fail closed with `SAR_ERR_STREAM_STATE`.

The Session Flags field describes bidirectional behavior requested or required by the endpoint that transmitted `SESSION_INIT`.

| Bit  | Name                              | Description                                                                                                                                              |
| ---- | --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | `BIDIRECTIONAL_CONTROL_REQUESTED` | The sender of `SESSION_INIT` can receive reverse-direction `SESSION_CONTROL` messages over the same transport connection.                                |
| 1    | `BIDIRECTIONAL_CONTROL_REQUIRED`  | The sender of `SESSION_INIT` requires the peer to support reverse-direction `SESSION_CONTROL` messages over the same transport connection.               |
| 2    | `BIDIRECTIONAL_STREAM_REQUESTED`  | The sender of `SESSION_INIT` can receive reverse-direction Session Mode and Filesystem Mode entries over the same transport connection.                  |
| 3    | `BIDIRECTIONAL_STREAM_REQUIRED`   | The sender of `SESSION_INIT` requires the peer to support reverse-direction Session Mode and Filesystem Mode entries over the same transport connection. |
| 4-15 | `RESERVED`                        | Reserved for future use.                                                                                                                                 |

`BIDIRECTIONAL_STREAM_REQUESTED` or `BIDIRECTIONAL_STREAM_REQUIRED` MUST NOT be set unless `BIDIRECTIONAL_CONTROL_REQUESTED` or `BIDIRECTIONAL_CONTROL_REQUIRED` is also set.

`BIDIRECTIONAL_STREAM_REQUIRED` MUST NOT be set unless `BIDIRECTIONAL_CONTROL_REQUIRED` is also set.

Invalid Session Flags combinations MUST result in `SAR_ERR_FLAG_CONFLICT`.

Reserved Session Flags bits MUST be set to 0. Receivers encountering non-zero reserved bits MUST return `SAR_ERR_RESERVED_VALUE` if reverse control is available, or terminate the session or transport connection otherwise.

If `BIDIRECTIONAL_CONTROL_REQUIRED` is set and the receiving endpoint cannot transmit reverse-direction `SESSION_CONTROL` messages for the selected transport binding, the receiving endpoint MUST terminate the session or transport connection.

If `BIDIRECTIONAL_STREAM_REQUIRED` is set and the receiving endpoint cannot transmit reverse-direction Session Mode and Filesystem Mode entries for the selected transport binding, the receiving endpoint MUST terminate the session or transport connection.

If `BIDIRECTIONAL_CONTROL_REQUESTED` is set without `BIDIRECTIONAL_CONTROL_REQUIRED`, a receiving endpoint that supports reverse-direction `SESSION_CONTROL` messages for the selected transport binding SHOULD enable bidirectional control. Otherwise, it MAY continue in unidirectional mode.

If `BIDIRECTIONAL_STREAM_REQUESTED` is set without `BIDIRECTIONAL_STREAM_REQUIRED`, a receiving endpoint that supports reverse-direction Session Mode and Filesystem Mode entries for the selected transport binding SHOULD enable bidirectional streaming. If it supports bidirectional control but not full bidirectional streaming, it SHOULD continue in bidirectional-control-only mode. If it cannot support reverse-direction `SESSION_CONTROL`, it MAY continue in unidirectional mode.

An endpoint that supports a requested bidirectional mode but disables it due to local policy MUST treat that mode as unavailable for the session and apply the same downgrade or termination rules that apply when the mode is unsupported.

If bidirectional control is available and a required bidirectional mode cannot be satisfied, the receiving endpoint SHOULD transmit `SESSION_STATUS` with the closest applicable error before terminating the session.

If bidirectional control is not available and a required bidirectional mode cannot be satisfied, the receiving endpoint MUST terminate the session or transport connection without relying on reverse `SESSION_STATUS`.

These rules apply regardless of which endpoint initiated the transport connection.


### 18.3 Transport and Ordering Requirements
This section applies **only to Stateful Streaming Mode** (see Section 18.1). It defines the required behavioral properties of the underlying transport abstraction and the interpretation of SAR stream ordering semantics.

#### 18.3.1 Transport Abstraction Requirements
Stateful Streaming Mode operates over a **byte-stream abstraction** that MUST provide the following properties to the SAR parser:

1. **Byte-Stream Continuity**:
   The transport abstraction MUST deliver SAR data as a single, contiguous byte stream.

2. **In-Order Delivery to Parser Interface**:
   Bytes MUST be presented to the SAR parsing layer in the exact order in which they were emitted by the sender.

3. **Integrity Detection**:
   The transport abstraction or surrounding system MUST provide a mechanism to detect:

   * truncation of the stream
   * corruption of transmitted data
   * loss of byte continuity

   Detection MAY be provided by the transport layer, by encapsulating protocols, or by SAR-level integrity checks (e.g., CRC, signatures, AEAD).

4. **Reliability Semantics**:
   The SAR specification does **not mandate any specific transport protocol**. However, the chosen transport MUST behave as a reliable byte-stream abstraction with respect to ordering and completeness as defined above.

Examples of transport mechanisms that MAY satisfy these requirements include, but are not limited to:

* TCP streams
* SCTP streams
* QUIC streams
* Application-defined reliable stream transports

#### 18.3.2 Sequence Number Semantics (Application-Layer Continuity Token)
The `Sequence No` field (2 bytes) is an **application-layer monotonic continuity indicator** used exclusively within Stateful Streaming Mode.

##### Semantics
1. The Sequence No MUST increment by exactly one for each successive LFH emitted within the same active session context.
2. The Sequence No is defined modulo 65.536 and MUST wrap from `0xFFFF` to `0x0000`.
3. Wraparound is **defined behavior** and MUST NOT be interpreted as an error condition.

##### Scope Limitation
The Sequence No:

* MUST NOT be used to enforce transport ordering
* MUST NOT be used as a substitute for transport reliability mechanisms
* MUST NOT influence byte-stream reconstruction order at the transport layer

##### Failure Detection Role
The Sequence No MAY be used by receivers for detection of:

* missing LFH entries within a contiguous stream
* unexpected session resets or desynchronization
* debugging, monitoring, and forensic reconstruction

Upon detection of discontinuity, implementations:

* MAY request reinitialization of the session (if supported)
* MAY terminate the session to prevent propagation of inconsistent state

Such actions are **implementation-defined behaviors** and MUST NOT be interpreted as protocol-level requirements.

#### 18.3.3 Heartbeat and Keep-Alive Semantics
To ensure session persistence during periods of payload inactivity, the following keep-alive rules MUST apply:

* Mandatory Interval: The Sender MUST emit a `SESSION_HEARTBEAT` (Op 0x3) or any other valid LFH at least once every 60 seconds.
* Minimum Value: To prevent network congestion and unnecessary CPU overhead, heartbeats MUST NOT be emitted more frequently than once every 5 seconds.
* Inactivity Timeout: The Receiver SHOULD implement a session watchdog. If no valid LFH (Data or Heartbeat) is received within 180 seconds (3x the mandatory interval), the Receiver SHALL terminate the session and return `SAR_ERR_TIMEOUT`.
* Sequence Continuity: Heartbeats MUST increment the `Sequence No` field like any other entry to ensure the application-layer continuity token remains valid.

`SESSION_HEARTBEAT` payload size SHALL be 0 bytes.

#### 18.3.4 Status Messages
Status SHALL be communicated by utilizing `SESSION_STATUS` (Op 0x4). The payload MUST contain a SAR Stream Status Frame. The SAR Stream Status Frame is encoded as follows:

| Order | Field Name | Size | Description |
| --- | --- | --- | --- |
| 0 | REF_SEQUENCE | 2B | The sequence number this status message refers to. |
| 1 | STATUS_CODE | 2B | Holds the status code value as defined in section 10 (-1 encoded as 0xFFFF). |
| 2 | MESSAGE_SIZE | 1B | Size of the status message in bytes. |
| 3 | STATUS_MESSAGE | var | Status message. |

The `STATUS_CODE` field SHALL contain a value from the Section 10 status-code registry and MAY represent a success, warning, or error condition.

The `Name Length` and `Name String` LFH fields of a `SESSION_STATUS` entry MAY be copied from the referenced LFH for diagnostic purposes.

If no referenced name is available, `Name Length` MUST be set to 0 and the `Name String` field MUST be omitted.

#### 18.3.5 Acknowledgement entries
Receipt, acceptance, or completion of any LFH within the active session MAY be signaled with a `SESSION_ACK` entry. The Acknowledgement Frame is encoded as follows:

| Order | Field Name | Size | Description |
| --- | --- | --- | --- |
| 0 | REF_SEQUENCE | 2B | The Sequence No of the message being acknowledged. |
| 1 | ACK_FLAGS | 1B | Flags defining whether the referenced message has been accepted. |

ACK_FLAGS MUST be structured as follows:

| Bit | Field Name | Description |
| --- | --- | --- |
| 0 | ACK | The referenced LFH was received and parsed syntactically |
| 1 | OK | The referenced LFH was accepted as valid and applicable. |
| 2 | SUCCESS | The operation requested by the referenced LFH completed successfully. |
| 3 - 7 | RESERVED | Reserved for future use. |

ACK_FLAGS MAY contain multiple bits.

`OK` MUST NOT be set unless `ACK` is also set.

`SUCCESS` MUST NOT be set unless both `ACK` and `OK` are also set.

Reserved ACK_FLAGS bits MUST be set to 0. Receivers encountering non-zero reserved bits MUST return `SAR_ERR_RESERVED_VALUE`.

### 18.3.6 End of Session

To terminate an active session, a sender SHALL transmit a `SESSION_CLOSE` message containing a zero-length payload.

`SESSION_CLOSE` terminates only the session associated with the referenced Stream ID.

Upon receiving `SESSION_CLOSE`, implementations MUST:

* unbind the Stream ID and Session UUID associated with the terminated session;
* release any session-specific state maintained for that stream;
* cease accepting additional data associated with the terminated Stream ID.

If bidirectional control is active and `SESSION_ACK` is supported, the receiver SHOULD transmit a `SESSION_ACK` message referencing the received `SESSION_CLOSE`.

The underlying transport connection MAY remain open after a session has been terminated.

A transport connection MAY continue carrying other active SAR streams that remain bound to the connection.

If no active SAR streams remain associated with the transport connection, the implementation MAY close the transport connection or MAY keep it open for future SAR stream establishment, subject to application policy.

#### 18.3.7 Session Resumption
When session resumption is attempted, the sender SHALL transmit a `SESSION_RESUME` control message. The `SESSION_RESUME` payload SHALL consist of the 16-byte Session UUID associated with the session being resumed.

If the supplied Session UUID matches the UUID bound to the Stream ID, the receiver MUST resume the session or return `SAR_ERR_UNSUPPORTED` if resumption is not supported.

If the supplied Session UUID does not match the UUID bound to the Stream ID, the receiver MUST return `SAR_ERR_STREAM_STATE`.

If reverse control is not available and the receiver encounters an error state, implementations MUST terminate the connection.

### 18.3.8 Session Metadata
`SESSION_METADATA` conveys application-level metadata associated with the active SAR stream. It does not alter SAR parsing rules, Global Flags, KMS state, LFH layout, or transformation semantics.

The payload of a `SESSION_METADATA` message SHALL be encoded as follows:

| Order | Field | Size | Description |
| --- | --- | --- | --- |
| 0 | Content-Type Length | 1B | Length, in bytes, of the `Content-Type` field. |
| 1 | Metadata Size | 4B | Size, in bytes, of the `Metadata` field. |
| 2 | Content-Type | Var | UTF-8 encoded media type or application-defined content type. |
| 3 | Metadata | Var | Opaque metadata bytes interpreted according to `Content-Type`. |

`Content-Type Length` MUST be non-zero.

`Content-Type` SHOULD contain an IANA media type where applicable, such as `video/mp4`, `audio/ogg`, `application/json`, or `application/cbor`.

Codec, profile, bitrate, resolution, language, timing, or other application-specific properties MAY be encoded inside the `Metadata` field.

The `Metadata` field MAY be zero bytes.

SAR implementations MUST NOT be required to interpret or validate the `Metadata` field.

If an implementation does not recognize the declared `Content-Type`, it MUST ignore the `Metadata` field and continue normal stream processing.

Receipt of `SESSION_METADATA` updates the application metadata associated with the active Stream ID until superseded by a later `SESSION_METADATA` message for the same Stream ID or until the session terminates.


#### 18.3.9 Session Capabilities

`SESSION_CAPABILITIES` advertises the session-control capabilities supported by the transmitting endpoint for the active Stream ID.

The payload of a `SESSION_CAPABILITIES` message SHALL be encoded as follows:

| Order | Field              | Size | Description                                        |
| ----- | ------------------ | ---- | -------------------------------------------------- |
| 0     | `CAPABILITY_FLAGS` | 2B   | Bitmask of supported session-control capabilities. |

`CAPABILITY_FLAGS` SHALL be structured as follows:

| Bit  | Capability                  | Meaning                                                                                                                 |
| ---- | --------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| 0    | `CAP_SESSION_ACK`           | Endpoint can transmit and process `SESSION_ACK`.                                                                        |
| 1    | `CAP_SESSION_STATUS`        | Endpoint can transmit and process `SESSION_STATUS`.                                                                     |
| 2    | `CAP_SESSION_RESUME`        | Endpoint can transmit and process `SESSION_RESUME`.                                                                     |
| 3    | `CAP_SESSION_METADATA`      | Endpoint can transmit and process `SESSION_METADATA`.                                                                   |
| 4    | `CAP_BIDIRECTIONAL_CONTROL` | Endpoint supports reverse-direction session-control messages.                                                           |
| 5    | `CAP_BIDIRECTIONAL_STREAM`  | Endpoint supports reverse-direction Filesystem Mode and Session Mode entries.                                           |
| 6    | `CAP_TLS_EXPORTER_AEAD`     | Endpoint supports SAR AEAD key derivation using KMS Mode `0x04 TLS_EXPORTER` over an authenticated TLS-based transport. |
| 7-15 | `RESERVED`                  | Reserved for future use.                                                                                                |

Reserved bits MUST be set to 0 by encoders and MAY be ignored by receivers unless strict validation is enabled.

If strict validation is enabled, receivers encountering non-zero reserved bits MUST return `SAR_ERR_RESERVED_VALUE`.

A sender MAY transmit `SESSION_CAPABILITIES` immediately after `SESSION_INIT`.

If bidirectional control is active, both endpoints SHOULD transmit `SESSION_CAPABILITIES` for the active Stream ID before sending non-control stream data in the reverse direction.

`SESSION_CAPABILITIES` advertises support. It does not select SAR-layer AEAD, change KMS state, alter Global Flags, or override the SAR Global Header.

`CAP_TLS_EXPORTER_AEAD` indicates that the transmitting endpoint supports deriving SAR-layer AEAD keying material from TLS exporter material using KMS Mode `0x04 TLS_EXPORTER`.

KMS Mode `0x04 TLS_EXPORTER`, when selected by the SAR Global Header / KMS configuration, is authoritative for selecting TLS-exporter SAR-AEAD for that SAR stream.

Failure behavior for unsupported KMS Mode `0x04 TLS_EXPORTER` is defined in Section 18.6.5.


### 18.4 Stateful Execution Semantics
This subsection defines execution guarantees that apply **only when Stateful Streaming Mode is active (Section 18.1)**.

These semantics apply at the **Receiver state layer**, not at the byte-stream parsing layer defined in Section 11.

#### 18.4.1 Idempotency and Atomic State
##### Idempotent Deletion
An `OP_DELETE` for an already absent resource SHALL result in `SAR_OK`.

This operation MUST be treated as **state-equivalent success**, and MUST NOT be treated as an error condition, regardless of prior execution history.

##### Atomic Transitions
When `ATOMIC_WRITE` (Bit 14) is set, the Receiver MUST ensure atomic visibility of the final resource state.

The implementation MUST:

1. Buffer incoming payload data in a **temporary shadow location**
2. Verify payload integrity using CRC validation defined by the SAR integrity model
3. Only upon successful verification, perform an atomic `rename()` (or equivalent filesystem atomic replace operation supported by the host environment)
4. Ensure that at no point is a partially-written final object visible to other consumers of the resource namespace

If CRC verification fails:

* The shadow data MUST be discarded
* No mutation to the final namespace MUST occur
* The operation MUST be treated as failed at the state layer, even if transport delivery succeeded

### 18.5 SAR Transport Binding Profiles

SAR Stateful Streaming Mode MAY be bound to multiple reliable transport profiles.

This specification defines the following transport binding profiles:

| Profile         | Transport             | Stream Multiplexing                 | TLS Availability                   | Notes                                                             |
| --------------- | --------------------- | ----------------------------------- | ---------------------------------- | ----------------------------------------------------------------- |
| `SAR-over-TCP`  | TCP byte stream       | Sequential SAR streams only         | Optional, if TCP is wrapped in TLS | SAR streams MUST NOT be byte-interleaved on one TCP connection.   |
| `SAR-over-QUIC` | QUIC stream transport | Concurrent independent QUIC streams | Mandatory as part of QUIC/TLS      | Each QUIC stream defines an independent SAR byte-stream boundary. |

A transport binding profile MUST preserve the byte-stream abstraction required by Section 18.3.1 for every SAR stream it presents to the SAR parser.

A transport binding profile MUST NOT weaken SAR AEAD, signature, hash, KMS, or transformation ordering requirements.

A transport binding profile MAY provide additional transport-level confidentiality, integrity, authentication, flow control, or multiplexing. Such transport-level protections do not replace SAR-layer AEAD protection when SAR-layer AEAD is required by the archive, session, or application policy.

#### 18.5.1 SAR-over-TCP Profile

In the `SAR-over-TCP` profile, a TCP connection carries SAR bytes as a reliable ordered byte stream.

A single TCP connection MAY carry multiple SAR streams sequentially.

SAR streams carried over one TCP connection MUST NOT be byte-interleaved.

A new SAR stream MAY begin on an existing TCP connection only after the preceding SAR stream has terminated via `SESSION_CLOSE` or otherwise reached its end.

If a receiver encounters an invalid or rejected SAR stream and cannot safely determine the end of that stream without fully accepting it, the receiver MUST close the TCP connection.

If TLS is layered over TCP and the TLS stack exposes exporter keying material, the resulting TLS session MAY be used with KMS Mode `0x04 TLS_EXPORTER`. Endpoints that do not support KMS Mode `0x04 TLS_EXPORTER` fail closed as defined in Section 18.6.5.

If TCP is not protected by TLS, KMS Mode `0x04 TLS_EXPORTER` MUST NOT be used.


#### 18.5.2 SAR-over-QUIC Profile

In the `SAR-over-QUIC` profile, SAR streams are carried over QUIC streams.

A QUIC connection MAY carry multiple simultaneous SAR sessions.

Each QUIC stream defines an independent byte-stream boundary. Bytes from different QUIC streams MUST NOT be interleaved before presentation to the SAR parser.

A primary SAR QUIC stream begins with a SAR Global Header beginning with the SAR magic bytes `SAR!`.

A single primary QUIC stream SHOULD carry at most one active SAR session lifecycle at a time.

Active SAR Stream IDs MUST be unique within a single QUIC connection. A duplicate active SAR Stream ID on the same QUIC connection MUST fail closed with `SAR_ERR_STREAM_STATE`.

The same numeric SAR Stream ID MAY be active on different QUIC connections. Such sessions are independent unless a future resumption profile explicitly defines otherwise.

Bidirectional SAR communication for an active session MUST use the same SAR Stream ID as the session it belongs to.

A bidirectional QUIC stream MAY carry both forward-direction and reverse-direction SAR entries for the same SAR Stream ID.

All SAR-over-QUIC implementations that advertise `CAP_BIDIRECTIONAL_CONTROL` MUST support transmitting and receiving reverse-direction `SESSION_ACK`, `SESSION_STATUS`, and `SESSION_CAPABILITIES` entries on the same bidirectional QUIC stream as the corresponding SAR session.

All SAR-over-QUIC implementations that advertise `CAP_BIDIRECTIONAL_STREAM` MUST support transmitting and receiving reverse-direction Filesystem Mode entries and Session Mode entries on the same bidirectional QUIC stream as the corresponding SAR session.

Additional QUIC streams MAY carry `SESSION_CONTROL` entries for an already-active SAR session on the same QUIC connection.

An additional QUIC control stream is not a primary SAR stream. It MUST NOT begin with a SAR Global Header and MUST NOT begin with the SAR magic bytes `SAR!`.

An additional QUIC control stream MUST begin directly with an LFH-encoded `SESSION_CONTROL` entry.

To associate an additional QUIC control stream with an active SAR session, the receiver MUST read the invariant LFH prefix through the `Stream ID` field, select the active session context bound to that Stream ID on the same QUIC connection, and then parse the complete LFH using that session's Global Header, Global Flags, KMS state, LFH layout rules, and AEAD state.

The first LFH on an additional QUIC control stream MUST satisfy all of the following:

* the LFH `Stream ID` references an active SAR session on the same QUIC connection;
* Entry Mode Bit 13 (`SESSION_CONTROL`) is set;
* the Session Mode opcode is permitted for additional control streams;
* the entry is not `SESSION_INIT`;
* the entry is not a Filesystem Mode entry.

The Session UUID for an additional QUIC control stream is the Session UUID already bound to the referenced Stream ID on the same QUIC connection. The Session UUID is not retransmitted by `SESSION_ACK`, `SESSION_STATUS`, or `SESSION_CAPABILITIES`.

If a `SESSION_CONTROL` opcode carried on an additional QUIC control stream contains a Session UUID in its payload, that UUID MUST match the Session UUID bound to the referenced Stream ID.

Additional QUIC control streams MUST be supported for `SESSION_ACK`, `SESSION_STATUS`, and `SESSION_CAPABILITIES` when bidirectional control is active.

A QUIC stream carrying only `SESSION_CONTROL` entries for an existing SAR Stream ID does not establish a new SAR session and MUST NOT cause the receiver to reinitialize the SAR session.

Additional QUIC control streams MUST NOT carry `SESSION_INIT`.

Additional QUIC control streams MUST NOT carry Filesystem Mode entries unless `CAP_BIDIRECTIONAL_STREAM` is active and the active transport profile explicitly permits reverse-direction filesystem entries on additional QUIC streams.

If an additional QUIC control stream references an unknown Stream ID, a closed session, a disallowed opcode, an ambiguous session state, or an entry that cannot be parsed using the referenced session context, the receiver MUST reject that QUIC stream with `SAR_ERR_STREAM_STATE`, `SAR_ERR_MALFORMED`, or the closest applicable structural error.

If multiple QUIC streams are associated with the same SAR Stream ID, the receiver MUST apply `SESSION_CONTROL` messages according to `Sequence No` ordering and MUST reject ambiguous or contradictory state transitions with `SAR_ERR_STREAM_STATE`.

Use of multiple QUIC streams for one SAR session MUST NOT relax Stream ID uniqueness, Sequence No validation, AEAD authentication, KMS state, transform state, or session lifecycle rules.

For a given selected feature set and security mode, SAR-over-QUIC encodings defined by this profile are canonical.

A SAR-over-QUIC sender's primary-stream entries MUST be processed the same way by every conforming receiver that supports the selected feature set and security mode.

When bidirectional control is active, a SAR-over-QUIC client's reverse-direction `SESSION_ACK`, `SESSION_STATUS`, and `SESSION_CAPABILITIES` entries MUST be decodable by every conforming SAR-over-QUIC listener implementation that supports the selected feature set and security mode.

Implementations MUST NOT require private stream markers, alternate control-stream magic values, or implementation-specific control envelopes for the encodings defined by this profile.

A QUIC stream whose first bytes are neither a valid primary SAR stream beginning with `SAR!` nor a valid LFH-encoded additional control stream for an already-active SAR Stream ID MUST be rejected stream-locally where supported by the QUIC API.

When a SAR stream carried on a QUIC stream is rejected, malformed, or exceeds limits, the receiver SHOULD reset, discard, or reject only the affected QUIC stream where supported by the QUIC API.

A stream-local error SHOULD NOT require closing the entire QUIC connection unless the error is connection-fatal or policy requires connection termination.

Termination of a SAR session MUST unbind the SAR Stream ID and Session UUID on that QUIC connection and MUST cause QUIC streams associated exclusively with that SAR session to be closed, reset, drained, or disassociated according to transport policy.

SAR-over-QUIC endpoints SHOULD support `CAP_TLS_EXPORTER_AEAD`.

SAR-over-QUIC deployments SHOULD use SAR-layer AEAD protection derived through KMS Mode `0x04 TLS_EXPORTER`.

Deployments MAY operate with QUIC/TLS transport protection only. In that mode, QUIC/TLS protects transport bytes, but SAR entries do not receive independent SAR-layer AEAD confidentiality or AAD authentication unless the archive itself uses SAR encryption.

SAR-over-QUIC deployments concerned with harvest-now-decrypt-later attacks SHOULD prefer or require post-quantum-safe or hybrid post-quantum TLS key agreement according to Section 18.6.7.

### 18.6 TLS_EXPORTER SAR AEAD Profile

The `TLS_EXPORTER` SAR AEAD profile defines how SAR derives SAR-layer AEAD keying material from an authenticated TLS-based transport session.

This profile applies to any SAR transport binding that uses TLS and exposes TLS exporter keying material, including:

* SAR-over-QUIC
* SAR-over-TCP when TCP is wrapped in TLS
* future TLS-based SAR transport bindings

This profile MUST NOT be used unless the underlying TLS session has completed successfully and the peer authentication policy required by the application has been satisfied.

For SAR-over-QUIC, the TLS session is the QUIC/TLS session.

For SAR-over-TCP+TLS, the TLS session is the TLS session carried over TCP.


#### 18.6.1 Security Modes

SAR transport bindings using TLS define two SAR-layer security modes:

| Mode                       | Description                                                                                                                                 |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| Transport-only TLS mode    | TLS protects transport bytes. SAR does not derive SAR-layer AEAD keys from TLS exporter material.                                           |
| TLS-exporter SAR-AEAD mode | TLS protects transport bytes, and SAR derives SAR-layer AEAD keying material from TLS exporter material using KMS Mode `0x04 TLS_EXPORTER`. |

TLS-exporter SAR-AEAD mode is RECOMMENDED for SAR-over-QUIC.

Transport-only TLS mode is allowed.

If application policy, profile negotiation, or archive metadata requires TLS-exporter SAR-AEAD mode, endpoints MUST NOT silently downgrade to transport-only TLS mode.

When TLS-exporter SAR-AEAD mode is used, the post-quantum or harvest-now-decrypt-later security of the derived SAR AEAD keying material depends on the negotiated TLS session secrets. Deployments requiring harvest-now-decrypt-later resistance SHOULD configure TLS key agreement policy according to Section 18.6.7.


#### 18.6.2 TLS_EXPORTER KMS Requirements

When KMS Mode `0x04 TLS_EXPORTER` is used:

* the SAR AEAD keying material MUST be derived from TLS exporter material;
* the TLS exporter output MUST NOT be transmitted in SAR frames;
* the derived SAR AEAD key MUST NOT be transmitted in SAR frames;
* SAR KMS Data MUST contain derivation metadata only;
* SAR KMS Data MUST NOT contain raw keys, wrapping keys, TLS exporter output, private keys, or plaintext content-encryption keys;
* the TLS exporter derivation MUST be bound to the SAR session context;
* the selected SAR AEAD algorithm MUST match the derived key length;
* unsupported exporter, KDF, hash, AEAD, or KMS parameters MUST fail closed.

If exporter keying material is unavailable from the TLS stack, implementations MUST return `SAR_ERR_UNSUPPORTED` or `SAR_ERR_KMS_FAILED`.


#### 18.6.3 Exporter Label and Context

The KMS Data for Mode `0x04 TLS_EXPORTER` supplies the TLS exporter label and non-secret derivation parameters used to construct SAR-layer AEAD keying material.

KMS Data is derivation input only. It does not alter, extend, or override the SAR AEAD AAD construction defined in Section 13.2.1.

The exporter label SHOULD be specific to the SAR transport binding profile.

Recommended labels are:

| Binding          | Recommended Exporter Label  |
| ---------------- | --------------------------- |
| SAR-over-QUIC    | `EXPORTER-SAR-v1-QUIC-AEAD` |
| SAR-over-TCP+TLS | `EXPORTER-SAR-v1-TLS-AEAD`  |

The TLS exporter context MUST bind the derived SAR AEAD keying material to the SAR session, transport binding, cryptographic profile, and key usage.

When the Mode `0x04 TLS_EXPORTER` KMS Data field `Context Version` is `0x01`, the TLS exporter context MUST be encoded exactly as follows:

| Order | Field                      | Size | Description                                    |
| ----- | -------------------------- | ---- | ---------------------------------------------- |
| 0     | Context Version            | 1B   | MUST be `0x01`.                                |
| 1     | Transport Profile ID       | 1B   | Transport binding profile identifier.          |
| 2     | SAR Major Version          | 1B   | SAR major protocol version.                    |
| 3     | SAR Minor Version          | 1B   | SAR minor protocol version.                    |
| 4     | Global Header Hash Algo ID | 1B   | Hash algorithm used for Global Header binding. |
| 5     | Global Header Hash Length  | 1B   | Length of Global Header Hash in bytes.         |
| 6     | Global Header Hash         | Var  | Hash of the complete encoded Global Header.    |
| 7     | KMS Mode ID                | 1B   | MUST be `0x04`.                                |
| 8     | AEAD Algo ID               | 1B   | SAR AEAD algorithm ID.                         |
| 9     | Stream ID                  | 2B   | SAR Stream ID, little-endian.                  |
| 10    | Session UUID               | 16B  | Session UUID from `SESSION_INIT`.              |
| 11    | Key Usage ID               | 1B   | Direction or key-usage identifier.             |
| 12    | Salt Length                | 1B   | Length of Salt from KMS Data in bytes.         |
| 13    | Salt                       | Var  | Salt/context bytes from KMS Data.              |

The Global Header Hash MUST be computed over the complete encoded Global Header as transmitted, including KMS Mode ID, KMS Payload Length, and KMS Payload. LFH bytes MUST NOT be included in the Global Header Hash.

The `Global Header Hash Algo ID` in the exporter context MUST be identical to the `Global Header Hash Algo ID` declared in the Mode `0x04 TLS_EXPORTER` KMS Data.

`Global Header Hash Algo ID` MUST reference the SAR hash algorithm registry. If the referenced algorithm is unsupported or reserved, implementations MUST fail closed with `SAR_ERR_UNSUPPORTED` or `SAR_ERR_RESERVED_VALUE` as applicable.

The `AEAD Algo ID`, `Salt Length`, and `Salt` fields in the exporter context MUST be identical to the corresponding fields declared in the Mode `0x04 TLS_EXPORTER` KMS Data.

For `KDF Algo ID = 0x00`, the TLS exporter MUST be invoked with the `Exporter Label`, the encoded TLS exporter context defined by `Context Version`, and an output length equal to `Derived Key Length`. The returned bytes are used directly as SAR AEAD keying material.

Unsupported `Context Version`, `Transport Profile ID`, `Key Usage ID`, `Global Header Hash Algo ID`, `AEAD Algo ID`, or `KDF Algo ID` values MUST fail closed.

Implementations MUST use distinct `Key Usage ID` values for distinct key usages. Implementations MUST NOT reuse the same derived AEAD key for both communication directions unless a future profile explicitly defines a safe bidirectional key schedule.

**TLS_EXPORTER Transport Profile ID Registry**

| ID        | Name             | Description                                                    |
| --------- | ---------------- | -------------------------------------------------------------- |
| 0x01      | SAR_OVER_QUIC    | SAR-over-QUIC profile.                                         |
| 0x02      | SAR_OVER_TCP_TLS | SAR-over-TCP wrapped in TLS.                                   |
| 0x03-0xEF | RESERVED         | Reserved for future standard TLS-based SAR transport profiles. |
| 0xF0-0xFF | CUSTOM           | Implementation-defined transport profiles.                     |

**TLS_EXPORTER Key Usage ID Registry**

| ID        | Name                   | Description                                          |
| --------- | ---------------------- | ---------------------------------------------------- |
| 0x01      | CLIENT_TO_SERVER_ENTRY | SAR entry protection for client-to-server direction. |
| 0x02      | SERVER_TO_CLIENT_ENTRY | SAR entry protection for server-to-client direction. |
| 0x03      | SESSION_CONTROL        | SAR session-control protection, if separately keyed. |
| 0x04-0xEF | RESERVED               | Reserved for future standard key usages.             |
| 0xF0-0xFF | CUSTOM                 | Implementation-defined key usages.                   |

For TLS_EXPORTER key usage, `CLIENT_TO_SERVER_ENTRY` and `SERVER_TO_CLIENT_ENTRY` refer to TLS transport roles, not SAR Sender/Receiver roles.

The TLS client is the endpoint that initiated the TCP+TLS or QUIC connection to the listening endpoint.

The TLS server is the endpoint that accepted the TCP+TLS or QUIC connection and presents the server-side TLS identity.

A SAR entry transmitted by the TLS client MUST use `CLIENT_TO_SERVER_ENTRY`.

A SAR entry transmitted by the TLS server MUST use `SERVER_TO_CLIENT_ENTRY`.

By default, `SESSION_CONTROL` entries MUST use the same directional key usage as ordinary SAR entries sent by the same TLS endpoint.

A `SESSION_CONTROL` entry transmitted by the TLS client therefore uses `CLIENT_TO_SERVER_ENTRY` unless a separate session-control key usage has been explicitly negotiated or mandated by the active transport profile.

A `SESSION_CONTROL` entry transmitted by the TLS server therefore uses `SERVER_TO_CLIENT_ENTRY` unless a separate session-control key usage has been explicitly negotiated or mandated by the active transport profile.

`SESSION_CONTROL` key usage MUST NOT be used unless both endpoints have explicitly negotiated it or the active transport profile mandates it.

Receivers MUST derive and verify using the single key usage selected by the active profile or negotiation. Receivers MUST NOT try multiple key usages to recover from authentication failure.


#### 18.6.4 AAD Requirements

This section does not redefine AAD composition rules.

AAD field selection, encoding, and storage are defined in the SAR AEAD/AAD specification Section 13.2 and apply uniformly across all SAR encryption modes.

When TLS-exporter SAR-AEAD mode is active, those existing AAD rules MUST be applied without modification.

For entries carried on a primary SAR stream, the Global Header portion of AAD is taken from the Global Header physically present on that primary SAR stream.

For entries carried on an additional QUIC control stream that does not contain a physical Global Header, the Global Header portion of AAD MUST be the canonical encoded Global Header bytes of the active SAR session associated with the LFH Stream ID.

For additional QUIC control streams, the LFH portion of AAD MUST be the LFH bytes physically present on that control stream.

An additional QUIC control stream MUST NOT alter or replace the associated session's Global Header bytes, Global Flags, KMS state, transform state, TLS exporter context, or AEAD configuration.

When TLS-exporter SAR-AEAD mode is active, implementations MUST ensure that the TLS-exporter-derived keying context is bound to the SAR session as defined in Section 18.6.3.

Implementations MUST NOT expose plaintext before AEAD authentication succeeds.

A missing, malformed, unsupported, or mismatched AAD context MUST produce a hard error.

`LOSS_TOLERANT` MUST NOT suppress AEAD authentication failures.


#### 18.6.5 TLS-Exporter AEAD Activation and Failure Behavior

Endpoints that support TLS-exporter SAR-AEAD SHOULD advertise `CAP_TLS_EXPORTER_AEAD` in `SESSION_CAPABILITIES`.

Advertising `CAP_TLS_EXPORTER_AEAD` does not select TLS-exporter SAR-AEAD.

KMS Mode `0x04 TLS_EXPORTER`, when selected by the SAR Global Header / KMS configuration, is authoritative for selecting TLS-exporter SAR-AEAD for that SAR stream.

If KMS Mode `0x04 TLS_EXPORTER` is not selected by the SAR Global Header / KMS configuration, endpoints MUST NOT use TLS-exporter SAR-AEAD for that SAR stream.

The TLS exporter secret becomes available only after the underlying TLS session has completed successfully and the TLS peer identity has been validated according to policy.

For SAR-over-QUIC, the underlying TLS session is the QUIC/TLS session.

TLS exporter availability alone is not sufficient to derive SAR AEAD keying material for a SAR session.

SAR TLS-exporter AEAD key derivation also requires:

* the SAR Global Header;
* KMS Mode `0x04 TLS_EXPORTER` parameters;
* Stream ID;
* Session UUID;
* key usage;
* exporter context as defined in Section 18.6.3.

`SESSION_INIT` is the only mandatory SAR-layer plaintext bootstrap entry for KMS Mode `0x04 TLS_EXPORTER` Context Version `0x01`.

`SESSION_INIT` MUST NOT be encrypted with TLS-exporter SAR-AEAD because the Session UUID contained in `SESSION_INIT` is required input to TLS-exporter SAR AEAD key derivation.

If the Global Header selects KMS Mode `0x04 TLS_EXPORTER`, the bootstrap `SESSION_INIT` entry MUST be encoded with Entry Mode Bit 2 (`IS_ENCRYPTED`) unset. Any physically present encryption fields are ignored according to the normal Global Flags / Entry Mode rules.

TLS-exporter SAR-AEAD binding for a SAR session becomes active after all of the following conditions are satisfied:

1. the TLS session is established;
2. the TLS peer identity has been validated according to policy;
3. the SAR Global Header has been parsed and accepted;
4. KMS Mode `0x04 TLS_EXPORTER` parameters have been parsed and accepted;
5. `SESSION_INIT` has successfully bound the Stream ID and Session UUID;
6. TLS exporter material has been obtained from the TLS stack;
7. SAR AEAD keying material has been derived successfully for the relevant key usage.

After TLS-exporter SAR-AEAD binding becomes active, every subsequent SAR entry in that session MUST be encrypted and authenticated with the derived SAR AEAD keying material.

This requirement applies to Filesystem Mode entries, Session Mode entries, `SESSION_CONTROL` entries, entries carried on the primary SAR stream, and entries carried on additional QUIC control streams.

An unencrypted SAR entry received after TLS-exporter SAR-AEAD binding is active MUST fail closed.

By default, `SESSION_CONTROL` entries use the same directional key usage as ordinary SAR entries sent by the same TLS endpoint, as defined in Section 18.6.3.

Additional QUIC control streams opened after TLS-exporter SAR-AEAD binding is active inherit the associated session's Global Header, KMS state, TLS exporter context, AEAD configuration, and active key usage rules.

If KMS Mode `0x04 TLS_EXPORTER` is selected and an endpoint does not support it, the endpoint MUST fail closed with `SAR_ERR_UNSUPPORTED`, `SAR_ERR_KMS_FAILED`, or the closest applicable transport error.

If bidirectional control is available, the endpoint SHOULD transmit `SESSION_STATUS` before terminating the session.

If bidirectional control is not available, the endpoint MUST terminate or reject the affected stream or connection according to the transport binding.

Failure at any required step MUST prevent decryption and MUST NOT expose plaintext.

Implementations MUST NOT silently downgrade from required TLS-exporter SAR-AEAD mode to transport-only TLS mode.

If an implementation or application policy requires every SAR entry, including `SESSION_INIT`, to be independently protected by SAR-layer AEAD, this requirement cannot be satisfied by KMS Mode `0x04 TLS_EXPORTER` Context Version `0x01`. Such a policy requires a future bootstrap or pre-shared session context profile.


#### 18.6.6 Prohibited Behavior

Implementations MUST NOT:

* transmit SAR content-encryption keys in `SESSION_*` messages;
* transmit TLS exporter output in SAR frames;
* place plaintext keys in KMS Data;
* treat Session UUIDs as authentication secrets;
* derive SAR AEAD keys without binding them to the SAR session context;
* reuse exporter-derived SAR AEAD keys across independent sessions unless explicitly allowed by a future rekey profile;
* expose plaintext before AEAD authentication succeeds;
* allow `LOSS_TOLERANT` to suppress AEAD failures;
* silently downgrade from required TLS-exporter SAR-AEAD mode to transport-only TLS mode.

#### 18.6.7 Post-Quantum and Hybrid TLS Key Agreement Policy

This section applies to SAR transport bindings that use TLS, including SAR-over-QUIC and SAR-over-TCP when TCP is wrapped in TLS.

TLS key agreement policy determines which TLS key agreement algorithms may be offered, negotiated, accepted, and used before TLS exporter material is used for SAR AEAD key derivation.

For purposes of this section:

* a **post-quantum-safe TLS key agreement** is a TLS key agreement mechanism based on a post-quantum algorithm accepted by the active transport policy;
* a **hybrid post-quantum TLS key agreement** combines a classical key agreement component with a post-quantum key agreement or KEM component;
* a **classical TLS key agreement** is a non-post-quantum key agreement mechanism, such as ECDHE over a classical elliptic-curve group.

Examples of hybrid post-quantum TLS key agreement mechanisms include `X25519MLKEM768`. This example is non-exclusive and MUST NOT be treated as permanently preferred by this specification.

SAR TLS transport implementations SHOULD expose policy controls equivalent to the following modes:

| Policy Mode            | Requirement                                                                                                                                                                                                                                     |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `CLASSICAL_ALLOWED`    | Classical, hybrid post-quantum, and post-quantum-safe TLS key agreement algorithms MAY be used when supported by the TLS stack and allowed by local policy.                                                                                     |
| `PREFER_PQ`            | Post-quantum-safe or hybrid post-quantum TLS key agreement SHOULD be preferred when available. Classical TLS key agreement MAY be used if no acceptable post-quantum-safe or hybrid algorithm can be negotiated.                                |
| `REQUIRE_PQ_OR_HYBRID` | The TLS session MUST negotiate a post-quantum-safe or hybrid post-quantum TLS key agreement accepted by policy. Classical-only key agreement MUST fail closed.                                                                                  |
| `REQUIRE_PQ_ONLY`      | The TLS session MUST negotiate a post-quantum-safe TLS key agreement accepted by policy. Hybrid or classical-only key agreement MUST fail closed unless local policy explicitly classifies a specific hybrid algorithm as satisfying this mode. |

When constructing TLS supported-group, key-share, or equivalent key-agreement configuration, implementations MUST omit algorithms disallowed by the active transport policy.

When multiple allowed algorithms are supported by the TLS stack, implementations SHOULD order the candidate list according to the active transport policy.

Unless local policy specifies a different order, implementations SHOULD prefer allowed algorithm classes in this order:

1. post-quantum-safe TLS key agreement;
2. hybrid post-quantum TLS key agreement;
3. classical TLS key agreement.

This ordering defines preference among allowed candidates only. It does not require support for every class and does not permit offering algorithms disabled by policy.

If policy requires post-quantum-safe or hybrid post-quantum TLS key agreement and the TLS stack cannot configure, negotiate, or confirm an acceptable key agreement, the connection MUST fail closed before TLS exporter material is used for SAR AEAD key derivation.

If the TLS stack exposes the negotiated key agreement group or equivalent classification, implementations enforcing `REQUIRE_PQ_OR_HYBRID` or `REQUIRE_PQ_ONLY` MUST verify that the negotiated value satisfies policy before using TLS exporter material for SAR AEAD key derivation.

If the TLS stack does not expose enough information to verify the negotiated key agreement, implementations MUST NOT claim post-quantum-safe or hybrid protection. If policy requires such protection, the connection MUST fail closed.

Implementations MUST NOT silently downgrade from a required post-quantum-safe or hybrid post-quantum TLS key agreement to a classical-only TLS key agreement.

When TLS-exporter SAR-AEAD mode is used, the SAR AEAD keying material inherits the harvest-now-decrypt-later properties of the negotiated TLS session secrets.

If the underlying TLS session negotiated a classical-only key agreement, TLS-exporter SAR-AEAD MUST NOT be described as post-quantum-safe or harvest-now-decrypt-later resistant.

If the underlying TLS session negotiated a post-quantum-safe or hybrid post-quantum key agreement accepted by policy, TLS-exporter SAR-AEAD MAY be described as providing the corresponding post-quantum or hybrid harvest-now-decrypt-later protection for SAR-layer AEAD keying material.

TLS certificate authentication and TLS key agreement are separate security properties.

Classical certificate authentication algorithms, including RSA and ECDSA, MAY remain supported while accepted by local policy. Such certificate algorithms authenticate peer identity but do not by themselves provide post-quantum confidentiality for recorded TLS sessions.

A TLS session using post-quantum or hybrid key agreement with a classical certificate algorithm MAY provide post-quantum or hybrid confidentiality for session secrets, subject to the negotiated key agreement and TLS stack.

A TLS session using post-quantum certificate authentication with classical-only key agreement MUST NOT be described as providing post-quantum harvest-now-decrypt-later protection for session confidentiality.

The negotiated TLS key agreement algorithm is transport security state. It MUST NOT be encoded as secret SAR payload data, MUST NOT be placed in KMS Data as a secret, and MUST NOT be used to bypass SAR AEAD, AAD, KMS, signature, hash, or transformation-ordering requirements.

Implementations MAY record the negotiated TLS key agreement algorithm or policy classification in non-secret diagnostics or audit metadata, provided doing so does not expose TLS secrets, exporter output, derived SAR AEAD keys, private keys, or plaintext payload.


## 19. Archive Partitioning and File Fragmentation
This section formalizes how SAR handles data that is physically or logically non-contiguous.

### 19.1 Archive Partitioning (Multi-part Archives)
When `PARTITIONED_ARCHIVE` (Global Bit 3) is set, a logical SAR archive is split across multiple physical `.sar` files.
* **Global Header**: Every physical file MUST contain the same Global Flags.
* **Central Dictionary**: Only the **final partition** contains the Central Dictionary and Footer.
* **Cross-Partition Offsets**: If `64BIT_SIZE` is active, offsets in the CD are absolute across the entire logical set (treating all files as one continuous byte-stream).

### 19.2 File Fragmentation (Multiplexing)
When `FILE_FRAGMENTATION` (Global Bit 4) is set, a single file (e.g., `video.mp4`) can be broken into $N$ fragments. This is critical for real-time streaming where large assets must be interleaved with control commands or other data.

#### 19.2.1 Fragment Identification
Each fragment of the same file MUST share the same **Fragment ID** LFH field value.
* **Fragment Index**: A 0-based monotonic counter. The receiver uses this to reassemble the bytes in the correct order.
* **Name/Path Persistence**: Only the first fragment (Index 0) is REQUIRED to carry the `Name String` and `Path String`. Subsequent fragments SHOULD set `Name Length` to 0 to save bandwidth, as the `Fragment ID` serves as the primary lookup.

#### 19.2.2 Reassembly Logic
A receiver encountering `IS_FRAGMENT` (Entry Mode Bit 5) MUST:
1. Check its local reassembly buffer for the `Fragment ID`.
2. Append the `Payload Data` to the buffer at the position dictated by `Fragment Index`.
3. If `LAST_FRAGMENT` (Bit 6) is encountered, the file is considered complete.
4. Perform `File CRC32` or `Content Hash` verification only **after** the final fragment is joined. If `LOSS_TOLERANT` is active, the `SAR_WARN_INCOMPLETE` status SHOULD be used to signal that the file was committed despite a hash mismatch.

### 19.3 Streaming Considerations
In e.g. a real-time dia-show application, the sender might stream `image_01.jpg`, then start streaming `background_audio.mp3` in fragments while `image_02.jpg` is being prepared. This allows the application to begin playing the audio before the entire file has arrived, while still allowing other small files to "jump the queue" in the stream.

## 19.4 Fragmentation & Partitioning Error Handling
Managing non-contiguous data requires the Receiver to act as a stateful buffer manager. This section defines the mandatory error recovery logic.

### 19.4.1 Reassembly Timeouts (The "Dead-Drop" Rule)
In `FILE_FRAGMENTATION` mode (Global Bit 4), the Receiver MUST implement a **Fragment TTL (Time To Live)**.
* **Problem**: A Sender starts a 4GB transfer in fragments but crashes after fragment 10. Without a timeout, the Receiver's memory remains "poisoned" with an incomplete reassembly buffer.
* **Requirement**: If no new fragment for a specific `Fragment ID` arrives within a set window (default 60s), the Receiver SHALL discard the buffer and return `SAR_ERR_FRAGMENT_TIMEOUT` (17).

### 19.4.2 Out-of-Order Handling
While the **Sequence No** field ensures transport-layer sanity, the **Fragment Index** field allows the logical file to be reassembled even if fragments are interleaved with other files.
* **Requirement**: If a fragment arrives with a `Fragment Index` that creates a gap, the Receiver SHOULD buffer subsequent indices and wait for the missing parts.
* **Critical Failure**: If `LAST_FRAGMENT` (Bit 6) arrives while gaps exist in the index sequence, the Receiver MUST return `SAR_ERR_FRAGMENT_GAP` (14) **UNLESS Bit 7 (`LOSS_TOLERANT`) is set**.

### 19.4.3 Resource Exhaustion & DoS Protection
Fragmentation is a potential vector for a **"Memory Exhaustion Attack"** (where a malicious sender starts thousands of fragmented transfers but never sends the `LAST_FRAGMENT`).
* **The "Concurrency Cap"**: Implementations SHOULD limit the number of concurrent "Active Fragments" they will track. If a new `Fragment ID` arrives that exceeds this limit, the Receiver SHALL return `SAR_ERR_REASSEMBLY_BUFFER_FULL` (15).

### 19.4.4 Partition Discovery, Verification, and Recovery

For `PARTITIONED_ARCHIVE` mode (Global Bit 3), Receivers MUST verify that all partitions belong to the same logical archive set before processing archive payloads.

#### Partition Association

Partitions MUST be associated using the Partition Descriptor defined in Section 5.

All partitions belonging to the same archive set MUST:

* Contain the same `Partition Set UUID`.
* Declare a unique `Partition Index`.
* Declare the same `Total Partitions` value.

Matching filenames, archive names, Magic values, or Global Flags alone MUST NOT be treated as sufficient proof that partitions belong to the same archive set.

Filesystem-based partition sets SHOULD use deterministic names of the form:

`[Archive_Name].sar.[3-byte zero-padded index]`

Implementations MUST NOT rely on filenames as the sole mechanism for partition discovery or verification.

#### Partition Integrity Verification

Partition integrity SHOULD be verified before extraction begins.

Verification MAY be performed using:

* Digital Signatures when the `SIGNED` flag is present.
* Partition Hash and Previous Partition Hash values contained within the Partition Descriptor.
* Archive-wide integrity mechanisms defined elsewhere in this specification.

Partition 0 MUST contain a zero-filled `Previous Partition Hash`.

Receivers MUST verify that all discovered partitions form a continuous and valid partition chain.

#### Incomplete Partition Sets

If one or more required partitions are unavailable, the Receiver MUST return `SAR_ERR_PARTITION_MISSING`.

Extraction SHOULD NOT begin until all required partitions have been located and verified.

#### Degraded Recovery Mode

Implementations MAY provide an application-controlled degraded recovery mode.

In degraded recovery mode, available partitions MAY be processed sequentially without relying on the final Central Dictionary.

When degraded recovery mode is used:

* Missing partitions MUST result in `SAR_WARN_INCOMPLETE`.
* Entries spanning unavailable partitions MUST be skipped.
* Integrity verification MUST be limited to metadata available within the recovered partitions.
* Implementations MUST NOT claim successful archive reconstruction if one or more required partitions are unavailable.

The use of degraded recovery mode is implementation-defined and MUST NOT be enabled implicitly.


### 19.4.5 Lossy Reassembly and Best-Effort Streaming
When the `LOSS_TOLERANT` flag (Bit 7) is active, SAR transitions to a "continuity-first" delivery model suitable for temporal data (audio, video, telemetry).
1. **Gap-Filling**: Upon receipt of the `LAST_FRAGMENT`, any missing indices SHALL be filled with **Null Bytes (0x00)** or maintained as unwritten regions in a sparse file.
2. **Integrity Bypass**: If gaps are present, a hash mismatch is expected. If Bit 7 is set, a failed `File CRC32` or `Content Hash` SHOULD NOT be treated as a fatal error. The Receiver SHALL commit the data and return `SAR_WARN_INCOMPLETE` (18).
3. **Out-of-Order Discard**: In time-sensitive streaming, if a "belated" fragment arrives after the file has already been committed or played, the Receiver MAY discard it without error.
4. **Authentication Preservation**: `LOSS_TOLERANT` applies only to missing, late, truncated, or otherwise unavailable data. It MUST NOT permit processing of payload data that fails cryptographic authentication. If AEAD authentication fails for an encrypted fragment or entry, the affected data MUST be discarded. Implementations MAY continue processing subsequent fragments, entries, or stream data when `LOSS_TOLERANT` is set, but MUST NOT expose, reconstruct, decode, decompress, patch, execute, or otherwise process unauthenticated payload contents.

## 19.5 Fragmentation Strategies
For large fragmented files, Receivers SHOULD NOT reassemble entirely in RAM.
* **Strategy**: When a `Fragment ID` is first encountered, the Receiver creates a **Sparse Shadow File** on disk.
* **Action**: Each incoming fragment is `seek()`ed to its correct offset based on `Fragment Index * Fragment_Size` and written directly.
* **Result**: This allows for reassembling 100GB files without consuming 100GB of RAM, leveraging the **Sparse File Logic (Section 17)** we already established.

### 19.6 Sparse File Interaction
When both `SPARSE_FILES` (Bit 30) and `FILE_FRAGMENTATION` (Bit 4) are active, the following rules apply:

1. **Global Scope**: The Sparse Map describes the layout of the fully reconstructed file, not individual fragments.
2. **Fragment Constraints**: Individual fragments MUST NOT contain independent Sparse Maps. The Sparse Map MUST be present only in the first fragment (Fragment Index 0).
3. **Reassembly Requirement**: The Receiver MUST first reassemble all fragments into a logical contiguous payload before applying Sparse Map reconstruction.
4. **Streaming Optimization (Optional)**: Implementations MAY apply sparse reconstruction incrementally during fragment arrival, provided correctness is maintained.
5. **Integrity Verification**: All integrity checks (CRC32, Content Hash) MUST be performed on the fully reconstructed sparse file.

## 20. Content-Defined Chunking (CDC) Protocol
Content-Defined Chunking allows SAR to utilize deduplication by representing files as "Recipes" of unique data blocks (chunks).

### 20.1 Selective Deduplication (Literal vs. Recipe)
If `CDC_SUPPORT` (Bit 5) is active globally, every LFH MUST be evaluated based on its `CDC Algo ID`:

1. **Literal Mode (`0x00`)**: The transformation pipeline (Section 13.1) treats the payload as the actual logical file data. This is REQUIRED for high-entropy content (e.g., encrypted video streams) where deduplication provides no benefit.
2. **Recipe Mode (`> 0x00`)**: The payload is interpreted as a **Hash Recipe**. Each hash in the payload refers to a unique chunk stored in a **Catalog**.

### 20.2 The Hash Recipe Structure
In Recipe Mode, the `Payload Data` (after decryption and decompression) MUST be parsed as a contiguous array of binary hashes.

* **Hash Algorithm**: The length and type of hashes in the recipe are determined by the `DEDUPLICATION` (Bit 29) setting.
* **Logical Continuity**: The order of hashes in the payload defines the exact byte-sequence of the reconstructed file.

### 20.3 Recipe Resolution and Transformation
The `CDC Algo ID` is the final stage of the decoding pipeline.

1. **Pipeline Resolution**: Apply Decrypt, Decompress, and Patch to the payload as defined in Section 13.7.4.
2. **Recipe Interpretation**: The resulting byte-block is the Recipe.
3. **Chunk Fetching**: The implementation SHALL iterate through the hashes in the Recipe, retrieving the corresponding bytes from either:
    * A local SAR **CDC_MAP** (Central Dictionary TLV).
    * An external Content-Addressable Storage (CAS) database.
4. **Final Reassembly**: Chunks are appended to the logical file.

## 21. CDC Cataloging and Metadata

SAR CDC processing uses the LFH `CDC Algo ID` field to identify the chunking algorithm for an entry. The CDC algorithm registry is defined in **Section 8.5, CDC Algorithms (****`SAR_L_CDC`****)**.

CDC cataloging and recipe-resolution metadata is carried in Metadata TLVs from the `0x40-0x4F` range. The CDC metadata TLV registry is defined in **Section 9.5, CDC Metadata (ID ****`0x40-0x4F`****)**.

To resolve Recipes, SAR implementations require a Catalog mapping content hashes to physical byte locations or to an external provider.

### 21.1 Central Dictionary CDC Map (`CDC_MAP`)

For self-contained archives, the Catalog is stored as a Metadata TLV block in the Central Dictionary using the CDC metadata TLV Type ID assigned in Section 9.5.

* **TLV Type ID**: `0x40` (`CDC_MAP`)
* **Structure**: A 16-byte `CDC_MAP_Header` followed by `Record_Count` 48-byte `CDC_MAP_Record` entries.
* **Requirement**: If `CDC_SUPPORT` is enabled and `NO_INDEX` is not set, this TLV SHOULD be present.
* **Verification Scope**: Structural validation of stored CDC metadata is always permitted. Hash verification over stored byte ranges is permitted when the hash algorithm is supported and archive bounds are available.

`CDC_MAP` is **self-describing** via the `Hash_Algorithm_ID` field in its header.  Parsers MUST read `Hash_Algorithm_ID` from the header to determine which hash algorithm is used for record hashes.  Parsers MUST NOT hard-code an unnamed hash algorithm or treat the LFH `CDC Algo ID` (chunking algorithm) as the hash algorithm for CDC_MAP records.

FASTCDC determines chunk *boundaries*.  `Hash_Algorithm_ID` determines how chunk *hashes* are computed.  These are independent.

#### CDC_MAP TLV v1 value layout

```text
CDC_MAP_Header (16 bytes) || CDC_MAP_Record[Record_Count] (Record_Count × 48 bytes)
```

TLV Length MUST equal `16 + Record_Count × Record_Size`.  Both the multiplication and the addition MUST use checked arithmetic.  All multi-byte fields are little-endian.

#### CDC_MAP_Header v1 (16 bytes)

| Field               | Size    | Description                                                           |
| ------------------- | ------- | --------------------------------------------------------------------- |
| `Map_Version`       | 1 byte  | MUST be `0x01`.                                                       |
| `Hash_Algorithm_ID` | 1 byte  | SAR hash algorithm registry ID used for all record hashes.            |
| `Flags`             | 2 bytes | MUST be zero for v1. Non-zero bits are reserved and MUST be rejected. |
| `Record_Count`      | 4 bytes | Number of records following the header.                               |
| `Record_Size`       | 2 bytes | MUST be `48` for v1 with 32-byte hashes.                              |
| `Reserved`          | 6 bytes | MUST be zero when written and MUST be rejected when read.             |

#### CDC_MAP_Record v1 (48 bytes)

| Field             | Size     | Description                                                                     |
| ----------------- | -------- | ------------------------------------------------------------------------------- |
| `Hash`            | 32 bytes | Hash of the referenced chunk bytes using `Hash_Algorithm_ID`.                   |
| `Partition_ID`    | 4 bytes  | Partition identifier containing the referenced chunk.                           |
| `Absolute_Offset` | 8 bytes  | Absolute byte offset of the referenced chunk from the beginning of the archive. |
| `Compressed_Size` | 4 bytes  | Size in bytes of the referenced stored chunk payload.                           |

#### CDC_MAP hash algorithm registry

`Hash_Algorithm_ID` uses the SAR hash algorithm registry (Section 9.4).

#### CDC_MAP structural validation

Structural validation MAY always be performed and includes:

* TLV length is at least 16;
* `Map_Version` is supported;
* `Flags` are zero;
* `Reserved` bytes are zero;
* `Record_Size` is correct;
* TLV Length equals `16 + Record_Count × Record_Size`;
* all arithmetic is checked;
* `Hash_Algorithm_ID` is in the registry.

#### CDC_MAP hash verification

Hash verification MAY be performed only if:

* `Hash_Algorithm_ID` is supported;
* the referenced byte range `[Absolute_Offset, Absolute_Offset + Compressed_Size)` is readable;
* archive bounds are available.

`Absolute_Offset + Compressed_Size` MUST use checked arithmetic and MUST be within archive bounds when archive bounds are available.

CDC_MAP hash verification is over the exact stored byte range `[Absolute_Offset, Absolute_Offset + Compressed_Size)`.  This is **not** the same as FASTCDC boundary-regeneration verification.

A parser does not require knowledge of the CDC chunking algorithm (as defined by the LFH `CDC Algo ID` in Section 8.5) to parse the `CDC_MAP` structure itself. The CDC algorithm determines how chunks are produced, but the `CDC_MAP` is a catalog of already materialized chunk metadata.


### 21.2 External Database Integration (`CDC_EXT_PROVIDER`)

In distributed environments, such as Edge-to-Cloud streaming, the Catalog MAY be maintained externally.

* **TLV Type ID**: `0x41` (`CDC_EXT_PROVIDER`)
* **Value**: A UTF-8 URI string pointing to the external chunk provider, for example `sarp+https://chunks.provider.net/v1`.
* **Constraint**: If an external provider is used, the implementation MUST ensure its availability. If a hash in a Recipe cannot be resolved, the implementation MUST return `SAR_ERR_RECIPE_UNRESOLVABLE` (`19`).

**Security Considerations**: The use of external provider URIs introduces potential security risks, including unauthorized data access, data exfiltration, or interaction with untrusted endpoints. Implementations SHOULD validate and sanitize all URIs before use. Implementations MAY restrict acceptable URI schemes, enforce allowlists of trusted domains, or apply other policy controls in an implementation-defined manner. Implementations SHOULD provide mechanisms to disable external provider resolution entirely or require explicit user consent before accessing external resources.

Implementations MUST NOT emit `CDC_EXT_PROVIDER` using TLV Type ID `0x31`, because `0x31` is assigned to `DATA_HASH/BLAKE3` by Section 9.4.

### 21.3 Hybrid Deduplication Performance

Implementations SHOULD utilize Selective Deduplication to optimize streaming throughput.

* **Intros/Outros/Ads**: Marked with `CDC Algo ID > 0`. These are pulled from the local edge cache via the Recipe.
* **Movie/Main Content**: Marked with `CDC Algo ID = 0x00`. These flow as Literal Mode data, avoiding the CPU overhead of fingerprinting or catalog lookups.


## 22. Implementation and Developer Guidance
### 22.1 Memory and I/O Optimization
* **Memory Mapping**: For random-access archives, implementations SHOULD use memory-mapped files (`mmap`) to access the Data Area. This allows the OS to handle caching and significantly improves performance during Central Dictionary lookups.
* **Packed Structs**: Because SAR headers are "packed" without alignment padding, C/C++ developers SHOULD use `#pragma pack(push, 1)` or `__attribute__((packed))` to ensure the binary structure matches the specification.

### 22.2 Sparse File Handling
see section 17.4

### 22.3 Fragmentation Strategies
see sections 19.4 and 19.5

### 22.4 Path Security

Before materializing an Entry, an implementation MUST derive its destination from the selected Extraction Root or explicitly authorized installation scope and the Entry's Full Logical Entry Path.

Archive or stream metadata MUST NOT override the selected scope.

Every filesystem mutation performed during materialization MUST remain within the selected scope.

Implementations MUST account for pre-existing symbolic links, symbolic links created by earlier Entries, path-component replacement, and other filesystem behavior that could redirect a mutation outside the selected scope. Lexical path validation alone is insufficient.

If an Entry destination escapes the selected scope, or confinement cannot be established, the implementation MUST return `SAR_ERR_PATH_ESCAPE` and MUST NOT perform the affected mutation.

The destination of a symbolic-link object and its stored target MUST be evaluated separately.

A relative symbolic-link target SHALL be evaluated lexically from the directory containing the symbolic-link object. The target is not required to exist.

If the lexical result escapes the selected scope, the implementation MUST return `SAR_ERR_PATH_ESCAPE` and MUST NOT create the symbolic link.

An absolute or platform-specific symbolic-link target remains valid archive metadata. Ordinary materialization MUST return `SAR_ERR_PATH_ESCAPE` if the target is outside the selected scope or its confinement cannot be established.

A materializer MUST NOT rewrite a symbolic-link target to make it conform to local security policy.

Later filesystem operations performed by the materialization operation MUST NOT follow a materialized or pre-existing symbolic link outside the selected scope.

Ordinary extraction or state application MUST fail if a selected Entry cannot be safely materialized.

Skipping a selected Entry MUST NOT be enabled by default or selected implicitly.

An implementation MAY skip a selected Entry only when the caller explicitly selected best-effort or other incomplete behavior before the skip condition occurred.

Such an operation MUST:

* identify skipped Entries;
* report the operation as incomplete; and
* not report complete extraction or state-application success.

If two distinct Full Logical Entry Paths map to the same destination filesystem object, the implementation MUST return `SAR_ERR_PATH_COLLISION`.

Such collisions include those caused by case folding, Unicode normalization, reserved-name handling, trailing-dot or trailing-space handling, separator conversion, path aliases, or other destination filesystem behavior.

Host-specific pathname restrictions do not make an otherwise conforming Full Logical Entry Path malformed.

An implementation MUST NOT resolve a path collision by silently renaming, merging, discarding, or rewriting either Entry.

Repeated occurrences of the same Full Logical Entry Path are not path collisions and are governed by Section 6.1.5.

Actual filesystem or host API failures not otherwise covered by this section MUST return `SAR_ERR_IO` or another more specific applicable error.

`SYSTEM_INSTALL` operations SHOULD require administrative privileges and SHOULD verify digital signatures (`SIGNED` Bit 18) before modifying system directories.

### 22.5 Transport and Session Sanity
* **Sequence Wraparound**: The 2-byte Sequence No wraps at 65.535. This is sufficient for detecting stream desync but is not a substitute for TCP sequence numbers.
* **AEAD Recommendation**: For replication over untrusted networks, the use of AEAD (Bit 10) is strongly recommended to protect both metadata (LFH) and session control commands (UUIDs)..

### 22.6 Listing and Verbosity Modes
Implementations SHOULD provide three standard levels of archive inspection for the user:

| Mode | Name | Description |
| --- | --- | --- |
| 0x00 | `NAMES_ONLY` | Fastest mode; only parses `Name` fields from CD or LFH. Ideal for quick index generation. |
| 0x01 | `METADATA` | Parses names, uncompressed sizes, path information, and timestamps. Suitable for standard views. |
| 0x02 | `TECHNICAL` | Exhaustive parse; includes absolute offsets, algorithm IDs, internal KMS metadata, and all TLV data blocks. |

### 22.7 Random Access
The `MetaSize` field in the Central Dictionary enables jumping to the offset array, bypassing variable-length metadata blocks. Implementations SHOULD use memory-mapped files (mmap) for the Data Area to leverage OS-level caching during random-access operations.

### 22.8 AEAD and Hijack Resistance
In streaming mode over untrusted networks, requiring the `ENCRYPTED` flag (Bit 10) to be enabled with an AEAD-capable algorithm is strongly recommended. This ensures that the `SESSION_INIT` and `SESSION_RESUME` payloads (UUIDs) are authenticated. Without AEAD, the protocol relies entirely on transport-layer security or network isolation to prevent session hijacking.

## Appendix A. Byte-Level LFH Example: Encrypted Fragment
The following represents a single LFH entry for **Fragment Index 1** of a larger logical file. Note that because this is not the first fragment, the `Name` and `Path` strings are omitted (Length = 0), leveraging the `Fragment ID` for reassembly.

This example assumes the following global flags are active: `ENCRYPTED` (Bit 10), `FILE_FRAGMENTATION` (Bit 4), and `HAS_PATH` (Bit 24). The `64BIT_SIZE` flag is NOT set, so standard size/offset LFH fields are 4 bytes.

### A.1. Hexadecimal Representation
```text
Offset       Byte Values (Hex)                        Description
-------------------------------------------------------------------------------------------------------
00000000     43 00 00 00                              Header Size: 67 bytes (4B)
00000004     24 00                                    Entry Mode: IS_ENCRYPTED | IS_FRAGMENT (2B)
00000006     05 00                                    Stream ID: 0x0005 (2B)
00000008     2A 00                                    Sequence No: 42 (0x002A) (2B)
0000000A     00 28 00 00                              Uncompressed Size: 10240 bytes (4B)
0000000E     00 04 00 00                              Payload Size: 1024 Bytes (4B)
00000012     04                                       Encr Algo ID: XCHACHA20_POLY (0x04) (1B)
00000013     DE AD C0 DE                              Fragment ID: 0xDEADC0DE (4B)
00000017     01 00 00 00                              Fragment Index: 1 (4B)
0000001B     00 08 00 00 00 00 00 00                  Frag Desc: Absolute Offset (2048) (8B)
00000023     00 04 00 00                              Frag Desc: Fragment Size (1024) (4B)
00000027     FF EE DD CC BB AA 99 88                  IV / Nonce (Bytes 1-8)
0000002F     77 66 55 44 33 22 11 00                  IV / Nonce (Bytes 9-16)
00000037     A1 B2 C3 D4 E5 F6 A7 B8                  IV / Nonce (Bytes 17-24) [Total: 24B]
0000003F     00 00                                    Name Length: 0 (Deferred) (2B)
00000041     00 00                                    Path Length: 0 (Deferred) (2B)
00000043     [... 1024 Bytes of Payload ...]          Encrypted & Fragmented Data
```


### A.2. Field Breakdown and Logic
| Field | Value | Logic / Invariant |
| --- | --- | --- |
| **Header Size** | `0x43` (67) | Byte count from start of LFH to the byte immediately before `Payload Data`. Derived from active global flags. |
| **Entry Mode** | `0x0024` | Bits 2 and 5 set. Signals AEAD verification is required and this is a partial file piece. |
| **Stream ID** | `0x0005` | Matches the active session handle established via `SESSION_INIT`. |
| **Sequence No** | `0x002A` | Monotonic heartbeat; must be exactly `Previous_Seq + 1`. |
| **Uncompressed Size** | `10240` | Total reconstructed size of the complete logical file (not this fragment alone). |
| **Payload Size** | `1024` | Defines the actual byte-count to read from the stream after the header. |
| **Encr Algo ID** | `0x04` | XChaCha20-Poly1305. The parser must use the IV below for the AEAD tag verification. |
| **Fragment ID** | `0xDEADC0DE` | Unique identifier linking this payload to the reassembly buffer for this file. |
| **Fragment Index** | `1` | Informs the Scatter-Gather logic that this is the second block of the file. |
| **Fragment Descriptor** | `Offset: 2048, Size: 1024` | **Crucial:** Directs the receiver to write the decrypted payload starting at byte 2048 of the logical file. |
| **Name Length** | `0` | Since `Fragment Index > 0`, the name is already known by the receiver's state machine. |
| **Path Length** | `0` | Evaluated conditionally based on the `HAS_PATH` global bitmask. |
### A.3. Transformation Pipeline Execution
To process the payload in the example above, the implementation must follow the **Canonical Decoding Order** (Section 13.7.4):

1. **Read Payload**: Consume 1024 bytes following the header.
2. **Decrypt**: Apply XChaCha20-Poly1305 with the provided IV and the Master Key (from KMS). Verify the Poly1305 tag.
3. **Decompress**: If the logical file is compressed (check `Fragment Index 0` state), decompress the decrypted block.
4. **Position**: Move the file pointer of the target resource (File ID `0xDEADC0DE`) to logical offset `2048`.
5. **Commit**: Write the transformed data to the target resource.


### A.4. Implementation Note: Native 64-bit Addressing for Fragment Descriptors
Note that the `Fragment Descriptor` strictly utilizes a full 8-byte (64-bit) Absolute Offset and a 4-byte (32-bit) Fragment Size, regardless of whether the global `64BIT_SIZE` flag is toggled for standard file metrics.

This is an intentional protocol design decision that guarantees:

* **Exabyte-Scale Future Proofing:** The protocol natively supports reassembling individual logical files up to 16 Exabytes ($2^{64}$ bytes) without requiring architecture-breaking revision changes.
* **CPU-Native Alignment:** 64-bit runtime environments (x86_64, ARM64) can parse, cast, and map the absolute offsets directly into registers using single-cycle CPU instructions.
* **Reduced Metadata Bloat:** A fragment size of 4 bytes allows individual data fragments to scale up to 4 GB. This drastically decreases the absolute number of required fragments for large datasets, minimizing LFH wrapper overhead across the archive.
