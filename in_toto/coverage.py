# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  coverage.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>
  Santiago Torres-Arias <santiago@nyu.edu>

<Started>
  June 28, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>

  Data structures for strict artifact coverage verification.

  Regular in-toto verification (see ``in_toto.verifylib.in_toto_verify``)
  applies the artifact rules of a layout like a firewall: rules consume
  artifacts from a queue and verification only fails if a terminal DISALLOW
  or REQUIRE rule is not satisfied. This tells the caller that "no rule was
  violated", but it does not tell *which rule authorized which artifact*.

  This module provides the immutable result types for an optional strict
  coverage verification (see
  ``in_toto.verifylib.in_toto_verify_coverage``) that records, for every
  consumed material and product, a per-artifact proof:

  - in which step or inspection (and, for delegated steps, in which
    sublayout scope) the artifact was consumed,
  - whether it was consumed from the item's materials or products,
  - which original rule (and its index in the layout's rule list)
    authorized the consumption,
  - which prefix transformations were applied and which verified link was
    matched (for MATCH rules),
  - and which digests were compared.

  Only artifacts that are actually reported by a verified link and that
  satisfy the rule (e.g. hash equality for MATCH) are consumed and
  recorded. Artifacts consumed by a wildcard ALLOW rule are recorded as
  such (``binding="wildcard"``) and are explicitly *not* presented as
  hash-bound.

  In strict mode every artifact reported by a verified link must end up
  with such a proof, otherwise verification fails with
  ``in_toto.exceptions.CoverageError``. Rules are never auto-appended
  (e.g. no implicit ``ALLOW *``) to make coverage pass.

"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, Optional, Tuple

#: An immutable representation of an artifact hash dictionary, i.e. a
#: sorted tuple of (algorithm, digest) pairs.
FrozenHashes = Tuple[Tuple[str, str], ...]

#: Binding kinds that explain on what grounds an artifact was consumed.
#:
#: "hash":
#:     A MATCH rule compared the digests of the source artifact and a
#:     destination artifact reported by another verified link.
#: "hash-difference":
#:     A MODIFY rule compared the digests of the artifact in the item's
#:     materials and products and found them different.
#: "set-membership":
#:     A CREATE or DELETE rule authorized the artifact based on its
#:     presence in/absence from the item's materials and products.
#: "wildcard":
#:     An ALLOW rule authorized the artifact by pattern only. No digest
#:     comparison was performed and the consumption is not hash-bound.
BINDING_HASH = "hash"
BINDING_HASH_DIFFERENCE = "hash-difference"
BINDING_SET_MEMBERSHIP = "set-membership"
BINDING_WILDCARD = "wildcard"


def freeze_hashes(hash_dict: Optional[dict]) -> Optional[FrozenHashes]:
    """Return an immutable sorted tuple of (algorithm, digest) pairs for a
    hash dictionary, or None if None is passed."""
    if hash_dict is None:
        return None
    return tuple(sorted(hash_dict.items()))


@dataclass(frozen=True)
class ArtifactConsumption:
    """Immutable per-artifact proof that a single material or product was
    consumed (authorized) by a specific artifact rule during verification.

    Attributes:
      scope: Sublayout delegation path. Empty at the top-level layout. If a
          step delegated to a sublayout, records created while verifying
          that sublayout carry the delegating step names here, outermost
          first.

      item_name: Name of the step or inspection whose rule consumed the
          artifact.

      item_kind: "step" or "inspection".

      source_type: "materials" or "products", i.e. the rule list
          (expected_materials or expected_products) the consuming rule
          belongs to.

      artifact: Full path of the consumed artifact, as reported by the
          verified link of ``item_name``.

      rule_index: Index of the consuming rule in the item's
          expected_materials/expected_products list, consistent with the
          order of rules in the layout.

      rule: The original rule, as written in the layout.

      rule_type: Lowercase rule type ("match", "create", "delete",
          "modify" or "allow").

      binding: On what grounds the artifact was consumed, one of "hash",
          "hash-difference", "set-membership" or "wildcard" (see module
          constants). Wildcard ALLOW consumption is recorded as
          "wildcard" and is not hash-bound.

      source_prefix: Source path prefix of a MATCH rule ("" if none). The
          prefix was stripped from ``artifact`` before globbing.

      dest_prefix: Destination path prefix of a MATCH rule ("" if none).
          The prefix was prepended to the globbed path to locate the
          destination artifact.

      dest_item: Name of the step or inspection whose verified link
          provided the destination artifact (MATCH rules only).

      dest_type: "materials" or "products", i.e. which artifact set of
          the destination link was matched (MATCH rules only).

      dest_artifact: Full path of the destination artifact in the
          destination link, after applying ``dest_prefix`` (MATCH rules
          only).

      source_hashes: Digests of the consumed artifact as reported by the
          item's verified link. None for wildcard ALLOW consumption,
          which is not hash-bound.

      dest_hashes: Digests of the destination artifact that was compared
          equal to ``source_hashes`` (MATCH rules only).

      in_materials: Whether the artifact was reported in the item's
          materials.

      in_products: Whether the artifact was reported in the item's
          products.

      material_hashes: Digests of the artifact in the item's materials,
          or None if it is not a material.

      product_hashes: Digests of the artifact in the item's products, or
          None if it is not a product.

    """

    scope: Tuple[str, ...]
    item_name: str
    item_kind: str
    source_type: str
    artifact: str
    rule_index: int
    rule: Tuple[str, ...]
    rule_type: str
    binding: str
    source_prefix: str = ""
    dest_prefix: str = ""
    dest_item: Optional[str] = None
    dest_type: Optional[str] = None
    dest_artifact: Optional[str] = None
    source_hashes: Optional[FrozenHashes] = None
    dest_hashes: Optional[FrozenHashes] = None
    in_materials: bool = False
    in_products: bool = False
    material_hashes: Optional[FrozenHashes] = None
    product_hashes: Optional[FrozenHashes] = None


@dataclass(frozen=True)
class RuleTraceEntry:
    """Immutable record of one rule application, in layout order, showing
    which artifacts the rule consumed and which artifacts remained in the
    queue afterwards.

    Attributes:
      scope: Sublayout delegation path (see ArtifactConsumption).
      item_name: Name of the step or inspection the rule belongs to.
      item_kind: "step" or "inspection".
      source_type: "materials" or "products".
      rule_index: Index of the rule in the item's rule list.
      rule: The original rule, as written in the layout.
      consumed: Sorted paths consumed by this rule application.
      queue_after: Sorted paths still unconsumed after this rule
          application.

    """

    scope: Tuple[str, ...]
    item_name: str
    item_kind: str
    source_type: str
    rule_index: int
    rule: Tuple[str, ...]
    consumed: Tuple[str, ...]
    queue_after: Tuple[str, ...]


@dataclass(frozen=True)
class UnconsumedArtifact:
    """Immutable record of an artifact reported by a verified link for
    which no rule provided a consumption proof. Only present in
    non-strict coverage reports; in strict mode such artifacts raise
    ``in_toto.exceptions.CoverageError`` instead.

    """

    scope: Tuple[str, ...]
    item_name: str
    item_kind: str
    source_type: str
    artifact: str


@dataclass(frozen=True)
class VerifiedLinkInfo:
    """Immutable record of the link metadata actually adopted for an item
    after signature threshold verification and, for delegated steps,
    successful sublayout verification. Coverage evidence is only ever
    built from these links, never from rejected candidates.

    Attributes:
      scope: Sublayout delegation path (see ArtifactConsumption).
      item_name: Name of the step or inspection.
      item_kind: "step" or "inspection".
      keyids: Keyids of the functionaries whose signatures verified for
          the adopted link(s) of a step. Empty for inspections, whose
          links are generated locally during verification.

    """

    scope: Tuple[str, ...]
    item_name: str
    item_kind: str
    keyids: Tuple[str, ...]


@dataclass(frozen=True)
class CoverageReport:
    """Immutable result of strict artifact coverage verification.

    Attributes:
      records: Per-artifact consumption proofs, one for each artifact
          consumed by a rule, in the order the rules were applied.
      rule_trace: Per-rule application trace, in layout order.
      unconsumed: Artifacts reported by verified links without a
          consumption proof. Always empty in strict mode (strict mode
          raises instead).
      verified_links: The links adopted for each step and inspection
          after threshold and sublayout verification.
      summary_link: The summary link of the verified supply chain, as
          also returned by ``in_toto.verifylib.in_toto_verify``.
      strict: Whether the report was created in strict mode.

    """

    records: Tuple[ArtifactConsumption, ...]
    rule_trace: Tuple[RuleTraceEntry, ...]
    unconsumed: Tuple[UnconsumedArtifact, ...]
    verified_links: Tuple[VerifiedLinkInfo, ...]
    summary_link: Any
    strict: bool

    @property
    def ok(self) -> bool:
        """True if every artifact reported by a verified link has a
        consumption proof."""
        return not self.unconsumed

    def records_for(
        self,
        item_name: Optional[str] = None,
        source_type: Optional[str] = None,
        rule_type: Optional[str] = None,
    ) -> Tuple[ArtifactConsumption, ...]:
        """Return consumption proofs, optionally filtered by item name,
        source type ("materials"/"products") and/or rule type."""
        return tuple(
            record
            for record in self.records
            if (item_name is None or record.item_name == item_name)
            and (source_type is None or record.source_type == source_type)
            and (rule_type is None or record.rule_type == rule_type)
        )

    def to_dict(self) -> dict:
        """Return a JSON-serializable dictionary representation of the
        report (the summary link is represented by name, materials and
        products)."""
        return {
            "strict": self.strict,
            "ok": self.ok,
            "records": [dataclasses.asdict(r) for r in self.records],
            "rule_trace": [dataclasses.asdict(t) for t in self.rule_trace],
            "unconsumed": [dataclasses.asdict(u) for u in self.unconsumed],
            "verified_links": [
                dataclasses.asdict(v) for v in self.verified_links
            ],
            "summary_link": {
                "name": self.summary_link.name,
                "materials": self.summary_link.materials,
                "products": self.summary_link.products,
            },
        }


@dataclass
class CoverageCollector:
    """Mutable collector used while verifying a supply chain. Passed
    through the verification workflow and turned into an immutable
    ``CoverageReport`` once verification has fully succeeded. A partially
    populated collector is never exposed if verification fails.

    """

    strict: bool = True
    records: list = field(default_factory=list)
    rule_trace: list = field(default_factory=list)
    unconsumed: list = field(default_factory=list)
    verified_links: list = field(default_factory=list)

    def build_report(self, summary_link) -> CoverageReport:
        """Return an immutable CoverageReport for a successfully verified
        supply chain."""
        return CoverageReport(
            records=tuple(self.records),
            rule_trace=tuple(self.rule_trace),
            unconsumed=tuple(self.unconsumed),
            verified_links=tuple(self.verified_links),
            summary_link=summary_link,
            strict=self.strict,
        )
