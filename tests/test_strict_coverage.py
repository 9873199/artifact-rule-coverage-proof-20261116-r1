# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  test_strict_coverage.py

<Author>
  Lukas Puehringer <lukas.puehringer@nyu.edu>

<Started>
  June 28, 2016

<Copyright>
  See LICENSE for licensing information.

<Purpose>
  Offline end-to-end demo and tests for strict artifact coverage
  verification (in_toto.verifylib.in_toto_verify_coverage).

  The tests build a small, fully self-contained and offline supply chain:
  a signed layout with two build steps ("build" and "package") and one
  inspection ("final-check"), plus signed link metadata for each step.
  No inspection command is ever executed: a local, non-executing
  inspection runner is injected instead, and the tests prove that a
  rejected layout never reaches the runner.

  Covered scenarios:
    - happy path with per-artifact provenance (steps, inspection,
      wildcard ALLOW, CREATE, prefix-renaming MATCH)
    - unconsumed artifacts (strict failure, non-strict reporting)
    - prefix transformation before/after a rename
    - same artifact name with one of multiple hashes mismatching
    - links inconsistent with threshold filtering
    - nested layouts (sublayout delegation)
    - rejected layouts never reach the inspection runner
    - the original in_toto_verify return convention keeps working

"""

import dataclasses
import hashlib
import json
import os
import unittest

from in_toto.coverage import (
    BINDING_HASH,
    BINDING_SET_MEMBERSHIP,
    BINDING_WILDCARD,
    CoverageReport,
)
from in_toto.exceptions import (
    CoverageError,
    RuleVerificationError,
    ThresholdVerificationError,
)
from in_toto.models.layout import (
    SUBLAYOUT_LINK_DIR_FORMAT,
    Inspection,
    Layout,
    Step,
)
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.verifylib import in_toto_verify, in_toto_verify_coverage
from tests.common import SignerStore, TmpDirMixin

# Owner (layout signing) and functionary keys, all offline test keys
OWNER = SignerStore.rsa
OWNER_PUB = SignerStore.rsa_pub
ALICE = SignerStore.ecdsa
ALICE_PUB = SignerStore.ecdsa_pub
BOB = SignerStore.ed25519
BOB_PUB = SignerStore.ed25519_pub

OWNER_KEYID = OWNER_PUB["keyid"]
ALICE_KEYID = ALICE_PUB["keyid"]
BOB_KEYID = BOB_PUB["keyid"]

#: A command that must never be executed by the tests. If verification
#: accidentally ran inspection commands instead of using the injected
#: local runner, this would fail noisily.
UNTRUSTED_COMMAND = ["in-toto-coverage-test-command-that-must-not-run"]


def hash_dict(content, with_sha512=False):
    """Return a hash dict for the passed content string."""
    data = content.encode("utf-8")
    hashes = {"sha256": hashlib.sha256(data).hexdigest()}
    if with_sha512:
        hashes["sha512"] = hashlib.sha512(data).hexdigest()
    return hashes


def make_link(name, materials, products, command=None):
    """Return an unsigned Link object with a zero return-value byproduct."""
    return Link(
        name=name,
        materials=materials,
        products=products,
        command=command or [],
        byproducts={"return-value": 0},
    )


def dump_signed(payload, signer, keyid, path):
    """Sign the passed payload (Link or Layout) and dump it to path."""
    metablock = Metablock(signed=payload)
    metablock.create_signature(signer)
    metablock.dump(path)
    return metablock


def dump_link(link, signer, keyid, directory="."):
    """Sign the passed link and dump it under its canonical filename."""
    return dump_signed(
        link,
        signer,
        keyid,
        os.path.join(
            directory,
            FILENAME_FORMAT.format(step_name=link.name, keyid=keyid),
        ),
    )


class FakeInspectionRunner:
    """Local, non-executing replacement for runlib.in_toto_run.

    Returns prebuilt inspection links and records how it was invoked, so
    tests can prove that no untrusted inspection command is executed and
    that rejected layouts never reach the runner.

    """

    def __init__(self, links_by_name):
        self.links_by_name = links_by_name
        self.calls = []

    def __call__(
        self, name, material_list, product_list, link_cmd, timeout=None
    ):
        self.calls.append({"name": name, "link_cmd": list(link_cmd)})
        return Metablock(signed=self.links_by_name[name])


class TestStrictCoverage(unittest.TestCase, TmpDirMixin):
    """Offline end-to-end tests for strict artifact coverage verification."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def setUp(self):
        # Each test builds its supply chain in a fresh subdirectory of the
        # class-level temporary directory
        self.workdir = os.path.join(self.test_dir, self.id().split(".")[-1])
        os.makedirs(self.workdir, exist_ok=True)
        os.chdir(self.workdir)

    def tearDown(self):
        os.chdir(self.test_dir)

    # -- Demo supply chain builders -------------------------------------

    def build_demo_layout(self, package_product_rules=None):
        """Build and dump the signed demo layout: two build steps and one
        inspection."""
        build = Step(
            name="build",
            pubkeys=[ALICE_KEYID],
            expected_command=["gcc", "-c", "foo.c"],
            expected_materials=[["ALLOW", "src/*"]],
            expected_products=[["CREATE", "build-out/*"], ["ALLOW", "src/*"]],
        )
        package = Step(
            name="package",
            pubkeys=[BOB_KEYID],
            expected_command=["tar", "cf", "app.tar"],
            expected_materials=[
                [
                    "MATCH",
                    "*",
                    "IN",
                    "dist",
                    "WITH",
                    "PRODUCTS",
                    "IN",
                    "build-out",
                    "FROM",
                    "build",
                ]
            ],
            expected_products=package_product_rules
            or [["CREATE", "dist/*.tar"], ["ALLOW", "dist/*"]],
        )
        final_check = Inspection(
            name="final-check",
            run=UNTRUSTED_COMMAND,
            expected_materials=[
                ["MATCH", "dist/*", "WITH", "PRODUCTS", "FROM", "package"]
            ],
            # The duplicate ALLOW rule at index 2 intentionally consumes
            # nothing; traces must still attribute rules by their index
            expected_products=[
                ["CREATE", "report.txt"],
                ["ALLOW", "dist/*"],
                ["ALLOW", "dist/*"],
            ],
        )
        layout = Layout(
            steps=[build, package],
            inspect=[final_check],
            keys={ALICE_KEYID: ALICE_PUB, BOB_KEYID: BOB_PUB},
        )
        return dump_signed(layout, OWNER, OWNER_KEYID, "root.layout")

    def build_demo_links(self, extra_package_products=None):
        """Build and dump signed links for the demo steps."""
        package_products = {
            "dist/foo.o": hash_dict("foo-object"),
            "dist/app.tar": hash_dict("app-tar"),
        }
        if extra_package_products:
            package_products.update(extra_package_products)

        dump_link(
            make_link(
                "build",
                materials={"src/foo.c": hash_dict("foo-source")},
                products={
                    "src/foo.c": hash_dict("foo-source"),
                    "build-out/foo.o": hash_dict("foo-object"),
                },
                command=["gcc", "-c", "foo.c"],
            ),
            ALICE,
            ALICE_KEYID,
        )
        dump_link(
            make_link(
                "package",
                materials={"dist/foo.o": hash_dict("foo-object")},
                products=package_products,
                command=["tar", "cf", "app.tar"],
            ),
            BOB,
            BOB_KEYID,
        )

    def build_demo_inspection_runner(self):
        """Return a fake runner with a prebuilt link for 'final-check'."""
        inspection_link = make_link(
            "final-check",
            materials={
                "dist/foo.o": hash_dict("foo-object"),
                "dist/app.tar": hash_dict("app-tar"),
            },
            products={
                "dist/foo.o": hash_dict("foo-object"),
                "dist/app.tar": hash_dict("app-tar"),
                "report.txt": hash_dict("report"),
            },
        )
        return FakeInspectionRunner({"final-check": inspection_link})

    def verify_coverage(self, runner, **kwargs):
        """Run strict coverage verification on the demo supply chain."""
        kwargs.setdefault("persist_inspection_links", False)
        kwargs.setdefault("inspection_runner", runner)
        return in_toto_verify_coverage(
            Metablock.load("root.layout"),
            {OWNER_KEYID: OWNER_PUB},
            link_dir_path=".",
            **kwargs,
        )

    # -- Tests -----------------------------------------------------------

    def test_happy_path_per_artifact_provenance(self):
        """Every artifact gets an immutable proof with full provenance."""
        self.build_demo_layout()
        self.build_demo_links()
        runner = self.build_demo_inspection_runner()

        report = self.verify_coverage(runner)

        # The report is complete and immutable
        self.assertIsInstance(report, CoverageReport)
        self.assertTrue(report.ok)
        self.assertEqual(report.unconsumed, ())
        self.assertIsInstance(report.records, tuple)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            report.records[0].item_name = "tampered"

        # The report is JSON-serializable for pipeline consumption
        json.dumps(report.to_dict())

        # The summary link summarizes the whole supply chain
        self.assertEqual(
            set(report.summary_link.materials), {"src/foo.c"}
        )
        self.assertEqual(
            set(report.summary_link.products),
            {"dist/foo.o", "dist/app.tar"},
        )

        # Every artifact of every verified link has exactly one proof
        provenanced = {(r.item_name, r.source_type, r.artifact) for r in report.records}
        self.assertEqual(
            provenanced,
            {
                ("build", "materials", "src/foo.c"),
                ("build", "products", "src/foo.c"),
                ("build", "products", "build-out/foo.o"),
                ("package", "materials", "dist/foo.o"),
                ("package", "products", "dist/foo.o"),
                ("package", "products", "dist/app.tar"),
                ("final-check", "materials", "dist/foo.o"),
                ("final-check", "materials", "dist/app.tar"),
                ("final-check", "products", "dist/foo.o"),
                ("final-check", "products", "dist/app.tar"),
                ("final-check", "products", "report.txt"),
            },
        )

        # The prefix-renaming MATCH records the transformation and the
        # verified destination link, with equal compared digests
        (match,) = report.records_for(item_name="package", rule_type="match")
        self.assertEqual(match.item_kind, "step")
        self.assertEqual(match.source_type, "materials")
        self.assertEqual(match.artifact, "dist/foo.o")
        self.assertEqual(match.rule_index, 0)
        self.assertEqual(
            match.rule,
            (
                "MATCH",
                "*",
                "IN",
                "dist",
                "WITH",
                "PRODUCTS",
                "IN",
                "build-out",
                "FROM",
                "build",
            ),
        )
        self.assertEqual(match.binding, BINDING_HASH)
        self.assertEqual(match.source_prefix, "dist")
        self.assertEqual(match.dest_prefix, "build-out")
        self.assertEqual(match.dest_item, "build")
        self.assertEqual(match.dest_type, "products")
        self.assertEqual(match.dest_artifact, "build-out/foo.o")
        self.assertEqual(
            match.source_hashes,
            tuple(sorted(hash_dict("foo-object").items())),
        )
        self.assertEqual(match.source_hashes, match.dest_hashes)

        # Wildcard ALLOW consumption is shown as-is, not hash-bound
        (allow,) = report.records_for(
            item_name="build", source_type="materials"
        )
        self.assertEqual(allow.rule_type, "allow")
        self.assertEqual(allow.binding, BINDING_WILDCARD)
        self.assertIsNone(allow.source_hashes)
        self.assertIsNone(allow.dest_hashes)

        # CREATE consumption records set-membership facts for both sets
        (create,) = report.records_for(item_name="build", rule_type="create")
        self.assertEqual(create.binding, BINDING_SET_MEMBERSHIP)
        self.assertEqual(create.artifact, "build-out/foo.o")
        self.assertFalse(create.in_materials)
        self.assertTrue(create.in_products)
        self.assertIsNone(create.material_hashes)
        self.assertEqual(
            create.product_hashes,
            tuple(sorted(hash_dict("foo-object").items())),
        )

        # Rule indices follow the layout's rule order, including the
        # duplicate ALLOW rule that consumed nothing
        trace = [
            entry
            for entry in report.rule_trace
            if entry.item_name == "final-check"
            and entry.source_type == "products"
        ]
        self.assertEqual([entry.rule_index for entry in trace], [0, 1, 2])
        self.assertEqual(trace[1].consumed, ("dist/app.tar", "dist/foo.o"))
        self.assertEqual(trace[2].consumed, ())

        # The adopted links are the signature-verified ones
        verified = {
            (v.scope, v.item_name, v.item_kind): v.keyids
            for v in report.verified_links
        }
        self.assertEqual(
            verified[((), "build", "step")], (ALICE_KEYID,)
        )
        self.assertEqual(
            verified[((), "package", "step")], (BOB_KEYID,)
        )
        self.assertEqual(
            verified[((), "final-check", "inspection")], ()
        )

        # The untrusted inspection command was never executed; the local
        # runner was invoked exactly once instead
        self.assertEqual(len(runner.calls), 1)
        self.assertEqual(runner.calls[0]["name"], "final-check")
        self.assertEqual(runner.calls[0]["link_cmd"], UNTRUSTED_COMMAND)

    def test_original_verify_return_convention(self):
        """in_toto_verify keeps returning a plain summary Link."""
        self.build_demo_layout()
        self.build_demo_links()
        runner = self.build_demo_inspection_runner()

        summary_link = in_toto_verify(
            Metablock.load("root.layout"),
            {OWNER_KEYID: OWNER_PUB},
            link_dir_path=".",
            persist_inspection_links=False,
            inspection_runner=runner,
        )

        self.assertIsInstance(summary_link, Link)
        self.assertEqual(set(summary_link.materials), {"src/foo.c"})
        self.assertEqual(
            set(summary_link.products), {"dist/foo.o", "dist/app.tar"}
        )
        self.assertEqual(len(runner.calls), 1)

    def test_unconsumed_artifact_fails_strict_coverage(self):
        """An artifact without consumption proof fails strict mode only."""
        self.build_demo_layout()
        self.build_demo_links(
            extra_package_products={"debug.log": hash_dict("debug")}
        )
        runner = self.build_demo_inspection_runner()

        # Plain verification passes: no DISALLOW rule is violated
        in_toto_verify(
            Metablock.load("root.layout"),
            {OWNER_KEYID: OWNER_PUB},
            link_dir_path=".",
            persist_inspection_links=False,
            inspection_runner=runner,
        )

        # Strict coverage rejects the unexplained artifact and returns
        # nothing (no partial result)
        with self.assertRaises(CoverageError) as ctx:
            self.verify_coverage(runner)
        self.assertIn("debug.log", str(ctx.exception))
        self.assertIn("package", str(ctx.exception))

        # Non-strict coverage reports the artifact instead, and does not
        # auto-append an ALLOW rule to make coverage pass
        report = self.verify_coverage(runner, strict=False)
        self.assertFalse(report.ok)
        self.assertEqual(len(report.unconsumed), 1)
        unconsumed = report.unconsumed[0]
        self.assertEqual(unconsumed.item_name, "package")
        self.assertEqual(unconsumed.item_kind, "step")
        self.assertEqual(unconsumed.source_type, "products")
        self.assertEqual(unconsumed.artifact, "debug.log")
        self.assertEqual(
            [r for r in report.records if r.artifact == "debug.log"],
            [],
        )

    def test_same_name_different_digest_is_not_a_match(self):
        """One mismatching hash of many defeats MATCH and stays pending."""
        # "make" produces app.bin with two hashes; "use" records the same
        # path with one of the two hashes differing
        make = Step(
            name="make",
            pubkeys=[ALICE_KEYID],
            expected_materials=[],
            expected_products=[["CREATE", "*"]],
        )
        use = Step(
            name="use",
            pubkeys=[BOB_KEYID],
            expected_materials=[
                ["MATCH", "*", "WITH", "PRODUCTS", "FROM", "make"]
            ],
            expected_products=[],
        )
        layout = Layout(
            steps=[make, use],
            inspect=[],
            keys={ALICE_KEYID: ALICE_PUB, BOB_KEYID: BOB_PUB},
        )
        dump_signed(layout, OWNER, OWNER_KEYID, "root.layout")

        good = hash_dict("app", with_sha512=True)
        tampered = dict(good)
        tampered["sha512"] = hashlib.sha512(b"evil").hexdigest()

        dump_link(
            make_link("make", materials={}, products={"app.bin": good}),
            ALICE,
            ALICE_KEYID,
        )
        dump_link(
            make_link("use", materials={"app.bin": tampered}, products={}),
            BOB,
            BOB_KEYID,
        )

        # Plain verification passes (no DISALLOW), but strict coverage
        # refuses to explain app.bin
        in_toto_verify(
            Metablock.load("root.layout"), {OWNER_KEYID: OWNER_PUB}
        )
        with self.assertRaises(CoverageError) as ctx:
            self.verify_coverage(None)
        self.assertIn("app.bin", str(ctx.exception))

        # The failed match was neither recorded as MATCH nor removed from
        # the pending set silently (the CREATE proof for app.bin comes from
        # the "make" step's own products and is legitimate)
        report = self.verify_coverage(None, strict=False)
        self.assertEqual(
            [
                r
                for r in report.records
                if r.artifact == "app.bin" and r.item_name == "use"
            ],
            [],
        )
        self.assertEqual(
            [
                (u.item_name, u.source_type, u.artifact)
                for u in report.unconsumed
            ],
            [("use", "materials", "app.bin")],
        )

    def test_threshold_filtering_selects_evidence_links(self):
        """Evidence comes only from links adopted by threshold filtering."""
        build = Step(
            name="build",
            pubkeys=[ALICE_KEYID, BOB_KEYID],
            threshold=1,
            expected_materials=[],
            expected_products=[["CREATE", "*"]],
        )
        layout = Layout(
            steps=[build],
            inspect=[],
            keys={ALICE_KEYID: ALICE_PUB, BOB_KEYID: BOB_PUB},
        )
        dump_signed(layout, OWNER, OWNER_KEYID, "root.layout")

        # Two authorized functionaries report different artifacts; the
        # threshold-consistent (first) link is adopted for evidence
        dump_link(
            make_link("build", {}, {"app.o": hash_dict("app")}),
            ALICE,
            ALICE_KEYID,
        )
        dump_link(
            make_link("build", {}, {"evil.o": hash_dict("evil")}),
            BOB,
            BOB_KEYID,
        )

        report = self.verify_coverage(None)
        self.assertTrue(report.ok)
        self.assertEqual(
            {r.artifact for r in report.records}, {"app.o"}
        )
        self.assertEqual(
            [r for r in report.records if r.artifact == "evil.o"], []
        )
        (verified,) = report.verified_links
        self.assertEqual(verified.item_name, "build")
        self.assertEqual(verified.keyids, (ALICE_KEYID, BOB_KEYID))

    def test_threshold_inconsistent_links_fail(self):
        """Links that disagree above the threshold fail; nothing is returned."""
        build = Step(
            name="build",
            pubkeys=[ALICE_KEYID, BOB_KEYID],
            threshold=2,
            expected_materials=[],
            expected_products=[["CREATE", "*"]],
        )
        layout = Layout(
            steps=[build],
            inspect=[],
            keys={ALICE_KEYID: ALICE_PUB, BOB_KEYID: BOB_PUB},
        )
        dump_signed(layout, OWNER, OWNER_KEYID, "root.layout")

        dump_link(
            make_link("build", {}, {"app.o": hash_dict("app")}),
            ALICE,
            ALICE_KEYID,
        )
        dump_link(
            make_link("build", {}, {"evil.o": hash_dict("evil")}),
            BOB,
            BOB_KEYID,
        )

        with self.assertRaises(ThresholdVerificationError):
            self.verify_coverage(None)
        with self.assertRaises(ThresholdVerificationError):
            in_toto_verify(
                Metablock.load("root.layout"), {OWNER_KEYID: OWNER_PUB}
            )

    def test_nested_sublayout_coverage(self):
        """Coverage recurses into sublayouts and keeps the source scope."""
        # Root layout delegates step "sub-chain" to a sublayout signed by
        # alice; step "wrap" consumes the sublayout's summary products
        sub_chain = Step(
            name="sub-chain",
            pubkeys=[ALICE_KEYID],
            expected_materials=[["ALLOW", "*"]],
            expected_products=[["ALLOW", "*"]],
        )
        wrap = Step(
            name="wrap",
            pubkeys=[BOB_KEYID],
            expected_materials=[
                ["MATCH", "*", "WITH", "PRODUCTS", "FROM", "sub-chain"]
            ],
            expected_products=[["CREATE", "*"]],
        )
        root_layout = Layout(
            steps=[sub_chain, wrap],
            inspect=[],
            keys={ALICE_KEYID: ALICE_PUB, BOB_KEYID: BOB_PUB},
        )
        dump_signed(root_layout, OWNER, OWNER_KEYID, "root.layout")

        # Sublayout, signed by alice, is provided in place of the link for
        # the delegated step
        compile_step = Step(
            name="compile",
            pubkeys=[BOB_KEYID],
            expected_materials=[],
            expected_products=[["CREATE", "*"]],
        )
        sub_layout = Layout(
            steps=[compile_step], inspect=[], keys={BOB_KEYID: BOB_PUB}
        )
        dump_signed(
            sub_layout,
            ALICE,
            ALICE_KEYID,
            FILENAME_FORMAT.format(step_name="sub-chain", keyid=ALICE_KEYID),
        )

        # Links of the sublayout live in the conventional subdirectory
        sub_dir = SUBLAYOUT_LINK_DIR_FORMAT.format(
            name="sub-chain", keyid=ALICE_KEYID
        )
        os.makedirs(sub_dir)
        dump_link(
            make_link("compile", {}, {"app.bin": hash_dict("app")}),
            BOB,
            BOB_KEYID,
            directory=sub_dir,
        )

        dump_link(
            make_link(
                "wrap",
                materials={"app.bin": hash_dict("app")},
                products={"app.pkg": hash_dict("pkg")},
            ),
            BOB,
            BOB_KEYID,
        )

        report = self.verify_coverage(None)
        self.assertTrue(report.ok)

        # Records created inside the sublayout carry the delegation scope
        (compile_record,) = report.records_for(item_name="compile")
        self.assertEqual(compile_record.scope, ("sub-chain",))
        self.assertEqual(compile_record.item_kind, "step")
        self.assertEqual(compile_record.artifact, "app.bin")

        # The superlayout MATCHes against the verified sublayout summary
        # link, keeping the destination source
        (match,) = report.records_for(item_name="wrap", rule_type="match")
        self.assertEqual(match.scope, ())
        self.assertEqual(match.dest_item, "sub-chain")
        self.assertEqual(match.dest_type, "products")
        self.assertEqual(match.dest_artifact, "app.bin")
        self.assertEqual(match.source_hashes, match.dest_hashes)

        # Verified link info is recorded on both nesting levels
        verified = {
            (v.scope, v.item_name): v.keyids for v in report.verified_links
        }
        self.assertEqual(verified[((), "sub-chain")], (ALICE_KEYID,))
        self.assertEqual(verified[(("sub-chain",), "compile")], (BOB_KEYID,))
        self.assertEqual(verified[((), "wrap")], (BOB_KEYID,))

        # The root summary link summarizes first materials and last products
        self.assertEqual(set(report.summary_link.materials), set())
        self.assertEqual(set(report.summary_link.products), {"app.pkg"})

    def test_rejected_layout_never_reaches_inspection_runner(self):
        """A layout rejected by step rules must not run inspections."""
        build = Step(
            name="build",
            pubkeys=[ALICE_KEYID],
            expected_materials=[],
            expected_products=[["DISALLOW", "*"]],
        )
        inspection = Inspection(
            name="final-check",
            run=UNTRUSTED_COMMAND,
            expected_materials=[["ALLOW", "*"]],
            expected_products=[["ALLOW", "*"]],
        )
        layout = Layout(
            steps=[build],
            inspect=[inspection],
            keys={ALICE_KEYID: ALICE_PUB},
        )
        dump_signed(layout, OWNER, OWNER_KEYID, "root.layout")
        dump_link(
            make_link("build", {}, {"app.o": hash_dict("app")}),
            ALICE,
            ALICE_KEYID,
        )

        runner = FakeInspectionRunner(
            {"final-check": make_link("final-check", {}, {})}
        )

        with self.assertRaises(RuleVerificationError):
            self.verify_coverage(runner)
        self.assertEqual(runner.calls, [])

        # The original verification entry point behaves the same way
        with self.assertRaises(RuleVerificationError):
            in_toto_verify(
                Metablock.load("root.layout"),
                {OWNER_KEYID: OWNER_PUB},
                link_dir_path=".",
                persist_inspection_links=False,
                inspection_runner=runner,
            )
        self.assertEqual(runner.calls, [])


if __name__ == "__main__":
    unittest.main()
