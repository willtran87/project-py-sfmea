"""CLI surface for governed LLM assurance-test implementation."""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from typing import Any

from .json_ingestion import load_bounded_json_document
from .store import load_analysis
from .test_generation import (
    RecordedTestGenerationProvider,
    TestGenerationProvider,
    apply_test_proposal,
    build_test_generation_packet,
    create_test_proposal,
    export_test_proposal,
    generation_readiness,
    load_test_proposal,
    load_test_proposal_apply_receipt,
    stage_test_proposal,
    verify_test_proposal,
    verify_test_proposal_apply_receipt,
    verify_test_proposal_stage,
)
from .test_generation_quality import (
    evaluate_test_generation_quality,
    export_test_generation_quality_result,
    load_test_generation_quality_corpus,
    load_test_generation_quality_result,
    verify_test_generation_quality_result,
)

ProviderFactory = Callable[[argparse.Namespace], TestGenerationProvider]


def add_test_generation_commands(
    subparsers: Any,
    add_provider_arguments: Callable[[argparse.ArgumentParser], None],
    provider_factory: ProviderFactory,
) -> None:
    """Register the isolated generated-test command group on the root parser."""

    generate = subparsers.add_parser(
        "assurance-test-generate",
        help="generate one closed, source-bound LLM assurance-test proposal",
    )
    generate.add_argument("analysis", help="analysis JSON path")
    generate.add_argument("obligation_id")
    generate.add_argument(
        "-o", "--output", help="proposal JSON output; required unless --dry-run"
    )
    generate.add_argument(
        "--dry-run",
        action="store_true",
        help="print the bounded provider packet without invoking a model",
    )
    generate.add_argument(
        "--response-file",
        help="strict offline response JSON for review, replay, or qualification",
    )
    generate.add_argument("--response-provider", default="recorded-response")
    generate.add_argument("--response-model", default="offline-review")
    generate.add_argument(
        "--max-attempts",
        type=int,
        default=1,
        choices=range(1, 4),
        metavar="{1,2,3}",
        help="bounded provider attempts including validator-guided repair",
    )
    generate.add_argument(
        "--approve-source-egress",
        action="store_true",
        help="approve sending the displayed bounded source packet to the configured provider",
    )
    add_provider_arguments(generate)
    generate.set_defaults(
        handler=_generate,
        test_generation_provider_factory=provider_factory,
    )

    proposal_verify = subparsers.add_parser(
        "assurance-test-proposal-verify",
        help="verify a generated test proposal and optional exact analysis binding",
    )
    proposal_verify.add_argument("proposal")
    proposal_verify.add_argument("--analysis")
    proposal_verify.add_argument("--json", action="store_true")
    proposal_verify.set_defaults(handler=_proposal_verify)

    stage = subparsers.add_parser(
        "assurance-test-stage",
        help="stage a verified implementation-ready proposal outside the repository",
    )
    stage.add_argument("proposal")
    stage.add_argument("--analysis", required=True)
    stage.add_argument("-o", "--output", required=True)
    stage.set_defaults(handler=_stage)

    stage_verify = subparsers.add_parser(
        "assurance-test-stage-verify",
        help="verify an isolated generated-test stage against its proposal and analysis",
    )
    stage_verify.add_argument("stage")
    stage_verify.add_argument("proposal")
    stage_verify.add_argument("--analysis", required=True)
    stage_verify.add_argument("--json", action="store_true")
    stage_verify.set_defaults(handler=_stage_verify)

    apply = subparsers.add_parser(
        "assurance-test-apply",
        help="atomically publish a reviewed generated test and application receipt",
    )
    apply.add_argument("stage")
    apply.add_argument("proposal")
    apply.add_argument("--analysis", required=True)
    apply.add_argument("--reviewer", required=True)
    apply.add_argument("--rationale", required=True)
    apply.add_argument("--receipt", required=True)
    apply.add_argument(
        "--approve", action="store_true", help="approve publication into the repository"
    )
    apply.set_defaults(handler=_apply)

    apply_verify = subparsers.add_parser(
        "assurance-test-apply-verify",
        help="verify an application receipt, proposal, exact test, and analysis binding",
    )
    apply_verify.add_argument("receipt")
    apply_verify.add_argument("proposal")
    apply_verify.add_argument("--analysis", required=True)
    apply_verify.add_argument("--json", action="store_true")
    apply_verify.set_defaults(handler=_apply_verify)

    readiness = subparsers.add_parser(
        "assurance-test-readiness",
        help="evaluate proposal-to-independent-evidence readiness gates",
    )
    readiness.add_argument("receipt")
    readiness.add_argument("proposal")
    readiness.add_argument("--analysis", required=True)
    readiness.add_argument("--json", action="store_true")
    readiness.set_defaults(handler=_readiness)

    quality = subparsers.add_parser(
        "assurance-test-quality-evaluate",
        help="score an independently labeled provider/model/prompt test-generation corpus",
    )
    quality.add_argument("corpus")
    quality.add_argument("-o", "--output", required=True)
    quality.add_argument(
        "--require-qualified",
        action="store_true",
        help="return a failing exit status unless every declared quality gate passes",
    )
    quality.set_defaults(handler=_quality_evaluate)

    quality_verify = subparsers.add_parser(
        "assurance-test-quality-verify",
        help="verify a test-generation quality result against its exact corpus",
    )
    quality_verify.add_argument("result")
    quality_verify.add_argument("corpus")
    quality_verify.set_defaults(handler=_quality_verify)


def _generate(args: argparse.Namespace) -> int:
    analysis = load_analysis(args.analysis)
    if args.dry_run:
        if (
            args.output
            or args.response_file
            or args.endpoint
            or args.model
            or args.max_attempts != 1
            or args.approve_source_egress
        ):
            raise ValueError(
                "--dry-run cannot be combined with output, response, or provider arguments"
            )
        packet = build_test_generation_packet(analysis, args.obligation_id)
        print(json.dumps(packet, indent=2, ensure_ascii=False))
        return 0
    if not args.output:
        raise ValueError("--output is required unless --dry-run is used")
    if args.response_file:
        if args.endpoint or args.model:
            raise ValueError(
                "--response-file cannot be combined with endpoint or model arguments"
            )
        document = load_bounded_json_document(
            args.response_file,
            label="recorded assurance test response",
            max_bytes=3_000_000,
            max_depth=50,
            max_nodes=150_000,
        )
        if not isinstance(document.value, dict):
            raise ValueError("recorded assurance test response must be an object")
        provider: TestGenerationProvider = RecordedTestGenerationProvider(
            document.value,
            name=args.response_provider,
            model=args.response_model,
        )
    else:
        if not args.approve_source_egress:
            raise ValueError(
                "live test generation requires explicit --approve-source-egress"
            )
        factory = args.test_generation_provider_factory
        provider = factory(args)
    proposal = create_test_proposal(
        analysis, args.obligation_id, provider, max_attempts=args.max_attempts
    )
    result = export_test_proposal(proposal, args.output)
    print(
        f"Created {proposal['response']['decision']} assurance test proposal "
        f"{proposal['id']}: {result}"
    )
    print(proposal["notice"])
    return 0


def _proposal_verify(args: argparse.Namespace) -> int:
    proposal = load_test_proposal(args.proposal)
    analysis = load_analysis(args.analysis) if args.analysis else None
    result = verify_test_proposal(proposal, analysis)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Assurance test proposal: {result['status']}; "
            f"implementation ready={result['implementation_ready']}"
        )
        for name, passed in result["checks"].items():
            state = "not checked" if passed is None else "pass" if passed else "fail"
            print(f"- {name}: {state}")
        for error in result["errors"]:
            print(f"- error: {error}")
        print(result["notice"])
    return int(not result["valid"])


def _stage(args: argparse.Namespace) -> int:
    proposal = load_test_proposal(args.proposal)
    analysis = load_analysis(args.analysis)
    result = stage_test_proposal(proposal, analysis, args.output)
    print(f"Staged unreviewed assurance test implementation: {result}")
    print(
        "Review and exercise it in an approved sandbox; staging does not modify the "
        "analyzed repository or register assurance evidence."
    )
    return 0


def _stage_verify(args: argparse.Namespace) -> int:
    proposal = load_test_proposal(args.proposal)
    analysis = load_analysis(args.analysis)
    result = verify_test_proposal_stage(args.stage, proposal, analysis)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Assurance test proposal stage: {result['status']}")
        for name, passed in result["checks"].items():
            print(f"- {name}: {'pass' if passed else 'fail'}")
        for error in result["errors"]:
            print(f"- error: {error}")
        print(result["notice"])
    return int(not result["valid"])


def _apply(args: argparse.Namespace) -> int:
    proposal = load_test_proposal(args.proposal)
    analysis = load_analysis(args.analysis)
    receipt = apply_test_proposal(
        args.stage,
        proposal,
        analysis,
        reviewer=args.reviewer,
        rationale=args.rationale,
        approved=args.approve,
        receipt_path=args.receipt,
    )
    print(
        f"Applied generated assurance test {receipt['file']['path']} with receipt "
        f"{args.receipt}"
    )
    print(
        "The test remains unregistered and unexecuted; inspect the diff, then use "
        "assurance-test-register with origin llm_generated."
    )
    return 0


def _apply_verify(args: argparse.Namespace) -> int:
    receipt = load_test_proposal_apply_receipt(args.receipt)
    proposal = load_test_proposal(args.proposal)
    analysis = load_analysis(args.analysis)
    result = verify_test_proposal_apply_receipt(receipt, proposal, analysis)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"Assurance test application receipt: {result['status']}")
        for name, passed in result["checks"].items():
            print(f"- {name}: {'pass' if passed else 'fail'}")
        for error in result["errors"]:
            print(f"- error: {error}")
        print(result["notice"])
    return int(not result["valid"])


def _readiness(args: argparse.Namespace) -> int:
    receipt = load_test_proposal_apply_receipt(args.receipt)
    proposal = load_test_proposal(args.proposal)
    analysis = load_analysis(args.analysis)
    result = generation_readiness(proposal, receipt, analysis)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(
            f"Generated assurance test: {result['status']} "
            f"({result['passed_gates']}/{result['required_gates']} gates)"
        )
        for gate in result["gates"]:
            print(f"- {gate['id']}: {'pass' if gate['passed'] else 'blocked'}")
            if not gate["passed"]:
                print(f"  {gate['remediation']}")
        print(result["notice"])
    return int(not result["ready"])


def _quality_evaluate(args: argparse.Namespace) -> int:
    corpus = load_test_generation_quality_corpus(args.corpus)
    result = evaluate_test_generation_quality(corpus)
    output = export_test_generation_quality_result(result, args.output)
    print(
        f"Test-generation quality: {result['status']} "
        f"({sum(gate['passed'] for gate in result['gates'])}/{len(result['gates'])} gates): {output}"
    )
    print(result["notice"])
    return int(args.require_qualified and not result["qualified"])


def _quality_verify(args: argparse.Namespace) -> int:
    result = load_test_generation_quality_result(args.result)
    corpus = load_test_generation_quality_corpus(args.corpus)
    verification = verify_test_generation_quality_result(result, corpus)
    print(
        "Test-generation quality result: "
        + ("valid" if verification["valid"] else "invalid")
    )
    for error in verification["errors"]:
        print(f"  {error}")
    return int(not verification["valid"])
