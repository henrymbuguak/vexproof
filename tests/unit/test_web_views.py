from __future__ import annotations

from tests.report_fixtures import CHAIN, finding, mixed
from vexproof.domain import Verdict
from vexproof.report.priority import rank
from vexproof.web.jobs import Job
from vexproof.web.views import repo_name, result_view, trace, verdict_sentence


def test_repo_names() -> None:
    assert repo_name("https://github.com/acme/shop.git") == "acme/shop"
    assert repo_name("/home/me/project") == "project"


def test_stage_rows_follow_the_job() -> None:
    job = Job(id="x", target="t", commit="c")
    assert {r["status"] for r in job.stage_rows()} == {"waiting"}
    job.state, job.stage = "running", "intel"
    job.started = {"checkout": 1.0, "intel": 2.0}
    rows = {r["key"]: r["status"] for r in job.stage_rows()}
    assert rows == {
        "checkout": "done",
        "ingest": "skipped",
        "intel": "running",
        "analyze": "waiting",
        "select": "waiting",
        "prove": "waiting",
    }
    job.state = "failed"
    assert job.stage_rows()[2]["status"] == "failed"
    assert job.status()["state"] == "failed"


def test_trace_labels_say_what_each_step_is() -> None:
    reviewed = finding("A", verdict=Verdict.AFFECTED, reviewed=True)
    labels = [s.label for s in trace(reviewed)]
    assert labels == [
        "Your code",
        "Uncertain step, judged plausible by the model",
        "Vulnerable function",
    ]
    routed = finding("B", verdict=Verdict.AFFECTED)
    chain = (
        CHAIN[0],
        CHAIN[1].model_copy(update={"via": "django_admin_upload"}),
        CHAIN[2].model_copy(update={"via": "pillow_open_registry", "certain": False}),
    )
    routed = routed.model_copy(
        update={"evidence": routed.evidence.model_copy(update={"call_chain": chain})}  # type: ignore[union-attr]
    )
    assert [s.label for s in trace(routed)][1:] == [
        "Through Django admin upload validation",
        "Vulnerable function, reached through Pillow's format registry: uncertain step, "
        "judged plausible by the model",
    ]
    odd = CHAIN[1].model_copy(update={"via": "some_new_rule"})
    routed = routed.model_copy(
        update={"evidence": routed.evidence.model_copy(update={"call_chain": (CHAIN[0], odd)})}  # type: ignore[union-attr]
    )
    assert trace(routed)[1].label == "Vulnerable function, reached through some new rule"


def test_headline_path_prefers_urgent_certain_confirmed_paths() -> None:
    document = {"source": "s", "findings": [f.model_dump(mode="json") for f in mixed()]}
    view = result_view(document)
    assert view.headline_path is not None
    assert view.headline_path.finding.advisory.id == "GHSA-kev"  # certain, fix now
    observed = {"workload": "w", "python": "3.8", "loaded_modules": [], "executed_functions": []}
    assert result_view(document, observation=observed).headline_path is None  # none ran
    assert view.find("GHSA-kev--pillow") is not None
    assert view.find("missing") is None
    assert view.outcomes.share(0) == 0.0


def test_verdict_sentences() -> None:
    items = {r.finding.advisory.id: r for r in rank(mixed())}
    assert verdict_sentence(items["GHSA-kev"]).startswith("Reachable")
    assert verdict_sentence(items["GHSA-gone"]).startswith("Not affected")
    assert verdict_sentence(items["GHSA-open"]).startswith("Open")
