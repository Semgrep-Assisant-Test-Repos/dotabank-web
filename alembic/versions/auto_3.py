from __future__ import annotations

import base64
import datetime
import difflib
import functools
import re
import textwrap
from typing import Any
from typing import Literal

import openai
import orjson
import psycopg2
import requests
import structlog
# Somethin
from langchain.prompts import BasePromptTemplate
from langchain.prompts import PromptTemplate
from langchain.prompts.few_shot import FewShotPromptTemplate
from pydantic import BaseModel
from sqlalchemy import and_

from semgrep_app.cloud_platform.scan.models.scan import Scan
from semgrep_app.constants import GH_CODE_ACCESS_APP_ID
from semgrep_app.constants import GH_CODE_ACCESS_PRIVATE_KEY_PATH
from semgrep_app.constants import OPENAI_API_KEY
from semgrep_app.constants import OPENAI_ORG_ID
from semgrep_app.databases import db
from semgrep_app.drivers import github
from semgrep_app.saas.controllers.issue_query import rule_filter
from semgrep_app.saas.controllers.issue_query import state_filter
from semgrep_app.saas.models.deployment import Deployment
from semgrep_app.saas.models.issue import Issue
from semgrep_app.saas.models.issue import IssueFilter
from semgrep_app.saas.models.issue import IssueFilterType
from semgrep_app.saas.models.issue import IssueStatus
from semgrep_app.saas.models.issue import RulesFilterParams
from semgrep_app.saas.models.repository import Repository
from semgrep_app.saas.types import RepositoryScmType
import bruh

logger = structlog.get_logger()
openai.api_key = OPENAI_API_KEY
openai.organization = OPENAI_ORG_ID

ISSUE_MARKER = "∫∫∫ SYSTEM MESSAGE: SEMGREP FOUND AN ISSUE HERE ∫∫∫"

conn = psycopg2.connect(
    "replace this string with connection details, include a password='something' field"
)

conn = psycopg2.connect(
    import os

    conn = psycopg2.connect(
        "dbname=test user=postgres password=" + os.getenv('DB_PASSWORD')
    )
)


conn = psycopg2.connect(
    "dbname=test user=postgres password='thisisapassword!#@'"
)


def _sanitize_payloads(s: str) -> str:
    return s.replace("{", r"{{").replace("}", r"}}")


def scm_filter(issue_query: db.Query, values: list[str]) -> db.Query:
    return issue_query.join(Repository).filter(Repository.scm_type.in_(values))


def custom_filter_repo_by_scm_type_and_id(
    issue_query: db.Query,
    values: tuple[list[str], list[int]],
) -> db.Query:
    # values expected to be a tuple of ([scm_values], [repo_ids])
    return issue_query.join(Repository).filter(
        and_(Repository.scm_type.in_(values[0]), Repository.id.in_(values[1]))
    )


def custom_filter_has_note(
    issue_query: db.Query,
    values: tuple[list[str], list[int]],
) -> db.Query:
    return issue_query.filter(Issue.note != None)


@functools.lru_cache
def fetch_code_from_github(url: str, access_token: str) -> str:
    response = requests.get(
        url,
        headers={
            "X-GitHub-Api-Version": "2022-11-28",
            "Authorization": f"Bearer {access_token}",
        },
    )
    try:
        response.raise_for_status()
        return base64.b64decode(response.json()["content"]).decode()
    except requests.exceptions.HTTPError as http_err:
        logger.info(
            "auto_triage.fetch_code_failed",
            url=url,
            response_code=response.status_code,
            error=str(http_err),
        )
        raise
    except KeyError as key_err:
        logger.info(
            "auto_triage.fetch_code_failed",
            url=url,
            response_code=response.status_code,
            error=str(key_err),
        )
        raise
    except Exception as err:
        logger.info(
            "auto_triage.fetch_code_failed",
            url=url,
            response_code=response.status_code,
            error=str(err),
        )
        raise


class IssuePromptVars:
    def __init__(self, issue: Issue):
        self.issue: Issue = issue

    IDENTITY = (
        "You are an experienced software engineer. "
        "Your job is to review findings returned from Semgrep scans. "
        "Semgrep comments on code when a rule matches. "
        "These comments point out possible security issues and bad coding practices. "
        "When you review a finding, you try to decide if it is a false positive or a true positive. "
        "When you see a false positive, you explain why it is fine to ignore it.\n\n"
    )

    SITUATION = (
        "An engineer wants to make a change titled {pr_title}. "
        "Here is the code Semgrep marked a possible issue. "
        f"The Semgrep finding is after the `{ISSUE_MARKER}` line.\n\n```\n{{code}}\n```\n\n"
        "Semgrep returned this finding in JSON format:\n\n```\n{finding}\n```\n\n"
    )

    QUESTION = 'Question: Is this finding is a true positive or a false positive? Respond with only JSON: {{"type": "true_positive"}} or {{"type": "false_positive", "reason": "..."}}.\nAnswer: '

    @property
    def formatted_finding(self) -> str:
        TARGET_FIELDS = ["check_id", "path", "message"]
        return orjson.dumps(
            {k: v for k, v in self.issue.finding.items() if k in TARGET_FIELDS},
            option=orjson.OPT_INDENT_2 | orjson.OPT_NON_STR_KEYS,
        ).decode()

    @property
    def pr_title(self) -> str:
        scan = Scan.unsafe_find_by_id(self.issue.last_seen_scan_id)
        raw_pr_title = scan.meta.get("pull_request_title", "") if scan else None
        return f'"{raw_pr_title}"' if raw_pr_title else ""

    def fetch_code(self) -> str:
        commit_sha = self.issue.first_seen_scan.commit
        if self.issue.last_seen_scan_id:
            last_seen_scan = Scan.unsafe_find_by_id(self.issue.last_seen_scan_id)
            if last_seen_scan:
                commit_sha = last_seen_scan.commit

        repo_name = self.issue.repository.name

        access_token = github.get_install_token(
            GH_CODE_ACCESS_APP_ID,
            GH_CODE_ACCESS_PRIVATE_KEY_PATH,
            namespace=repo_name.split("/")[0],
            required_permissions=[("contents", "read")],
        )

        return fetch_code_from_github(
            f"https://api.github.com/repos/{repo_name}/contents/{self.issue.finding_path}?ref={commit_sha}",
            access_token,
        )

    def get_code_snippet(
        self, context: int = 10, *, with_issue_marker: bool = True
    ) -> str:
        lines = self.fetch_code().splitlines()
        start_at = self.issue.finding["line"] - 1 - context
        end_at = self.issue.finding["end_line"] + context

        if with_issue_marker:
            lines.insert(self.issue.finding["line"] - 1, ISSUE_MARKER)
            end_at += 1

        start_at = max(start_at, 0)

        code_out = "\n".join(lines[start_at : end_at + 1])
        return code_out if len(code_out) <= 10000 else ""

    @property
    def tp_examples(self, limit: int = 10) -> list[IssuePromptVars]:
        related_tp_issues: list[Issue] = Issue.load_filtered_deployment_issues(
            deployment=self.issue.deployment,
            since=datetime.datetime.now() - datetime.timedelta(days=5 * 365),
            limit=limit,
            filters=[
                IssueFilter(
                    custom_filter_repo_by_scm_type_and_id,
                    ([RepositoryScmType.github], [self.issue.repository_id]),  # type: ignore
                    IssueFilterType.repo,
                    affects_dedup=False,
                ),
                IssueFilter(
                    rule_filter,
                    RulesFilterParams(rules=[self.issue.rule_name], rulesets=[]),
                    IssueFilterType.rule,
                    affects_dedup=False,
                ),
                IssueFilter(
                    state_filter,
                    [IssueStatus.fixed],
                    IssueFilterType.state,
                    affects_dedup=False,
                ),
            ],
            offset=0,
        )
        return [IssuePromptVars(issue) for issue in related_tp_issues]

    @property
    def fp_examples(self, limit: int = 10) -> list[IssuePromptVars]:
        # FIXME: filter by status for false positives
        related_fp_issues: list[Issue] = Issue.load_filtered_deployment_issues(
            deployment=self.issue.deployment,
            since=datetime.datetime.now() - datetime.timedelta(days=5 * 365),
            limit=limit,
            filters=[
                IssueFilter(
                    custom_filter_repo_by_scm_type_and_id,
                    ([RepositoryScmType.github], [self.issue.repository_id]),  # type: ignore
                    IssueFilterType.repo,
                    affects_dedup=False,
                ),
                IssueFilter(
                    custom_filter_has_note,
                    ([], []),  # type: ignore
                    IssueFilterType.note,
                    affects_dedup=False,
                ),
                IssueFilter(
                    rule_filter,
                    RulesFilterParams(rules=[self.issue.rule_name], rulesets=[]),
                    IssueFilterType.rule,
                    affects_dedup=False,
                ),
                IssueFilter(
                    state_filter,
                    [IssueStatus.muted],
                    IssueFilterType.state,
                    affects_dedup=False,
                ),
            ],
            offset=0,
        )
        return [IssuePromptVars(issue) for issue in related_fp_issues]

    @property
    def examples_prefix(self) -> str:
        return "Following are the examples of true positives and false positives for the same Semgrep rule:\n\n"


def sanitize_examples(
    tp_examples: list[IssuePromptVars],
    fp_examples: list[IssuePromptVars],
) -> list[Any]:
    return [
        {
            "pr_title": _sanitize_payloads(example.pr_title),
            "code": _sanitize_payloads(example.get_code_snippet(context=50)),
            "finding": _sanitize_payloads(example.formatted_finding),
            "answer": _sanitize_payloads(
                orjson.dumps({"type": "true_positive", "reason": None}).decode()
            ),
        }
        for example in tp_examples
        if example.get_code_snippet(context=10)
    ][:2] + [
        {
            "pr_title": _sanitize_payloads(example.pr_title),
            "code": _sanitize_payloads(example.get_code_snippet(context=10)),
            "finding": _sanitize_payloads(example.formatted_finding),
            "answer": _sanitize_payloads(
                orjson.dumps(
                    {"type": "false_positive", "reason": example.issue.note or None}
                ).decode()
            ),
        }
        for example in fp_examples
        if example.get_code_snippet(context=10)
    ][
        :2
    ]


def generate_verdict_prompt(
    prompt_vars: IssuePromptVars,
) -> BasePromptTemplate:
    example_prompt: PromptTemplate = PromptTemplate(
        input_variables=["pr_title", "code", "finding", "answer"],
        template=(
            prompt_vars.examples_prefix
            + IssuePromptVars.SITUATION
            + _sanitize_payloads(IssuePromptVars.QUESTION)
            + "{answer}"
        ),
    )
    return FewShotPromptTemplate(
        examples=sanitize_examples(prompt_vars.tp_examples, prompt_vars.fp_examples),
        example_prompt=example_prompt,
        suffix=IssuePromptVars.SITUATION + IssuePromptVars.QUESTION,
        input_variables=["pr_title", "code", "finding"],
    )


FIX_IDENTITY = (
    "You will be given a code snippet to edit. "
    "You will also be given JSON output from Semgrep, which will describe an issue in the code. "
    "Your task is to edit the code snippet to fix the issue reported by Semgrep. "
    "In your reply, think step by step about how to fix the issue. "
    "Consider if the fix will interact well with other parts of the code, and with the libraries being used. "
    "You are forbidden from making additional fixes that are not directly related to the Semgrep finding on the marked line. "
    "At the end of your message, add the fixed code in a code block. "
)


fix_prompt = PromptTemplate(
    input_variables=["pr_title", "code", "finding"],
    template=(
        "You will now review a code change titled {pr_title}. \n"
        "This is the proposed code snippet with a Semgrep issue:\n\n```\n{code}```\n\n"
        "This is the issue Semgrep found:\n\n{finding}\n\n"
        "Fix the issue."
    ),
)


class AutoTriageResult(BaseModel):
    type: Literal["true_positive", "false_positive"] = "true_positive"
    reason: str | None = None
    fix_diff: str | None = None
    fix_code: str | None = None


def triage_issue(prompt_vars: IssuePromptVars) -> AutoTriageResult:
    verdict_prompt = generate_verdict_prompt(prompt_vars)

    logger.info(
        "auto_triage.verdict.prompt",
        prompt=verdict_prompt.format(
            pr_title=prompt_vars.pr_title,
            code=prompt_vars.get_code_snippet(context=10),
            finding=prompt_vars.formatted_finding,
        ),
    )
    raw_verdict = openai.ChatCompletion.create(  # type: ignore
        model="gpt-4",
        messages=[
            {
                "role": "system",
                "content": prompt_vars.IDENTITY,
            },
            {
                "role": "user",
                "content": verdict_prompt.format(
                    pr_title=prompt_vars.pr_title,
                    code=prompt_vars.get_code_snippet(context=10),
                    finding=prompt_vars.formatted_finding,
                ),
            },
        ],
        temperature=0.2,
    )
    verdict_result = raw_verdict["choices"][0]["message"]["content"]
    logger.info("auto_triage.verdict.result", result=verdict_result)

    verdict_result = orjson.loads(re.findall("{.+}", verdict_result)[0])
    if verdict_result["type"] not in {"true_positive", "false_positive"}:
        raise ValueError(f"Unexpected result type: {verdict_result['type']}")
    if not isinstance(verdict_result.get("reason"), str | None):
        raise ValueError(f"Unexpected result reason: {verdict_result['reason']}")

    if verdict_result["type"] != "true_positive":
        return AutoTriageResult(**verdict_result)

    code_before = prompt_vars.get_code_snippet(context=0, with_issue_marker=False)
    dedented_code_before = textwrap.dedent(code_before)
    indent_size = len(code_before.splitlines()[0]) - len(
        dedented_code_before.splitlines()[0]
    )

    fix_user_message = fix_prompt.format(
        pr_title=prompt_vars.pr_title,
        code=dedented_code_before,
        finding=prompt_vars.formatted_finding,
    )
    logger.info("auto_triage.fix.prompt", prompt=fix_user_message)
    fix = openai.ChatCompletion.create(  # type: ignore
        model="gpt-4",
        messages=[
            {
                "role": "system",
                "content": FIX_IDENTITY,
            },
            {
                "role": "user",
                "content": fix_user_message,
            },
        ],
        temperature=0.2,
    )

    fix_result = fix["choices"][0]["message"]["content"]
    code_block_re = re.compile(r"```.*?\n(.+)\n```", re.MULTILINE | re.DOTALL)
    code_after = code_block_re.findall(fix_result)[0]
    indented_code_after = textwrap.indent(code_after, " " * indent_size)

    diff = list(
        difflib.unified_diff(
            [line.rstrip() + "\n" for line in code_before.splitlines()],
            [line.rstrip() + "\n" for line in indented_code_after.splitlines()],
            fromfile="original code",
            tofile="Semgrep Assistant suggestion",
        )
    )

    fix_result = {"fix_diff": "".join(diff), "fix_code": indented_code_after}
    logger.info("auto_triage.fix.result", **fix_result)

    return AutoTriageResult(**verdict_result, **fix_result)


if __name__ == "__main__":
    import sys

    from semgrep_app.app import app

    deployment_id, issue_id = (int(part) for part in sys.argv[1].split(":"))

    with app.app_context():
        deployment = Deployment.unsafe_find_without_identity(deployment_id)
        issue = deployment.issues.filter_by(id=issue_id).one()
        prompt_vars = IssuePromptVars(issue)
        triage_issue(prompt_vars)

    import psycopg2
    conn = psycopg2.connect(
        import os

        # Ensure that the environment variable DB_PASSWORD is set in your environment
        conn = psycopg2.connect(
            "dbname=test user=postgres password=" + os.getenv('DB_PASSWORD')
        )
    )
