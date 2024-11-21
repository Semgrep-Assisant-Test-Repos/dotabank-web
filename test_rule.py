from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest
import structlog

from semgrep_app.ai.chains.rule_generation import run
from semgrep_app.ai.inputs import RuleVars

file_extensions = {
    "python": "py",
    "javascript": "js",
    "java": "java",
    "c": "c",
    "cpp": "cpp",
    "kotlin": "kt",
}

logger = structlog.get_logger()


@pytest.mark.parametrize(
    "rule_vars",
    [
        RuleVars(
            message="Setting an element's innerHTML to a non-constant value is insecure",
            language="typescript",
            bad_code="function x(el) { el.innerHTML = '<div>' + userInput + '</div>';}",
            good_code="function x(el) { el.innerHTML = '<div>this is ok</div>';}",
        ),
        RuleVars(
            message="AWS secret access key committed in repository",
            language="python",
            bad_code="from boto3 import client\nclient('s3', aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')",
            good_code="boto3.sessions.Session(aws_secret_access_key=os.environ.get('AWS_SECRET_KEY'))",
        ),
        RuleVars(
            message="The save method of Django models must always call super().save()",
            language="python",
            bad_code="class Post(models.Model):\n    def save(self, *args, **kwargs):\n        if not self.slug:\n            self.slug = slugify(self.title)",
            good_code="class Post(models.Model):\n    def save(self, *args, **kwargs):\n        if not self.slug:\n            self.slug = slugify(self.title)\n        super(Post, self).save(*args, **kwargs)",
        ),
    ],
    ids=lambda rule_vars: rule_vars.message,
)
def test_rule_generation(rule_vars: RuleVars, tmp_path: Path) -> None:
    rule_yaml = run(rule_vars)
    (tmp_path / "rule.yaml").write_text(rule_yaml)
    (tmp_path / "bad_code.txt").write_text(rule_vars.bad_code)
    (tmp_path / "good_code.txt").write_text(rule_vars.good_code)
    output_str = subprocess.check_output(
        [
            "semgrep",
            "--json",
            "--scan-unknown-extensions",
            "--config",
            "rule.yaml",
            "bad_code.txt",
            "good_code.txt",
        ],
        cwd=tmp_path,
    )
    output = json.loads(output_str.decode())
    logger.info(f"Handling query console request:\n{output}")
    assert not output["errors"], "rule is not valid"
    assert output["results"], "did not match the bad code"
    for result in output["results"]:
        assert result["path"] == "bad_code.txt", "matched the good code"


def check_top_level_component(
    yaml_string: str,
    rule_var: RuleVars,
    delimiter: str = "==========",
) -> bool:
    # data = yaml.load(yaml_string)
    good_code = rule_var.good_code
    bad_code = rule_var.bad_code
    language = rule_var.language
    file_extension = file_extensions[language]
    rule_file = "/tmp/rule.yaml"
    good_code_file = f"/tmp/good_code.{file_extension}"
    bad_code_file = f"/tmp/bad_code.{file_extension}"
    if os.path.exists(good_code_file):
        os.remove(good_code_file)
    if os.path.exists(bad_code_file):
        os.remove(bad_code_file)
    if os.path.exists(rule_file):
        os.remove(rule_file)
    with open(good_code_file, "w") as f:
        good_code = good_code.replace(delimiter, "\n")
        f.write(good_code)
    with open(bad_code_file, "w") as f:
        bad_code = bad_code.replace(delimiter, "\n")
        f.write(bad_code)
    with open(rule_file, "w") as f:
        f.write(yaml_string)
    command = f"semgrep --json -c {rule_file} {bad_code_file} {good_code_file}"
    try:
        output = subprocess.check_output(
            command,
            shell=True,
        )
        text = output.decode("utf-8")
        json_data = json.loads(text)
        return not json_data["errors"]
    except subprocess.CalledProcessError as e:
        print("Errors in rule schema", e.returncode)
    return False
