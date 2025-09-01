import os
import subprocess
import tempfile
import shutil
import pathlib
import json
import logging
from git import Repo

logger = logging.getLogger(__name__)




def locate_secret_in_repo(repo_path, raw_secret):
    """Fallback: search repo for the raw secret and return file + line if found."""
    if not raw_secret:
        return None, None

    for file_path in pathlib.Path(repo_path).rglob("*"):
        try:
            if file_path.is_file():
                with open(file_path, "r", errors="ignore") as f:
                    for i, line in enumerate(f, start=1):
                        if raw_secret in line:
                            return str(file_path), i
        except (UnicodeDecodeError, PermissionError, IsADirectoryError):
            continue
    return None, None


def run_credential_scan_agent(repo_path):
    """Scan repository for secrets using Trufflehog (with line numbers if available)."""
    findings = []

    try:
        # Try v3 syntax first
        result = subprocess.run(
            ["trufflehog", "filesystem", "--path", repo_path, "--json"],
            capture_output=True,
            text=True
        )

        # If CLI doesn’t like --path (old version), retry with v2 syntax
        if result.returncode != 0 and "unknown long flag '--path'" in result.stderr:
            result = subprocess.run(
                ["trufflehog", "filesystem", repo_path, "--json"],
                capture_output=True,
                text=True
            )

        # Parse JSON line by line
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                logger.debug(f"Skipping non-JSON line: {line[:100]}...")
                continue

            file = (
                data.get("SourceMetadata", {})
                .get("Data", {})
                .get("file")
            )
            line_no = (
                data.get("SourceMetadata", {})
                .get("Data", {})
                .get("line")
            )
            raw = data.get("Raw")

            # Fallback if file/line missing
            if (not file or not line_no) and raw:
                file, line_no = locate_secret_in_repo(repo_path, raw)

            findings.append({
                "file": file,
                "line": line_no,
                "detector": data.get("DetectorName"),
                "raw": raw,
            })

    except FileNotFoundError:
        return {
            "agent": "credential_scan",
            "score": 0,
            "details": [{"error": "Trufflehog not found. Is it installed and in PATH?"}]
        }
    except Exception as e:
        logger.exception("Credential scan failed")
        return {
            "agent": "credential_scan",
            "score": 0,
            "details": [{"error": f"Trufflehog scan failed: {str(e)}"}]
        }

    score = min(len(findings), 25)

    return {
        "agent": "credential_scan",
        "score": score,
        "details": findings[:20] if findings else [{"info": "No secrets found"}]
    }


def scan_github_repo(repo_url):
    """Clone a GitHub repo and run secret scanning."""
    temp_dir = tempfile.mkdtemp()
    try:
        repo_path = os.path.join(temp_dir, "repo")
        logger.info(f"Cloning {repo_url} into {repo_path}")
        Repo.clone_from(repo_url, repo_path)
        
        results = run_credential_scan_agent(repo_path)
        return results
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    # Example usage
    test_repo = "https://github.com/parthv18/testing.git"  # Example repo with test secrets
    report = scan_github_repo(test_repo)
    print(json.dumps(report, indent=2))


