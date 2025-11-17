import re
from typing import List, Dict, Any

UNPINNED_REGEX = re.compile(
    r'uses:\s*([\w./-]+)(?:@([\w.-]+))?', 
    re.IGNORECASE
)

CURL_BASH_REGEX = re.compile(
    r'\b(curl|wget)\b.*\|\s*(bash|sh|zsh)\b', 
    re.IGNORECASE
)

BASE64_REGEX = re.compile(
    r'base64\s+-d|[A-Za-z0-9+/]{40,}={0,2}',
    re.IGNORECASE
)


SECRET_REGEX = re.compile(
    r'\${{\s*secrets\.[A-Za-z0-9_]+\s*}}',
    re.IGNORECASE
)

LONG_INLINE_THRESHOLD = 200

def detectUnpinnedActions(yamlText: str) -> List[Dict[str, Any]]:
    findings = []
    for m in UNPINNED_REGEX.finditer(yamlText):
        uses = m.group(1)
        ref = m.group(2)

        # Ignore local actions
        if uses.startswith("./"):
            continue

        if not ref:
            findings.append({
                "type": "unpinned_action",
                "message": f"Action `{uses}` used without a pinned ref (no @sha or tag).",
                "match": m.group(0),
            })
        else:
            if not re.match(r'^[0-9a-f]{7,40}$', ref):  # Not a SHA
                findings.append({
                    "type": "unpinned_action",
                    "message": f"Action `{uses}@{ref}` is not pinned to a commit SHA.",
                    "match": m.group(0),
                })

    return findings


def detectCurlBash(yamlText: str) -> List[Dict[str, Any]]:
    findings = []
    for m in CURL_BASH_REGEX.finditer(yamlText):
        findings.append({
            "type": "curl_pipe_bash",
            "message": "Use of curl/wget piped to shell detected.",
            "match": m.group(0),
        })
    return findings


def detectBase64Obfuscation(yamlText: str) -> List[Dict[str, Any]]:
    findings = []
    for m in BASE64_REGEX.finditer(yamlText):
        if len(m.group(0)) > 60:
            findings.append({
                "type": "base64_obfuscation",
                "message": "Possible base64 obfuscation detected",
                "match": m.group(0)[:200],
            })
    return findings

def detectSecretExposure(yamlText: str) -> List[Dict[str, Any]]:
    findings = []
    for m in SECRET_REGEX.finditer(yamlText):
        findings.append({
            "type": "secret_exposure",
            "message": "Potential secret exposure: secrets are printed or echoed.",
            "match": m.group(0),
        })
    return findings


def detectLongInlineScripts(yamlParsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []
    jobs = yamlParsed.get("jobs", {})

    for jobName, job in jobs.items():
        steps = job.get("steps", [])
        for step in steps:
            run = step.get("run")
            if run and isinstance(run, str) and len(run) > LONG_INLINE_THRESHOLD:
                findings.append({
                    "type": "long_inline_script",
                    "message": f"Long inline script in job `{jobName}` step `{step.get('name','(unnamed)')}`.",
                    "length": len(run),
                    "snippet": run[:200],
                })

    return findings


def detectDangerousPermissions(yamlParsed: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings = []

    # Top-level permissions
    top = yamlParsed.get("permissions")
    if isinstance(top, str) and top.lower() == "write-all":
        findings.append({
            "type": "dangerous_permissions",
            "message": "Workflow uses dangerous top-level permission: write-all.",
        })

    # Job-level permissions
    jobs = yamlParsed.get("jobs", {})
    for jobName, job in jobs.items():
        perms = job.get("permissions")
        if isinstance(perms, str) and perms.lower() == "write-all":
            findings.append({
                "type": "dangerous_permissions",
                "message": f"Job `{jobName}` uses dangerous permission: write-all.",
            })

    return findings


def detectAll(yamlText: str, yamlParsed: Dict[str, Any], filename: str) -> List[Dict[str, Any]]:
    if yamlParsed is None:
        yamlParsed = {}

    findings = []
    findings.extend(detectUnpinnedActions(yamlText))
    findings.extend(detectCurlBash(yamlText))
    findings.extend(detectBase64Obfuscation(yamlText))
    findings.extend(detectSecretExposure(yamlText))
    findings.extend(detectLongInlineScripts(yamlParsed))
    findings.extend(detectDangerousPermissions(yamlParsed))

    for f in findings:
        f["file"] = filename

    return findings
