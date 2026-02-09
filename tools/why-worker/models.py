"""Data models matching worker-request.schema.json and worker-response.schema.json."""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EvidenceType(str, Enum):
    K8S_FIELD = "K8S_FIELD"
    IMAGE_SCAN = "IMAGE_SCAN"
    SBOM = "SBOM"
    POLICY = "POLICY"
    OTHER = "OTHER"


@dataclass
class ResourceRef:
    kind: str
    name: str
    namespace: str
    uid: Optional[str] = None
    apiVersion: Optional[str] = None


@dataclass
class Evidence:
    type: str
    subject: str
    detail: str
    raw: Optional[Dict[str, Any]] = None


@dataclass
class PatchSuggestion:
    format: str
    content: str


@dataclass
class Fix:
    title: str
    detail: str
    patch: Optional[PatchSuggestion] = None


@dataclass
class PolicyFinding:
    policyId: str
    title: str
    severity: str
    message: str
    evidence: List[Evidence] = field(default_factory=list)
    suggestedFixes: List[Fix] = field(default_factory=list)


@dataclass
class WorkerRequestInput:
    resource: ResourceRef
    imageRefs: Optional[List[str]] = None
    policyFindings: Optional[List[PolicyFinding]] = None
    rawContext: Optional[Dict[str, Any]] = None


@dataclass
class WorkerRequest:
    version: str
    requestId: str
    input: WorkerRequestInput
    locale: Optional[str] = None
    provider: Optional[str] = None


@dataclass
class ViolationTranslation:
    policyId: str
    title: str
    message: str


@dataclass
class ActionTranslation:
    title: str
    detail: str


@dataclass
class Translations:
    summary: Optional[str] = None
    violations: Optional[List[ViolationTranslation]] = None
    nextActions: Optional[List[ActionTranslation]] = None


@dataclass
class Violation:
    policyId: str
    title: str
    severity: str
    message: str
    evidence: Optional[List[Evidence]] = None
    fix: Optional[List[Fix]] = None


@dataclass
class NextAction:
    title: str
    detail: str
    patch: Optional[PatchSuggestion] = None


@dataclass
class DecisionAdditions:
    summary: Optional[str] = None
    violations: Optional[List[Violation]] = None
    nextActions: Optional[List[NextAction]] = None
    translations: Optional[Translations] = None


@dataclass
class WorkerResponse:
    version: str
    requestId: str
    decisionAdditions: Optional[DecisionAdditions] = None


def dict_to_resource_ref(data: Dict[str, Any]) -> ResourceRef:
    return ResourceRef(
        kind=data["kind"],
        name=data["name"],
        namespace=data["namespace"],
        uid=data.get("uid"),
        apiVersion=data.get("apiVersion"),
    )


def dict_to_evidence(data: Dict[str, Any]) -> Evidence:
    return Evidence(
        type=data["type"],
        subject=data["subject"],
        detail=data["detail"],
        raw=data.get("raw"),
    )


def dict_to_patch(data: Dict[str, Any]) -> PatchSuggestion:
    return PatchSuggestion(format=data["format"], content=data["content"])


def dict_to_fix(data: Dict[str, Any]) -> Fix:
    patch = dict_to_patch(data["patch"]) if data.get("patch") else None
    return Fix(title=data["title"], detail=data["detail"], patch=patch)


def dict_to_policy_finding(data: Dict[str, Any]) -> PolicyFinding:
    evidence = [dict_to_evidence(e) for e in data.get("evidence", [])]
    fixes = [dict_to_fix(f) for f in data.get("suggestedFixes", [])]
    return PolicyFinding(
        policyId=data["policyId"],
        title=data["title"],
        severity=data["severity"],
        message=data["message"],
        evidence=evidence,
        suggestedFixes=fixes,
    )


def dict_to_request_input(data: Dict[str, Any]) -> WorkerRequestInput:
    policy_findings = None
    if data.get("policyFindings"):
        policy_findings = [dict_to_policy_finding(pf) for pf in data["policyFindings"]]
    return WorkerRequestInput(
        resource=dict_to_resource_ref(data["resource"]),
        imageRefs=data.get("imageRefs"),
        policyFindings=policy_findings,
        rawContext=data.get("rawContext"),
    )


def dict_to_worker_request(data: Dict[str, Any]) -> WorkerRequest:
    return WorkerRequest(
        version=data["version"],
        requestId=data["requestId"],
        input=dict_to_request_input(data["input"]),
        locale=data.get("locale"),
        provider=data.get("provider"),
    )


def to_json_dict(obj: Any) -> Any:
    """Convert dataclass tree to JSON-serializable dict, omitting None values."""
    if obj is None:
        return None
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, list):
        return [to_json_dict(item) for item in obj]
    if isinstance(obj, dict):
        return {k: to_json_dict(v) for k, v in obj.items() if v is not None}
    if hasattr(obj, "__dataclass_fields__"):
        return {
            name: to_json_dict(getattr(obj, name))
            for name in obj.__dataclass_fields__
            if getattr(obj, name) is not None
        }
    return obj
