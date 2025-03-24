"""Models for security findings and related data structures."""

import enum
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Union
from uuid import UUID, uuid4

from dataclasses_json import dataclass_json
from pydantic import BaseModel, Field


class Severity(enum.Enum):
    """Enumeration of finding severity levels."""
    
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


class RemediationDifficulty(enum.Enum):
    """Enumeration of remediation difficulty levels."""
    
    EASY = 1
    MODERATE = 2
    DIFFICULT = 3


@dataclass_json
@dataclass
class FrameworkMapping:
    """Mapping of a finding to a security framework."""
    
    framework: str
    """Name of the security framework (e.g., 'CWE', 'MITRE ATT&CK')."""
    
    id: str
    """ID within the framework (e.g., 'CWE-284' or 'T1078')."""
    
    name: str
    """Name of the mapped item in the framework."""
    
    url: Optional[str] = None
    """URL to the framework item documentation."""


@dataclass_json
@dataclass
class RemediationStep:
    """A specific remediation step for addressing a finding."""
    
    title: str
    """Short title for the remediation step."""
    
    description: str
    """Detailed description of the remediation step."""
    
    code: Optional[str] = None
    """Example code or command to perform the remediation."""
    
    code_language: Optional[str] = None
    """Language of the example code (e.g., 'bash', 'python')."""


@dataclass_json
@dataclass
class Remediation:
    """Remediation information for a finding."""
    
    summary: str
    """Brief summary of the remediation approach."""
    
    description: str
    """Detailed description of the remediation."""
    
    steps: List[RemediationStep] = field(default_factory=list)
    """Ordered list of remediation steps."""
    
    difficulty: RemediationDifficulty = RemediationDifficulty.MODERATE
    """Assessed difficulty of implementing the remediation."""
    
    links: List[str] = field(default_factory=list)
    """Reference links for remediation guidance."""


@dataclass_json
@dataclass
class Resource:
    """Represents a cloud resource with a finding."""
    
    id: str
    """Unique identifier for the resource."""
    
    name: str
    """Friendly name of the resource."""
    
    type: str
    """Resource type (e.g., 's3_bucket', 'virtual_machine')."""
    
    region: Optional[str] = None
    """Region/location where the resource is deployed."""
    
    arn: Optional[str] = None
    """Amazon Resource Name (ARN) if applicable."""
    
    properties: Dict[str, Any] = field(default_factory=dict)
    """Additional properties of the resource."""


@dataclass_json
@dataclass
class Finding:
    """Security finding representing a detected vulnerability or issue."""
    
    title: str
    """Short descriptive title of the finding."""
    
    description: str
    """Detailed description of the finding."""
    
    provider: str
    """Cloud provider (e.g., 'aws', 'azure')."""
    
    service: str
    """Cloud service (e.g., 's3', 'blob_storage')."""
    
    severity: Severity
    """Severity level of the finding."""
    
    id: UUID = field(default_factory=uuid4)
    """Unique identifier for the finding."""
    
    resources: List[Resource] = field(default_factory=list)
    """Affected cloud resources."""
    
    remediation: Optional[Remediation] = None
    """Remediation guidance if available."""
    
    framework_mappings: List[FrameworkMapping] = field(default_factory=list)
    """Mappings to security frameworks."""
    
    created_at: datetime = field(default_factory=datetime.utcnow)
    """Timestamp when the finding was created."""
    
    risk_score: float = 0.0
    """Normalized risk score (0.0-100.0)."""
    
    tags: Set[str] = field(default_factory=set)
    """Tags for categorization."""
    
    source: str = "cloudguard"
    """Source of the finding."""
    
    metadata: Dict[str, Any] = field(default_factory=dict)
    """Additional metadata about the finding."""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.
        
        Returns:
            Dictionary representation of the finding
        """
        data = json.loads(self.to_json())
        
        # Convert enum values to their string representations
        if 'severity' in data:
            if isinstance(data['severity'], int):
                severity_map = {
                    0: "INFO",
                    1: "LOW",
                    2: "MEDIUM",
                    3: "HIGH",
                    4: "CRITICAL"
                }
                data['severity'] = severity_map.get(data['severity'], "UNKNOWN")
            elif isinstance(data['severity'], dict) and 'name' in data['severity']:
                # Handle enum serialized as a dict with name field
                data['severity'] = data['severity']['name']
        
        # Convert UUID to string
        if 'id' in data:
            data['id'] = str(data['id'])
        
        # Ensure created_at is a string
        if 'created_at' in data and not isinstance(data['created_at'], str):
            data['created_at'] = data['created_at'].isoformat()
        
        return data
    
    def calculate_risk_score(self) -> float:
        """Calculate a normalized risk score based on severity and other factors.
        
        Returns:
            Risk score from 0.0 to 100.0
        """
        # Base score from severity
        severity_base = {
            Severity.CRITICAL: 90,
            Severity.HIGH: 70,
            Severity.MEDIUM: 50,
            Severity.LOW: 30,
            Severity.INFO: 10
        }
        
        base_score = severity_base[self.severity]
        
        # Adjust based on remediation difficulty if available
        if self.remediation:
            difficulty_factor = {
                RemediationDifficulty.EASY: 0.9,
                RemediationDifficulty.MODERATE: 1.0,
                RemediationDifficulty.DIFFICULT: 1.1
            }
            base_score *= difficulty_factor[self.remediation.difficulty]
        
        # Ensure the score is within bounds
        self.risk_score = max(0.0, min(100.0, base_score))
        return self.risk_score 