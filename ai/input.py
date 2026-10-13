
from .models import VulnerabilityInput
from .normalization import normalize_vulnerability_type


def validate_vulnerability(data):
    finding = VulnerabilityInput(**data)

    normalized_vulnerability = normalize_vulnerability_type(
        finding.vulnerability
    )

    return finding.model_copy(
        update={"vulnerability": normalized_vulnerability}
    )
