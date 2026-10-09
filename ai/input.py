from .models import VulnerabilityInput


def validate_vulnerability(data):
    return VulnerabilityInput(**data)
