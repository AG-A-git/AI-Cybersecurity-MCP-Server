# Scanner Integration Contract

## Overview

The backend sends uploaded project information to the vulnerability scanner.

The scanner analyzes the source code and returns standardized vulnerability results.

---

## Backend → Scanner

### Request

```json
{
    "project_id": 5,
    "path": "uploads/extracted/project1",
    "language": "python"
}