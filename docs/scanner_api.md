# Scanner API

## Overview

The scanner provides a single entry point for scanning an individual source
file or an entire project directory.

The backend can use:

```python
from scanner.engine import scan_project

results = scan_project(project_path)