# AI Integration Contract

## Overview

This document defines the interface between the security scanner,
AI analysis module, and backend.

The AI module accepts standardized vulnerability findings from
Member 2's scanner and returns structured security analysis results.

---

# Architecture

```text
Source Code
    |
    v
Member 2 Scanner
    |
    v
Standardized Vulnerability JSON
    |
    v
VulnerabilityInput
    |
    v
Member 3 AI Analysis
    |
    +--> Input Validation
    |
    +--> Risk Scoring
    |
    +--> Ollama / LLM
    |
    +--> Explanation
    |
    +--> Recommendation
    |
    v
Structured AI Result
    |
    v
Member 1 Backend
    |
    v
Member 4 Frontend