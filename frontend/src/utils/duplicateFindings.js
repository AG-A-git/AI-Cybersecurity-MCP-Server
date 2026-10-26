export const deduplicateFindings = (findings = []) => {
  const uniqueFindings = new Map();

  for (const finding of findings) {
    const key = [
      finding.file ?? finding.file_name ?? finding.filename ?? "",
      finding.line ?? finding.line_number ?? "",
      finding.vulnerability ?? finding.vulnerability_type ?? finding.type ?? "",
      finding.code ?? finding.vulnerable_code ?? "",
    ]
      .join("|")
      .toLowerCase();

    if (!uniqueFindings.has(key)) {
      uniqueFindings.set(key, finding);
    }
  }

  return Array.from(uniqueFindings.values());
};