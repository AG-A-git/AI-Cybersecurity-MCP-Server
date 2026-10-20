import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { getProjects } from "../services/projectService";
import { getScans, getScanResults } from "../services/scanService";
import { downloadScanReport } from "../services/reportService";

import LoadingState from "../components/LoadingState";
import ErrorState from "../components/ErrorState";
import EmptyState from "../components/EmptyState";

const getFindings = (data) => {
    if (Array.isArray(data?.vulnerabilities)) {
        return data.vulnerabilities;
    }

    if (Array.isArray(data?.findings)) {
        return data.findings;
    }

    if (Array.isArray(data?.results?.vulnerabilities)) {
        return data.results.vulnerabilities;
    }

    if (Array.isArray(data?.results?.findings)) {
        return data.results.findings;
    }

    if (Array.isArray(data?.results)) {
        return data.results;
    }

    return [];
};

const getFindingKey = (finding) => {
    const normalize = (value) =>
        String(value ?? "")
            .trim()
            .replace(/\\/g, "/")
            .replace(/\s+/g, " ")
            .toLowerCase();

    return JSON.stringify([
        normalize(
            finding.file_name ??
                finding.filename ??
                finding.file
        ),
        normalize(finding.line_number ?? finding.line),
        normalize(
            finding.vulnerability_type ??
                finding.vulnerability ??
                finding.type
        ),
        normalize(finding.severity),
        normalize(
            finding.code ??
                finding.vulnerable_code ??
                finding.source_code ??
                finding.snippet
        ),
    ]);
};

const removeDuplicateFindings = (findings) => {
    const seen = new Set();

    return findings.filter((finding) => {
        const key = getFindingKey(finding);

        if (seen.has(key)) {
            return false;
        }

        seen.add(key);
        return true;
    });
};

const getProjectList = (data) => {
    if (Array.isArray(data)) return data;
    if (Array.isArray(data?.projects)) return data.projects;
    if (Array.isArray(data?.results)) return data.results;
    if (Array.isArray(data?.data)) return data.data;
    return [];
};

const getScanList = (data) => {
    if (Array.isArray(data)) return data;
    if (Array.isArray(data?.scans)) return data.scans;
    if (Array.isArray(data?.results)) return data.results;
    if (Array.isArray(data?.data)) return data.data;
    return [];
};

const getScanId = (scan) => scan?.id ?? scan?.scan_id;

const getScanStatus = (scan) =>
    scan?.status ?? scan?.scan_status ?? scan?.state ?? "Unknown";

const getScanFindings = (scan) => {
    const findings =
        scan?.findings ??
        scan?.vulnerabilities ??
        scan?.results;

    if (Array.isArray(findings)) {
        return findings;
    }

    if (Array.isArray(findings?.findings)) {
        return findings.findings;
    }

    if (Array.isArray(findings?.vulnerabilities)) {
        return findings.vulnerabilities;
    }

    return [];
};

const getSummaryFindingCount = (scan) => {
    const count =
        scan?.total_findings ??
        scan?.finding_count ??
        scan?.findings_count ??
        scan?.vulnerability_count ??
        scan?.total_vulnerabilities;

    if (count === null || count === undefined || count === "") {
        return null;
    }

    const parsed = Number(count);

    return Number.isFinite(parsed) && parsed >= 0
        ? parsed
        : null;
};

const getErrorMessage = (error, fallback) => {
    if (error?.userMessage) {
        return error.userMessage;
    }

    const detail = error?.response?.data?.detail;

    if (typeof detail === "string" && detail.trim()) {
        return detail;
    }

    if (typeof error?.message === "string" && error.message.trim()) {
        return error.message;
    }

    return fallback;
};

function Reports() {
    const navigate = useNavigate();

    const [projects, setProjects] = useState([]);
    const [scans, setScans] = useState([]);
    const [findingCounts, setFindingCounts] = useState({});
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState("");
    const [exportError, setExportError] = useState("");
    const [exportingScanId, setExportingScanId] = useState(null);
    const [exportingFormat, setExportingFormat] = useState(null);

    const loadReports = useCallback(async () => {
        setLoading(true);
        setError("");

        try {
            const [projectsResult, scansResult] =
                await Promise.allSettled([
                    getProjects(),
                    getScans(),
                ]);

            if (projectsResult.status === "rejected") {
                throw projectsResult.reason;
            }

            const projectData =
                projectsResult.value?.data ?? projectsResult.value;

            const projectList = getProjectList(projectData);
            setProjects(projectList);

            if (scansResult.status === "rejected") {
                throw scansResult.reason;
            }

            const scanData =
                scansResult.value?.data ?? scansResult.value;

            const scanList = getScanList(scanData);
            setScans(scanList);

            const initialCounts = {};

            scanList.forEach((scan) => {
                const id = getScanId(scan);

                if (id == null) return;

                const findings = getScanFindings(scan);
                const summaryCount = getSummaryFindingCount(scan);

                if (findings.length > 0) {
                    initialCounts[id] =
                        removeDuplicateFindings(findings).length;
                } else if (summaryCount !== null) {
                    initialCounts[id] = summaryCount;
                }
            });

            setFindingCounts(initialCounts);

            const detailResults = await Promise.allSettled(
                scanList
                    .filter((scan) => getScanId(scan) != null)
                    .map(async (scan) => {
                        const id = getScanId(scan);
                        const details = await getScanResults(id);

                        return { id, details };
                    })
            );

            const resolvedCounts = { ...initialCounts };

            detailResults.forEach((result) => {
                if (result.status !== "fulfilled") {
                    console.warn(
                        "Could not retrieve scan finding count:",
                        result.reason
                    );
                    return;
                }

                const { id, details } = result.value;
                const findings = getFindings(details);

                if (findings.length > 0) {
                    resolvedCounts[id] =
                        removeDuplicateFindings(findings).length;
                } else {
                    const summaryCount =
                        getSummaryFindingCount(details);

                    if (summaryCount !== null) {
                        resolvedCounts[id] = summaryCount;
                    } else if (initialCounts[id] === undefined) {
                        delete resolvedCounts[id];
                    }
                }
            });

            setFindingCounts(resolvedCounts);
        } catch (err) {
            console.error("Failed to load reports:", err);

            setError(
                getErrorMessage(
                    err,
                    "Unable to load report data. Check your backend connection."
                )
            );
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        loadReports();
    }, [loadReports]);

    const getProjectName = (projectId, scan = null) => {
        const project = projects.find(
            (item) =>
                String(item.id ?? item.project_id) ===
                String(projectId)
        );

        return (
            scan?.project_name ??
            scan?.project?.name ??
            project?.project_name ??
            project?.name ??
            project?.title ??
            `Project ${projectId ?? "Unknown"}`
        );
    };

    const getFindingCount = (scan) => {
        const id = getScanId(scan);

        if (
            id != null &&
            findingCounts[id] !== undefined
        ) {
            return findingCounts[id];
        }

        const findings = getScanFindings(scan);

        if (findings.length > 0) {
            return removeDuplicateFindings(findings).length;
        }

        const summaryCount = getSummaryFindingCount(scan);

        return summaryCount !== null
            ? summaryCount
            : "Not available";
    };

    const downloadReport = async (selectedScan, format = "pdf") => {
        const scanId = getScanId(selectedScan);
        const normalizedFormat = String(format).toLowerCase();

        setExportError("");

        if (
            scanId == null ||
            String(scanId).trim() === "" ||
            !Number.isInteger(Number(scanId)) ||
            Number(scanId) <= 0
        ) {
            setExportError(
                "A valid scan ID is required to export this report."
            );
            return;
        }

        if (!["json", "html", "pdf"].includes(normalizedFormat)) {
            setExportError("Unsupported report format.");
            return;
        }

        setExportingScanId(scanId);
        setExportingFormat(normalizedFormat);

        let objectUrl;

        try {
            const response = await downloadScanReport(
                scanId,
                normalizedFormat
            );

            const blob = response.data;

            if (!(blob instanceof Blob) || blob.size === 0) {
                throw new Error(
                    "The backend returned an empty report."
                );
            }

            objectUrl = URL.createObjectURL(blob);

            const link = document.createElement("a");
            link.href = objectUrl;
            link.download = `scan-report-${scanId}.${normalizedFormat}`;
            link.style.display = "none";

            document.body.appendChild(link);

            try {
                link.click();
            } finally {
                link.remove();
            }
        } catch (err) {
            console.error("Failed to download scan report:", err);

            setExportError(
                getErrorMessage(
                    err,
                    `Unable to download the ${normalizedFormat.toUpperCase()} report. Please try again.`
                )
            );
        } finally {
            if (objectUrl) {
                window.setTimeout(
                    () => URL.revokeObjectURL(objectUrl),
                    1000
                );
            }

            setExportingScanId(null);
            setExportingFormat(null);
        }
    };

    if (loading) {
        return (
            <main className="p-4 sm:p-6">
                <h1 className="mb-4 text-2xl font-bold">Reports</h1>
                <LoadingState message="Loading report data..." />
            </main>
        );
    }

    if (error) {
        return (
            <main className="mx-auto max-w-6xl p-4 sm:p-6">
                <h1 className="mb-4 text-2xl font-bold">Reports</h1>
                <ErrorState
                    message={error}
                    onRetry={loadReports}
                />
            </main>
        );
    }

    const completedScans = scans.filter((scan) =>
        ["completed", "complete", "success", "successful"].includes(
            String(getScanStatus(scan)).toLowerCase()
        )
    );

    return (
        <main className="mx-auto max-w-6xl space-y-8 p-4 sm:p-6">
            <header>
                <h1 className="text-2xl font-bold">Reports</h1>
                <p className="mt-1 text-gray-600">
                    Review projects, scan activity, and export security findings.
                </p>
            </header>

            {exportError && (
                <div
                    role="alert"
                    className="rounded-lg border border-red-200 bg-red-50 p-3 text-red-700"
                >
                    <div className="flex items-center justify-between gap-3">
                        <p>{exportError}</p>
                        <button
                            type="button"
                            className="shrink-0 rounded border border-red-300 px-3 py-1 text-sm"
                            onClick={() => setExportError("")}
                        >
                            Dismiss
                        </button>
                    </div>
                </div>
            )}

            <section className="grid grid-cols-1 gap-4 sm:grid-cols-3">
                {[
                    { label: "Total Projects", value: projects.length },
                    { label: "Total Scans", value: scans.length },
                    {
                        label: "Completed Scans",
                        value: completedScans.length,
                    },
                ].map((item) => (
                    <article
                        key={item.label}
                        className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm"
                    >
                        <h2 className="text-sm font-medium text-gray-600">
                            {item.label}
                        </h2>
                        <p className="mt-2 text-3xl font-bold">
                            {item.value}
                        </p>
                    </article>
                ))}
            </section>

            <section className="space-y-4">
                <h2 className="text-xl font-semibold">Project Summary</h2>

                {projects.length === 0 ? (
                    <EmptyState
                        title="No projects found"
                        message="Create a project before generating reports."
                        buttonText="Go to Projects"
                        onButtonClick={() => navigate("/projects")}
                    />
                ) : (
                    <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
                        {projects.map((project, index) => {
                            const projectId =
                                project.id ?? project.project_id;

                            const projectScans = scans.filter(
                                (scan) =>
                                    String(
                                        scan.project_id ??
                                        scan.project?.id
                                    ) === String(projectId)
                            );

                            return (
                                <article
                                    key={projectId ?? `project-${index}`}
                                    className="overflow-hidden rounded-xl border border-gray-200 bg-white p-5 shadow-sm"
                                >
                                    <h3 className="break-words text-lg font-semibold">
                                        {project.project_name ??
                                            project.name ??
                                            project.title ??
                                            `Project ${projectId}`}
                                    </h3>

                                    <p className="mt-2 text-sm text-gray-600">
                                        Project ID: {projectId ?? "Not available"}
                                    </p>

                                    <p className="mt-2 break-words text-sm text-gray-600">
                                        {project.description ?? "No description"}
                                    </p>

                                    <p className="mt-3 text-sm">
                                        Total scans: {projectScans.length}
                                    </p>

                                    <button
                                        type="button"
                                        className="mt-4 rounded-lg bg-blue-600 px-4 py-2 text-white hover:bg-blue-700"
                                        onClick={() => {
                                            localStorage.setItem(
                                                "selected_project_id",
                                                String(projectId)
                                            );
                                            navigate("/upload");
                                        }}
                                    >
                                        Open Project
                                    </button>
                                </article>
                            );
                        })}
                    </div>
                )}
            </section>

            <section className="space-y-4">
                <h2 className="text-xl font-semibold">Scan Reports</h2>

                {scans.length === 0 ? (
                    <EmptyState
                        title="No scans found"
                        message="Upload a file and start a scan first."
                        buttonText="Go to Projects"
                        onButtonClick={() => navigate("/projects")}
                    />
                ) : (
                    <div className="overflow-x-auto rounded-xl border border-gray-200">
                        <table className="w-full min-w-[650px] border-collapse text-left">
                            <thead className="bg-gray-50">
                                <tr>
                                    {[
                                        "Scan ID",
                                        "Project",
                                        "Status",
                                        "Findings",
                                        "Actions",
                                    ].map((heading) => (
                                        <th
                                            key={heading}
                                            className="border-b border-gray-200 p-3 text-sm font-semibold"
                                        >
                                            {heading}
                                        </th>
                                    ))}
                                </tr>
                            </thead>

                            <tbody>
                                {scans.map((scan, index) => {
                                    const scanId = getScanId(scan);

                                    return (
                                        <tr key={scanId ?? index}>
                                            <td className="border-b border-gray-100 p-3">
                                                {scanId ?? "N/A"}
                                            </td>

                                            <td className="border-b border-gray-100 p-3">
                                                {getProjectName(
                                                    scan.project_id ??
                                                        scan.project?.id,
                                                    scan
                                                )}
                                            </td>

                                            <td className="border-b border-gray-100 p-3">
                                                {getScanStatus(scan)}
                                            </td>

                                            <td className="border-b border-gray-100 p-3">
                                                {getFindingCount(scan)}
                                            </td>

                                            <td className="border-b border-gray-100 p-3">
                                                <div className="flex flex-wrap gap-2">
                                                    <button
                                                        type="button"
                                                        disabled={scanId == null}
                                                        className="rounded-md border border-gray-300 px-3 py-2 text-sm disabled:opacity-50"
                                                        onClick={() => {
                                                            navigate("/results", {
                                                                state: {
                                                                    scanId,
                                                                    result: scan,
                                                                },
                                                            });
                                                        }}
                                                    >
                                                        View Results
                                                    </button>

                                                    {["json", "html", "pdf"].map(
                                                        (format) => {
                                                            const isExporting =
                                                                String(exportingScanId) ===
                                                                    String(scanId) &&
                                                                exportingFormat === format;

                                                            return (
                                                                <button
                                                                    key={format}
                                                                    type="button"
                                                                    disabled={
                                                                        exportingScanId !== null ||
                                                                        scanId == null
                                                                    }
                                                                    className="rounded-md bg-blue-600 px-3 py-2 text-sm text-white hover:bg-blue-700 disabled:opacity-50"
                                                                    onClick={() =>
                                                                        downloadReport(
                                                                            scan,
                                                                            format
                                                                        )
                                                                    }
                                                                >
                                                                    {isExporting
                                                                        ? "Exporting..."
                                                                        : `Export ${format.toUpperCase()}`}
                                                                </button>
                                                            );
                                                        }
                                                    )}
                                                </div>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </section>

            <div className="flex flex-wrap gap-3">
                <button
                    type="button"
                    className="rounded-lg border border-gray-300 px-4 py-2"
                    onClick={loadReports}
                >
                    Refresh Reports
                </button>

                <button
                    type="button"
                    className="rounded-lg border border-gray-300 px-4 py-2"
                    onClick={() => navigate("/projects")}
                >
                    Go to Projects
                </button>

                <button
                    type="button"
                    className="rounded-lg border border-gray-300 px-4 py-2"
                    onClick={() => navigate("/dashboard")}
                >
                    Back to Dashboard
                </button>
            </div>
        </main>
    );
}

export default Reports;