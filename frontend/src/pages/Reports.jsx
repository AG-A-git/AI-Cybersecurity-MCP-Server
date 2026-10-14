
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { getProjects } from "../services/projectService";
import {
    getScans,
    getScanResults,
} from "../services/scanService";

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
        normalize(finding.file_name ?? finding.filename ?? finding.file),
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

const getScanId = (scan) => scan.id ?? scan.scan_id;

const getScanStatus = (scan) =>
    scan.status ?? scan.scan_status ?? scan.state ?? "Unknown";

const getScanFindings = (scan) => {
    const findings =
        scan.findings ??
        scan.vulnerabilities ??
        scan.results;

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
        scan.total_findings ??
        scan.finding_count ??
        scan.findings_count ??
        scan.vulnerability_count ??
        scan.total_vulnerabilities;

    if (count === null || count === undefined || count === "") {
        return null;
    }

    const parsed = Number(count);

    return Number.isFinite(parsed) && parsed >= 0
        ? parsed
        : null;
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

            const projectData = projectsResult.value?.data ??
                projectsResult.value;

            const projectList = getProjectList(projectData);
            setProjects(projectList);

            if (scansResult.status === "rejected") {
                throw scansResult.reason;
            }

            const scanData = scansResult.value?.data ??
                scansResult.value;

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
                err.userMessage ??
                    err.response?.data?.detail ??
                    "Unable to load report data. Check your backend connection."
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

    const downloadReport = async (selectedScan) => {
        const scanId = getScanId(selectedScan);

        setExportError("");

        if (scanId == null) {
            setExportError("The scan ID is unavailable.");
            return;
        }

        setExportingScanId(scanId);

        try {
            const details = await getScanResults(scanId);

            const uniqueFindings = removeDuplicateFindings(
                getFindings(details)
            );

            const projectId =
                details.project_id ??
                selectedScan.project_id ??
                details.project?.id ??
                selectedScan.project?.id ??
                null;

            let projectName = getProjectName(projectId, {
                ...selectedScan,
                ...details,
            });

            if (
                projectName ===
                    `Project ${projectId ?? "Unknown"}` &&
                projectId != null
            ) {
                try {
                    const projectsResponse = await getProjects();

                    const projectList = getProjectList(
                        projectsResponse?.data ?? projectsResponse
                    );

                    const project = projectList.find(
                        (item) =>
                            String(item.id ?? item.project_id) ===
                            String(projectId)
                    );

                    projectName =
                        project?.project_name ??
                        project?.name ??
                        project?.title ??
                        projectName;
                } catch (projectError) {
                    console.error(
                        "Could not resolve project name:",
                        projectError
                    );
                }
            }

            const report = {
                report_generated_at: new Date().toISOString(),
                scan_id: details.id ?? details.scan_id ?? scanId,
                project_id: projectId,
                project_name: projectName,
                scan_status:
                    details.status ??
                    details.scan_status ??
                    getScanStatus(selectedScan),
                findings: uniqueFindings.map((finding) => ({
                    id: finding.id ?? null,
                    file_name:
                        finding.file_name ??
                        finding.filename ??
                        finding.file ??
                        "Unknown",
                    line_number:
                        finding.line_number ??
                        finding.line ??
                        null,
                    vulnerability_type:
                        finding.vulnerability_type ??
                        finding.vulnerability ??
                        finding.type ??
                        "Unknown",
                    severity: finding.severity ?? "Unknown",
                    confidence: finding.confidence ?? null,
                    code:
                        finding.code ??
                        finding.vulnerable_code ??
                        finding.source_code ??
                        finding.snippet ??
                        "",
                    explanation:
                        finding.explanation ??
                        finding.description ??
                        finding.message ??
                        null,
                    recommendation:
                        finding.recommendation ??
                        finding.remediation ??
                        finding.fix ??
                        null,
                })),
                finding_count: uniqueFindings.length,
                note: "Findings retrieved from the scan detail endpoint. This JSON file is generated by the frontend.",
            };

            const blob = new Blob(
                [JSON.stringify(report, null, 2)],
                { type: "application/json" }
            );

            const url = URL.createObjectURL(blob);
            const link = document.createElement("a");

            link.href = url;
            link.download = `scan-report-${scanId}.json`;

            document.body.appendChild(link);
            link.click();
            link.remove();

            window.setTimeout(
                () => URL.revokeObjectURL(url),
                1000
            );
        } catch (err) {
            console.error("Failed to export scan report:", err);

            setExportError(
                err.userMessage ??
                    err.response?.data?.detail ??
                    "Unable to export scan details. Please try again."
            );
        } finally {
            setExportingScanId(null);
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

                                                    <button
                                                        type="button"
                                                        disabled={
                                                            exportingScanId !== null ||
                                                            scanId == null
                                                        }
                                                        className="rounded-md bg-blue-600 px-3 py-2 text-sm text-white hover:bg-blue-700 disabled:opacity-50"
                                                        onClick={() =>
                                                            downloadReport(scan)
                                                        }
                                                    >
                                                        {String(exportingScanId) ===
                                                        String(scanId)
                                                            ? "Exporting..."
                                                            : "Export JSON"}
                                                    </button>
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
