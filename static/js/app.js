document.addEventListener("DOMContentLoaded", () => {
    // =========================================================
    // ELEMENTS
    // =========================================================

    const targetUrl =
        document.getElementById("targetUrl");

    const scanButton =
        document.getElementById("scanButton");

    const scanStatus =
        document.getElementById("scanStatus");

    const results =
        document.getElementById("results");

    const scanBadge =
        document.getElementById("scanBadge");

    const scanModeOptions =
        document.querySelectorAll(".scan-mode-option");

    const modeStatus =
        document.getElementById("modeStatus");


    // =========================================================
    // DASHBOARD STATISTICS
    // =========================================================

    const totalScans =
        document.getElementById("totalScans");

    const totalVulnerabilities =
        document.getElementById("totalVulnerabilities");

    const highRisk =
        document.getElementById("highRisk");

    const securityScore =
        document.getElementById("securityScore");

    const confirmedVulnerabilities =
        document.getElementById(
            "confirmedVulnerabilities"
        );

    const potentialVulnerabilities =
        document.getElementById(
            "potentialVulnerabilities"
        );

    const misconfigurations =
        document.getElementById(
            "misconfigurations"
        );

    const informationalFindings =
        document.getElementById(
            "informationalFindings"
        );


    // =========================================================
    // AUTOMATIC SCAN PROFILES
    // =========================================================

    const SCAN_PROFILES = {

        passive: {
            max_pages: 10,
            timeout: 5,
            max_depth: 1,
            description:
                "Low-impact observation without active parameter probes."
        },

        standard: {
            max_pages: 20,
            timeout: 10,
            max_depth: 2,
            description:
                "Recommended balanced assessment with safe active checks."
        },

        active: {
            max_pages: 50,
            timeout: 15,
            max_depth: 3,
            description:
                "Deeper authorized assessment with additional comparisons."
        }
    };


    let selectedScanMode = "standard";

    const ACTIVE_JOB_KEY =
        "webguard_active_scan_job";

    // =========================================================
    // UTILITY FUNCTIONS
    // =========================================================

    function escapeHTML(value) {

        return String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }


    function severityClass(severity) {

        return String(severity || "info")
            .toLowerCase()
            .replace(/[^a-z]/g, "");
    }


    function showStatus(message) {

        if (!scanStatus) {
            return;
        }

        scanStatus.textContent = message;
        scanStatus.classList.remove("hidden");
    }


    function hideStatus() {

        if (!scanStatus) {
            return;
        }

        scanStatus.classList.add("hidden");
    }


    // =========================================================
    // MODE LABEL
    // =========================================================

    function getModeLabel(mode) {

        const labels = {

            passive: "Passive",

            standard: "Standard",

            active: "Active"
        };

        return labels[
            String(mode || "standard").toLowerCase()
        ] || "Standard";
    }


    // =========================================================
    // GET AUTOMATIC PROFILE
    // =========================================================

    function getScanProfile(mode) {

        return (
            SCAN_PROFILES[
                String(
                    mode || "standard"
                ).toLowerCase()
            ]
            ||
            SCAN_PROFILES.standard
        );
    }


    // =========================================================
    // UPDATE AUTOMATIC CONFIGURATION UI
    // =========================================================

    function updateScanProfileUI(mode) {

        const profile =
            getScanProfile(mode);


        // -----------------------------------------------------
        // Optional configuration elements
        // -----------------------------------------------------

        const profilePages =
            document.getElementById(
                "profileMaxPages"
            );

        const profileTimeout =
            document.getElementById(
                "profileTimeout"
            );

        const profileDepth =
            document.getElementById(
                "profileDepth"
            );

        const profileDescription =
            document.getElementById(
                "scanprofileDescription"
            );


        if (profilePages) {

            profilePages.textContent =
                profile.max_pages;
        }


        if (profileTimeout) {

            profileTimeout.textContent =
                `${profile.timeout}s`;
        }


        if (profileDepth) {

            profileDepth.textContent =
                profile.max_depth;
        }


        if (profileDescription) {

            profileDescription.textContent =
                profile.description;
        }


        // -----------------------------------------------------
        // Generic profile values
        // -----------------------------------------------------

        const profileName =
            document.getElementById(
                "profileName"
            );

        if (profileName) {

            profileName.textContent =
                `${getModeLabel(mode)} Scan`;
        }
    }


    // =========================================================
    // BUTTON LOADING STATE
    // =========================================================

    function setLoading(state) {

        if (!scanButton) {
            return;
        }


        scanButton.disabled = state;


        if (state) {

            scanButton.textContent =
                `🧠 ${getModeLabel(
                    selectedScanMode
                )} Scanning...`;

        } else {

            scanButton.textContent =
                `🔍 Start ${getModeLabel(
                    selectedScanMode
                )} Scan`;
        }
    }


    // =========================================================
    // SELECT SCAN MODE
    // =========================================================

    function setSelectedMode(mode) {

        const normalized =
            String(
                mode || "standard"
            ).toLowerCase();


        if (
            ![
                "passive",
                "standard",
                "active"
            ].includes(normalized)
        ) {

            return;
        }


        selectedScanMode =
            normalized;


        // -----------------------------------------------------
        // Update mode cards
        // -----------------------------------------------------

        scanModeOptions.forEach(option => {

            const isSelected =
                option.dataset.mode ===
                selectedScanMode;


            option.classList.toggle(
                "selected",
                isSelected
            );


            option.setAttribute(
                "aria-checked",
                isSelected
                    ? "true"
                    : "false"
            );
        });


        // -----------------------------------------------------
        // Update mode status
        // -----------------------------------------------------

        if (modeStatus) {

            modeStatus.textContent =
                getModeLabel(
                    selectedScanMode
                );
        }


        // -----------------------------------------------------
        // Automatically update scan configuration
        // -----------------------------------------------------

        updateScanProfileUI(
            selectedScanMode
        );


        // -----------------------------------------------------
        // Update scan button
        // -----------------------------------------------------

        if (
            scanButton &&
            !scanButton.disabled
        ) {

            scanButton.textContent =
                `🔍 Start ${getModeLabel(
                    selectedScanMode
                )} Scan`;
        }
    }


    // =========================================================
    // LOAD HISTORY STATISTICS
    // =========================================================

    async function loadHistoryStats() {

        try {

            const response =
                await fetch(
                    "/api/history?_=" +
                    Date.now()
                );


            if (!response.ok) {

                return;
            }


            const data =
                await response.json();


            if (totalScans) {

                totalScans.textContent =
                    (
                        data.scans || []
                    ).length;
            }


        } catch (error) {

            console.warn(
                "History unavailable:",
                error
            );
        }
    }


    // =========================================================
    // RENDER ENDPOINTS
    // =========================================================

    function renderEndpoints(endpoints) {

        if (!endpoints.length) {

            return `
                <div class="empty-state">

                    <div class="empty-icon">
                        🌐
                    </div>

                    <h3>
                        No endpoints discovered
                    </h3>

                </div>
            `;
        }


        return `
            <div class="endpoint-list">

                ${endpoints.map(endpoint => `

                    <div class="endpoint-row">

                        <span>
                            ${escapeHTML(
                                endpoint.url
                            )}
                        </span>

                        <strong>
                            ${escapeHTML(
                                endpoint.status_code
                            )}
                        </strong>

                    </div>

                `).join("")}

            </div>
        `;
    }


    // =========================================================
    // RENDER FINDING
    // =========================================================

    function renderFinding(finding) {

        return `
            <div class="finding">

                <div class="finding-main">

                    <div class="finding-title">

                        ${escapeHTML(
                            finding.name
                        )}

                    </div>


                    <p>
                        ${escapeHTML(
                            finding.description
                        )}
                    </p>


                    ${
                        finding.parameter
                        ? `
                            <small>

                                <strong>
                                    Parameter:
                                </strong>

                                ${escapeHTML(
                                    finding.parameter
                                )}

                            </small>

                            <br>
                        `
                        : ""
                    }


                    ${
                        finding.evidence
                        ? `
                            <small>

                                <strong>
                                    Evidence:
                                </strong>

                                ${escapeHTML(
                                    finding.evidence
                                )}

                            </small>

                            <br>
                        `
                        : ""
                    }


                    <small>

                        <strong>
                            Recommendation:
                        </strong>

                        ${escapeHTML(
                            finding.recommendation
                        )}

                    </small>

                </div>


                <span
                    class="severity ${severityClass(
                        finding.severity
                    )}"
                >

                    ${escapeHTML(
                        finding.severity
                    )}

                </span>

            </div>
        `;
    }


    // =========================================================
    // RENDER SCAN RESULTS
    // =========================================================

    function renderResults(data) {

        const findings =
            data.findings || [];


        const endpoints =
            data.discovered_endpoints || [];


        const risk =
            data.risk || {};


        // -----------------------------------------------------
        // Statistics
        // -----------------------------------------------------

        if (totalVulnerabilities) {

            totalVulnerabilities.textContent =
                risk.vulnerabilities ?? 0;
        }


        if (confirmedVulnerabilities) {

            confirmedVulnerabilities.textContent =
                risk.vulnerabilities ?? 0;
        }


        if (potentialVulnerabilities) {

            potentialVulnerabilities.textContent =
                risk.potential_vulnerabilities ?? 0;
        }


        if (misconfigurations) {

            misconfigurations.textContent =
                risk.misconfigurations ?? 0;
        }


        if (informationalFindings) {

            informationalFindings.textContent =
                risk.informational ?? 0;
        }


        if (highRisk) {

            highRisk.textContent =
                risk.high_risk ?? 0;
        }


        if (securityScore) {

            securityScore.textContent =
                `${risk.security_score ?? 0}/100`;
        }


        // -----------------------------------------------------
        // Risk Badge
        // -----------------------------------------------------

        if (scanBadge) {

            scanBadge.textContent =
                risk.risk_level
                    ? risk.risk_level.toUpperCase()
                    : "COMPLETED";


            scanBadge.className =
                "badge";


            const level =
                String(
                    risk.risk_level || ""
                ).toLowerCase();


            if (level === "high") {

                scanBadge.classList.add(
                    "risk-high"
                );

            } else if (level === "medium") {

                scanBadge.classList.add(
                    "risk-medium"
                );

            } else if (level === "low") {

                scanBadge.classList.add(
                    "risk-low"
                );
            }
        }


        if (!results) {

            return;
        }


        // -----------------------------------------------------
        // Results HTML
        // -----------------------------------------------------

        results.innerHTML = `

            <div class="scan-summary">

                <div class="summary-card">

                    <strong>
                        Security Score
                    </strong>

                    <span>
                        ${escapeHTML(
                            risk.security_score ?? 0
                        )}/100
                    </span>

                </div>


                <div class="summary-card">

                    <strong>
                        Risk Level
                    </strong>

                    <span>
                        ${escapeHTML(
                            risk.risk_level ||
                            "Unknown"
                        )}
                    </span>

                </div>


                <div class="summary-card">

                    <strong>
                        Endpoints
                    </strong>

                    <span>
                        ${endpoints.length}
                    </span>

                </div>


                <div class="summary-card">

                    <strong>
                        Findings
                    </strong>

                    <span>
                        ${findings.length}
                    </span>

                </div>

            </div>


            <!-- =============================================
                 AUTOMATIC SCAN PROFILE
            ============================================== -->

            <div class="scan-profile-result">

                <h3>
                    ⚙️ Scan Profile
                </h3>

                <p>
                    ${escapeHTML(
                        getModeLabel(
                            data.mode ||
                            selectedScanMode
                        )
                    )} configuration was
                    automatically applied.
                </p>

                <div class="profile-stats">

                    <span>
                        📄
                        <strong>
                            ${getScanProfile(
                                data.mode ||
                                selectedScanMode
                            ).max_pages}
                        </strong>
                        Pages
                    </span>

                    <span>
                        ⏱
                        <strong>
                            ${getScanProfile(
                                data.mode ||
                                selectedScanMode
                            ).timeout}s
                        </strong>
                        Timeout
                    </span>

                    <span>
                        🌐
                        <strong>
                            ${getScanProfile(
                                data.mode ||
                                selectedScanMode
                            ).max_depth}
                        </strong>
                        Depth
                    </span>

                </div>

            </div>


            <!-- =============================================
                 ENDPOINTS
            ============================================== -->

            <div class="dashboard-endpoints">

                <h3>
                    🌐 Discovered Endpoints
                </h3>

                ${renderEndpoints(
                    endpoints
                )}

            </div>


            <!-- =============================================
                 FINDINGS
            ============================================== -->

            <div class="dashboard-findings">

                <h3>
                    🛡 Security Findings
                    (${findings.length})
                </h3>


                ${
                    findings.length

                    ? findings
                        .map(renderFinding)
                        .join("")

                    : `

                        <div class="empty-state">

                            <div class="empty-icon">
                                ✅
                            </div>

                            <h3>
                                No vulnerabilities detected
                            </h3>

                            <p>
                                WebGuard didn't find any
                                issues during this scan.
                            </p>

                        </div>

                    `
                }

            </div>

        `;


        // -----------------------------------------------------
        // Full Report Button
        // -----------------------------------------------------

        if (data.scan_id) {

            const button =
                document.createElement(
                    "a"
                );


            button.href =
                `/scan/${data.scan_id}`;


            button.className =
                "scan-details-link";


            button.textContent =
                "📄 View Full Scan Report";


            results.appendChild(
                button
            );
        }
    }


    // =========================================================
    // START SCAN
    // =========================================================

    // =========================================================
// BACKGROUND SCAN JOB
// =========================================================

async function fetchJobStatus(jobId) {

    const response = await fetch(
        `/api/scan/jobs/${jobId}?_=${Date.now()}`
    );

    let data;

    try {

        data = await response.json();

    } catch (error) {

        throw new Error(
            "Server returned an invalid job response."
        );
    }

    if (
        !response.ok ||
        !data.success
    ) {

        throw new Error(
            data.error ||
            "Unable to read scan job status."
        );
    }

    return data;
}


// =========================================================
// RENDER JOB PROGRESS
// =========================================================

function renderJobProgress(job) {

    if (!results) {
        return;
    }

    const progress =
        Number(
            job.progress || 0
        );

    const stage =
        job.stage ||
        "Working";

    const message =
        job.message ||
        "Processing scan...";

    const status =
        String(
            job.status ||
            "running"
        );

    const displayStatus =
        status.charAt(0).toUpperCase()
        +
        status.slice(1);

    results.innerHTML = `

        <div
            class="empty-state"
            style="
                max-width:720px;
                margin:0 auto;
            "
        >

            <div class="empty-icon">
                🧠
            </div>

            <h3>
                ${escapeHTML(
                    getModeLabel(
                        job.mode
                    )
                )}
                Scan
                ${escapeHTML(
                    displayStatus
                )}
            </h3>

            <p>
                ${escapeHTML(stage)}
                —
                ${escapeHTML(message)}
            </p>

            <div
                style="
                    margin:24px auto 8px;
                    width:min(100%,560px);
                    height:10px;
                    background:rgba(255,255,255,.10);
                    border-radius:999px;
                    overflow:hidden;
                "
            >

                <div
                    style="
                        width:${Math.max(
                            0,
                            Math.min(
                                100,
                                progress
                            )
                        )}%;
                        height:100%;
                        background:currentColor;
                        transition:width .35s ease;
                    "
                ></div>

            </div>

            <strong>
                ${progress}%
            </strong>

            <p
                style="
                    opacity:.7;
                    margin-top:10px;
                "
            >
                Job #${escapeHTML(job.id)}
                ·
                The scan is running in
                the background.
            </p>

        </div>
    `;
}


// =========================================================
// MONITOR BACKGROUND JOB
// =========================================================

async function monitorScanJob(jobId) {

    localStorage.setItem(
        ACTIVE_JOB_KEY,
        String(jobId)
    );

    while (true) {

        const data =
            await fetchJobStatus(
                jobId
            );

        const job =
            data.job || {};

        renderJobProgress(
            job
        );

        // ----------------------------------------------------
        // Badge
        // ----------------------------------------------------

        if (scanBadge) {

            scanBadge.textContent =
                String(
                    job.status ||
                    "RUNNING"
                ).toUpperCase();

            scanBadge.className =
                "badge";

            if (
                job.status === "failed"
            ) {

                scanBadge.classList.add(
                    "risk-high"
                );
            }
        }

        // ----------------------------------------------------
        // Completed
        // ----------------------------------------------------

        if (
            job.status ===
            "completed"
        ) {

            localStorage.removeItem(
                ACTIVE_JOB_KEY
            );

            if (!data.scan) {

                throw new Error(
                    "Scan completed but results were not found."
                );
            }

            const scan =
                data.scan;

            renderResults({

                success: true,

                scan_id:
                    scan.id,

                target:
                    scan.target,

                mode:
                    job.mode,

                discovered_endpoints:
                    scan.endpoints ||
                    [],

                findings:
                    scan.findings ||
                    [],

                risk:
                    data.risk ||
                    {}

            });

            await loadHistoryStats();

            showStatus(
                `${getModeLabel(
                    job.mode
                )} scan completed.`
            );

            // -----------------------------------------------
            // Final risk badge
            // -----------------------------------------------

            if (scanBadge) {

                scanBadge.textContent =
                    (
                        data.risk?.risk_level ||
                        "COMPLETED"
                    ).toUpperCase();

                scanBadge.className =
                    "badge";

                const level =
                    String(
                        data.risk?.risk_level ||
                        ""
                    ).toLowerCase();

                if (
                    level === "high"
                ) {

                    scanBadge.classList.add(
                        "risk-high"
                    );

                } else if (
                    level === "medium"
                ) {

                    scanBadge.classList.add(
                        "risk-medium"
                    );

                } else if (
                    level === "low"
                ) {

                    scanBadge.classList.add(
                        "risk-low"
                    );
                }
            }

            return;
        }

        // ----------------------------------------------------
        // Failed
        // ----------------------------------------------------

        if (
            job.status ===
            "failed"
        ) {

            localStorage.removeItem(
                ACTIVE_JOB_KEY
            );

            throw new Error(
                job.error ||
                job.message ||
                "Background scan failed."
            );
        }

        // ----------------------------------------------------
        // Continue polling
        // ----------------------------------------------------

        await new Promise(
            resolve =>
                setTimeout(
                    resolve,
                    1000
                )
        );
    }
}


// =========================================================
// RESUME ACTIVE JOB
// =========================================================

async function resumeActiveScan() {

    const storedJobId =
        localStorage.getItem(
            ACTIVE_JOB_KEY
        );

    if (!storedJobId) {
        return;
    }

    const jobId =
        Number(
            storedJobId
        );

    if (
        !Number.isInteger(jobId) ||
        jobId <= 0
    ) {

        localStorage.removeItem(
            ACTIVE_JOB_KEY
        );

        return;
    }

    try {

        setLoading(true);

        showStatus(
            "Reconnecting to background scan..."
        );

        await monitorScanJob(
            jobId
        );

    } catch (error) {

        console.error(
            "Unable to resume scan:",
            error
        );

        localStorage.removeItem(
            ACTIVE_JOB_KEY
        );

        showStatus(
            "Unable to resume the previous scan."
        );

    } finally {

        setLoading(false);
    }
}


// =========================================================
// START SCAN
// =========================================================

async function startScan() {

    if (!targetUrl) {
        return;
    }

    const url =
        targetUrl.value.trim();

    // --------------------------------------------------------
    // Validate URL
    // --------------------------------------------------------

    if (!url) {

        alert(
            "Enter a target URL."
        );

        return;
    }

    if (
        !url.startsWith(
            "http://"
        )
        &&
        !url.startsWith(
            "https://"
        )
    ) {

        alert(
            "URL must start with http:// or https://"
        );

        return;
    }

    // --------------------------------------------------------
    // Loading
    // --------------------------------------------------------

    setLoading(true);

    if (scanBadge) {

        scanBadge.textContent =
            "QUEUED";

        scanBadge.className =
            "badge";
    }

    if (results) {

        results.innerHTML = `

            <div class="empty-state">

                <div class="empty-icon">
                    ⏳
                </div>

                <h3>
                    Creating Background Scan
                </h3>

                <p>
                    Submitting the scan job...
                </p>

            </div>

        `;
    }

    try {

        showStatus(
            "Creating background scan job..."
        );

        // ----------------------------------------------------
        // Create job
        // ----------------------------------------------------

        const response =
            await fetch(
                "/api/scan",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({

                        url: url,

                        mode:
                            selectedScanMode

                    })
                }
            );

        let data;

        try {

            data =
                await response.json();

        } catch (error) {

            throw new Error(
                "Server returned an invalid response."
            );
        }

        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Unable to create scan job."
            );
        }

        if (!data.job_id) {

            throw new Error(
                "Server did not return a scan job ID."
            );
        }

        // ----------------------------------------------------
        // Monitor job
        // ----------------------------------------------------

        showStatus(
            "Background scan started."
        );

        await monitorScanJob(
            data.job_id
        );

    } catch (error) {

        console.error(
            "WebGuard background scan error:",
            error
        );

        localStorage.removeItem(
            ACTIVE_JOB_KEY
        );

        if (scanBadge) {

            scanBadge.textContent =
                "FAILED";

            scanBadge.className =
                "badge risk-high";
        }

        if (results) {

            results.innerHTML = `

                <div class="empty-state">

                    <div class="empty-icon">
                        ❌
                    </div>

                    <h3>
                        Scan Failed
                    </h3>

                    <p>
                        ${escapeHTML(
                            error.message
                        )}
                    </p>

                </div>

            `;
        }

        showStatus(
            "Scan failed."
        );

    } finally {

        setLoading(false);
    }
}


    // =========================================================
    // SCAN MODE EVENTS
    // =========================================================

    scanModeOptions.forEach(
        option => {

            option.addEventListener(
                "click",
                () => {

                    if (
                        scanButton &&
                        scanButton.disabled
                    ) {

                        return;
                    }


                    setSelectedMode(
                        option.dataset.mode
                    );
                }
            );


            option.addEventListener(
                "keydown",
                event => {

                    if (
                        (
                            event.key === "Enter" ||
                            event.key === " "
                        ) &&
                        !(
                            scanButton &&
                            scanButton.disabled
                        )
                    ) {

                        event.preventDefault();


                        setSelectedMode(
                            option.dataset.mode
                        );
                    }
                }
            );

        }
    );


    // =========================================================
    // BUTTON EVENT
    // =========================================================

    if (scanButton) {

        scanButton.addEventListener(
            "click",
            startScan
        );
    }


    // =========================================================
    // ENTER KEY
    // =========================================================

    if (targetUrl) {

        targetUrl.addEventListener(
            "keydown",
            event => {

                if (
                    event.key === "Enter" &&
                    !(
                        scanButton &&
                        scanButton.disabled
                    )
                ) {

                    startScan();
                }
            }
        );
    }


    // =========================================================
    // INITIALIZE
    // =========================================================

    setSelectedMode(
        "standard"
    );


    loadHistoryStats();

    resumeActiveScan();
    

});