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

    async function startScan() {

        if (!targetUrl) {

            return;
        }


        const url =
            targetUrl.value.trim();


        // -----------------------------------------------------
        // URL validation
        // -----------------------------------------------------

        if (!url) {

            alert(
                "Enter a target URL."
            );

            return;
        }


        if (
            !url.startsWith(
                "http://"
            ) &&
            !url.startsWith(
                "https://"
            )
        ) {

            alert(
                "URL must start with http:// or https://"
            );

            return;
        }


        // -----------------------------------------------------
        // AUTOMATIC CONFIGURATION
        // -----------------------------------------------------

        const scanConfig =
            getScanProfile(
                selectedScanMode
            );


        // -----------------------------------------------------
        // Loading
        // -----------------------------------------------------

        setLoading(true);


        if (scanBadge) {

            scanBadge.textContent =
                "SCANNING";


            scanBadge.className =
                "badge";
        }


        if (results) {

            results.innerHTML = `

                <div class="empty-state">

                    <div class="empty-icon">
                        🧠
                    </div>

                    <h3>
                        ${escapeHTML(
                            getModeLabel(
                                selectedScanMode
                            )
                        )}
                        Scan Running
                    </h3>

                    <p id="progressText">
                        Initializing scanner...
                    </p>

                </div>

            `;
        }


        const progress =
            document.getElementById(
                "progressText"
            );


        try {

            // -------------------------------------------------
            // Validation
            // -------------------------------------------------

            showStatus(
                "Validating target..."
            );


            if (progress) {

                progress.textContent =
                    "✓ Target validated";
            }


            // -------------------------------------------------
            // Crawling
            // -------------------------------------------------

            showStatus(
                "Crawling endpoints..."
            );


            if (progress) {

                progress.textContent =
                    `✓ Crawling endpoints (max ${scanConfig.max_pages} pages)`;
            }


            // -------------------------------------------------
            // Parameter discovery
            // -------------------------------------------------

            showStatus(
                "Discovering parameters..."
            );


            if (progress) {

                progress.textContent =
                    "✓ Discovering parameters";
            }


            // -------------------------------------------------
            // API REQUEST
            // -------------------------------------------------

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

                            // Only the scan mode is
                            // selected by the user.
                            mode:
                                selectedScanMode
                        })
                    }
                );


            // -------------------------------------------------
            // Parse response
            // -------------------------------------------------

            let data;


            try {

                data =
                    await response.json();

            } catch (parseError) {

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
                    "Scan failed."
                );
            }


            // -------------------------------------------------
            // Analysis
            // -------------------------------------------------

            showStatus(
                "Analyzing findings..."
            );


            if (progress) {

                progress.textContent =
                    "✓ Scan completed — analyzing findings";
            }


            // -------------------------------------------------
            // Render results
            // -------------------------------------------------

            renderResults(
                data
            );


            // -------------------------------------------------
            // History
            // -------------------------------------------------

            await loadHistoryStats();


            // -------------------------------------------------
            // Completed
            // -------------------------------------------------

            showStatus(
                `${getModeLabel(
                    selectedScanMode
                )} scan completed.`
            );


        } catch (error) {

            console.error(
                "WebGuard scan error:",
                error
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

});