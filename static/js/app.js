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


    // Classification statistics

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
    // UTILITIES
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


    function setLoading(state) {

        if (!scanButton) {
            return;
        }

        scanButton.disabled = state;

        if (state) {

            scanButton.textContent =
                "🧠 Smart Scanning...";

        } else {

            scanButton.textContent =
                "🧠 Start Smart Scan";
        }
    }


    // =========================================================
    // HISTORY COUNT
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
                    (data.scans || []).length;
            }

        } catch (error) {

            console.warn(
                "History unavailable:",
                error
            );
        }
    }


    // =========================================================
    // ENDPOINT RENDERING
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
                            ${escapeHTML(endpoint.url)}
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
    // FINDING RENDERING
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
        // MAIN DASHBOARD
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
                (risk.high || 0) +
                (risk.critical || 0);
        }


        if (securityScore) {

            securityScore.textContent =
                risk.security_score !== undefined
                    ? `${risk.security_score}/100`
                    : "--";
        }


        // -----------------------------------------------------
        // RISK BADGE
        // -----------------------------------------------------

        const riskLevel =
            String(
                risk.risk_level || "unknown"
            ).toLowerCase();


        if (scanBadge) {

            scanBadge.textContent =
                riskLevel.toUpperCase();

            // IMPORTANT:
            // Use risk-high / risk-medium / risk-low
            // instead of just high / medium / low.

            scanBadge.className =
                `badge risk-${riskLevel}`;
        }


        // -----------------------------------------------------
        // RESULTS HTML
        // -----------------------------------------------------

        results.innerHTML = `

            <div class="scan-summary">


                <div>

                    <strong>
                        Target
                    </strong>

                    <span>
                        ${escapeHTML(
                            data.target
                        )}
                    </span>

                </div>


                <div>

                    <strong>
                        Scan Type
                    </strong>

                    <span>
                        Smart Scan
                    </span>

                </div>


                <div>

                    <strong>
                        Endpoints
                    </strong>

                    <span>
                        ${endpoints.length}
                    </span>

                </div>


                <div>

                    <strong>
                        Findings
                    </strong>

                    <span>
                        ${findings.length}
                    </span>

                </div>


            </div>


            <!-- =============================================
                 DISCOVERED ENDPOINTS
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
                 SECURITY FINDINGS
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
        // FULL SCAN REPORT BUTTON
        // -----------------------------------------------------

        if (data.scan_id) {

            const button =
                document.createElement("a");


            button.href =
                `/scan/${data.scan_id}`;


            button.className =
                "scan-details-link";


            button.textContent =
                "📄 View Full Scan Report";


            results.appendChild(button);
        }
    }


    // =========================================================
    // SMART SCAN
    // =========================================================

    async function startScan() {

        const url =
            targetUrl.value.trim();


        // -----------------------------------------------------
        // URL VALIDATION
        // -----------------------------------------------------

        if (!url) {

            alert(
                "Enter a target URL."
            );

            return;
        }


        if (
            !url.startsWith("http://") &&
            !url.startsWith("https://")
        ) {

            alert(
                "URL must start with http:// or https://"
            );

            return;
        }


        // -----------------------------------------------------
        // START LOADING
        // -----------------------------------------------------

        setLoading(true);


        scanBadge.textContent =
            "SCANNING";


        scanBadge.className =
            "badge";


        results.innerHTML = `

            <div class="empty-state">

                <div class="empty-icon">
                    🧠
                </div>

                <h3>
                    Smart Scan Running
                </h3>

                <p id="progressText">
                    Initializing scanner...
                </p>

            </div>

        `;


        const progress =
            document.getElementById(
                "progressText"
            );


        try {

            // -------------------------------------------------
            // VALIDATION
            // -------------------------------------------------

            showStatus(
                "Validating target..."
            );


            if (progress) {

                progress.textContent =
                    "✓ Target validated";
            }


            await new Promise(
                resolve =>
                    setTimeout(
                        resolve,
                        350
                    )
            );


            // -------------------------------------------------
            // CRAWLING
            // -------------------------------------------------

            showStatus(
                "Crawling endpoints..."
            );


            if (progress) {

                progress.textContent =
                    "✓ Crawling endpoints";
            }


            await new Promise(
                resolve =>
                    setTimeout(
                        resolve,
                        350
                    )
            );


            // -------------------------------------------------
            // PARAMETER DISCOVERY
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
                            url: url
                        })
                    }
                );


            const data =
                await response.json();


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
            // ANALYSIS
            // -------------------------------------------------

            showStatus(
                "Analyzing findings..."
            );


            await new Promise(
                resolve =>
                    setTimeout(
                        resolve,
                        300
                    )
            );


            // -------------------------------------------------
            // DISPLAY RESULTS
            // -------------------------------------------------

            renderResults(data);


            // Update total scan count

            await loadHistoryStats();


            showStatus(
                "Smart Scan completed."
            );


        } catch (error) {

            console.error(error);


            // -------------------------------------------------
            // FAILED SCAN
            // -------------------------------------------------

            scanBadge.textContent =
                "FAILED";


            scanBadge.className =
                "badge risk-high";


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


            showStatus(
                "Scan failed."
            );


        } finally {

            setLoading(false);
        }
    }


    // =========================================================
    // EVENTS
    // =========================================================

    scanButton.addEventListener(
        "click",
        startScan
    );


    targetUrl.addEventListener(
        "keydown",
        event => {

            if (
                event.key === "Enter" &&
                !scanButton.disabled
            ) {

                startScan();
            }

        }
    );


    // =========================================================
    // INITIAL DASHBOARD
    // =========================================================

    loadHistoryStats();

});