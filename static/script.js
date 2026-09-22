// ============================================================
// PIVOTGUARD DASHBOARD SCRIPT
// ============================================================

"use strict";


// ============================================================
// HELPER
// ============================================================

function setText(id, value) {

    const element = document.getElementById(id);

    if (element) {
        element.textContent = value;
    }
}


// ============================================================
// LOAD DASHBOARD STATISTICS
// ============================================================

async function loadStats() {

    try {

        const response = await fetch(
            "/api/stats",
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error("Statistics API failed");
        }

        const data = await response.json();


        // Security Overview

        setText(
            "totalEvents",
            data.total_events || 0
        );

        setText(
            "highRisk",
            data.high || 0
        );

        setText(
            "mediumRisk",
            data.medium || 0
        );

        setText(
            "lowRisk",
            data.low || 0
        );


        // Alert Status

        setText(
            "newAlerts",
            data.new || 0
        );

        setText(
            "acknowledgedAlerts",
            data.acknowledged || 0
        );

        setText(
            "investigatingAlerts",
            data.investigating || 0
        );

        setText(
            "resolvedAlerts",
            data.resolved || 0
        );

    } catch (error) {

        console.error(
            "Stats loading error:",
            error
        );

    }
}


// ============================================================
// LOAD EVENTS
// ============================================================

async function loadEvents() {

    try {

        const response = await fetch(
            "/api/events",
            {
                cache: "no-store"
            }
        );

        if (!response.ok) {
            throw new Error("Events API failed");
        }

        const events = await response.json();

        renderEvents(events);

        updateNetworkActivity(events);

        updateAttackPath(events);

    } catch (error) {

        console.error(
            "Events loading error:",
            error
        );

    }
}


// ============================================================
// NETWORK ACTIVITY
// ============================================================

function updateNetworkActivity(events) {

    if (!Array.isArray(events)) {
        return;
    }


    const sources = [
        ...new Set(
            events
                .map(event => event.source_ip)
                .filter(Boolean)
        )
    ];


    const destinations = [
        ...new Set(
            events
                .map(event => event.destination_ip)
                .filter(Boolean)
        )
    ];


    const services = [
        ...new Set(
            events
                .map(event => {

                    const port =
                        Number(event.port);

                    const serviceMap = {

                        22: "SSH",
                        135: "RPC",
                        139: "NetBIOS",
                        445: "SMB",
                        3389: "RDP",
                        5985: "WinRM",
                        5986: "WinRM"

                    };

                    return serviceMap[port] || null;

                })
                .filter(Boolean)
        )
    ];


    setText(
        "uniqueSources",
        sources.length
    );

    setText(
        "uniqueDestinations",
        destinations.length
    );

    setText(
        "servicesDetected",
        services.length
    );


    setText(
        "topSource",
        sources.length
            ? sources[0]
            : "-"
    );

    setText(
        "topDestination",
        destinations.length
            ? destinations[0]
            : "-"
    );


    setText(
        "mostUsedService",
        getMostUsedService(events)
    );
}


// ============================================================
// MOST USED SERVICE
// ============================================================

function getMostUsedService(events) {

    const serviceMap = {

        22: "SSH",
        135: "RPC",
        139: "NetBIOS",
        445: "SMB",
        3389: "RDP",
        5985: "WinRM",
        5986: "WinRM"

    };


    const counts = {};


    events.forEach(event => {

        const port =
            Number(event.port);

        const service =
            serviceMap[port];

        if (!service) {
            return;
        }

        counts[service] =
            (counts[service] || 0) + 1;

    });


    const entries =
        Object.entries(counts);


    if (!entries.length) {
        return "-";
    }


    entries.sort(
        (a, b) => b[1] - a[1]
    );


    return entries[0][0];
}


// ============================================================
// RENDER SECURITY EVENTS
// ============================================================

function renderEvents(events) {

    const tableBody =
        document.getElementById(
            "eventsTableBody"
        );


    if (!tableBody) {
        return;
    }


    if (!events.length) {

        tableBody.innerHTML = `
            <tr>
                <td colspan="9">
                    No security events detected.
                </td>
            </tr>
        `;

        return;
    }


    tableBody.innerHTML =
        events.map(event => {

            const severity =
                String(
                    event.severity || "Low"
                ).toLowerCase();


            const status =
                event.status || "New";


            return `

                <tr>

                    <td>
                        ${escapeHtml(
                            event.timestamp || "-"
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            event.source_ip || "-"
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            event.destination_ip || "-"
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            String(
                                event.port || "-"
                            )
                        )}
                    </td>

                    <td>
                        ${escapeHtml(
                            event.protocol || "-"
                        )}
                    </td>

                    <td>

                        <span class="severity ${severity}">
                            ${escapeHtml(
                                event.severity || "Low"
                            )}
                        </span>

                    </td>

                    <td>
                        ${escapeHtml(
                            event.reason ||
                            "Security event detected"
                        )}
                    </td>

                    <td>

                        <select
                            class="status-select"
                            data-event-id="${event.id}"
                            onchange="updateAlertStatus(this)"
                        >

                            <option value="New"
                                ${status === "New" ? "selected" : ""}>
                                New
                            </option>

                            <option value="Acknowledged"
                                ${status === "Acknowledged" ? "selected" : ""}>
                                Acknowledged
                            </option>

                            <option value="Investigating"
                                ${status === "Investigating" ? "selected" : ""}>
                                Investigating
                            </option>

                            <option value="Resolved"
                                ${status === "Resolved" ? "selected" : ""}>
                                Resolved
                            </option>

                        </select>

                    </td>

                    <td>

                        <button
                            onclick="saveAlertStatus(
                                ${event.id},
                                this
                            )"
                        >
                            Update
                        </button>

                    </td>

                </tr>

            `;

        }).join("");
}


// ============================================================
// UPDATE ALERT STATUS
// ============================================================

function updateAlertStatus(selectElement) {

    if (!selectElement) {
        return;
    }

    const eventId =
        selectElement.getAttribute(
            "data-event-id"
        );

    console.log(
        "Selected status:",
        eventId,
        selectElement.value
    );
}


// ============================================================
// SAVE ALERT STATUS
// ============================================================

async function saveAlertStatus(
    eventId,
    button
) {

    const select =
        document.querySelector(
            `.status-select[data-event-id="${eventId}"]`
        );


    if (!select) {

        alert(
            "Status selector not found."
        );

        return;
    }


    const newStatus =
        select.value;


    if (button) {

        button.disabled = true;

        button.textContent =
            "Saving...";

    }


    try {

        const response =
            await fetch(
                `/api/events/${eventId}/status`,
                {

                    method: "PUT",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        status: newStatus
                    }),

                    cache: "no-store"

                }
            );


        const result =
            await response.json();


        if (!response.ok) {

            throw new Error(
                result.message ||
                "Status update failed"
            );

        }


        if (button) {

            button.textContent =
                "Updated ✓";

        }


        await loadStats();

        await loadAnalytics();

        await loadEvents();


        setTimeout(
            function () {

                if (button) {

                    button.disabled =
                        false;

                    button.textContent =
                        "Update";

                }

            },
            1200
        );


    } catch (error) {

        console.error(
            "Status update error:",
            error
        );


        alert(
            "Unable to update alert status."
        );


        if (button) {

            button.disabled =
                false;

            button.textContent =
                "Update";

        }

    }
}


// ============================================================
// LOAD ANALYTICS
// ============================================================

async function loadAnalytics() {

    try {

        const response =
            await fetch(
                "/api/analytics",
                {
                    cache: "no-store"
                }
            );


        if (!response.ok) {

            throw new Error(
                "Analytics API failed"
            );

        }


        const data =
            await response.json();


        // ----------------------------------------------------
        // SEVERITY
        // ----------------------------------------------------

        setText(
            "severityHigh",
            data.severity.High || 0
        );

        setText(
            "severityMedium",
            data.severity.Medium || 0
        );

        setText(
            "severityLow",
            data.severity.Low || 0
        );


        // ----------------------------------------------------
        // STATUS
        // ----------------------------------------------------

        setText(
            "newAlerts",
            data.status.New || 0
        );

        setText(
            "acknowledgedAlerts",
            data.status.Acknowledged || 0
        );

        setText(
            "investigatingAlerts",
            data.status.Investigating || 0
        );

        setText(
            "resolvedAlerts",
            data.status.Resolved || 0
        );


        // ----------------------------------------------------
        // TOTAL ALERTS
        // ----------------------------------------------------

        setText(
            "analyticsTotal",
            data.total_events || 0
        );


        // ----------------------------------------------------
        // LISTS
        // ----------------------------------------------------

        renderAnalyticsList(
            "topSourcesList",
            data.top_sources,
            "ip"
        );


        renderAnalyticsList(
            "topDestinationsList",
            data.top_destinations,
            "ip"
        );


        renderAnalyticsList(
            "remoteServicesList",
            data.remote_services,
            "service"
        );


        // ----------------------------------------------------
        // RISK BARS
        // ----------------------------------------------------

        updateRiskBars(data);


    } catch (error) {

        console.error(
            "Analytics loading error:",
            error
        );

        showAnalyticsError();

    }
}


// ============================================================
// ANALYTICS LIST
// ============================================================

function renderAnalyticsList(
    elementId,
    items,
    labelKey
) {

    const element =
        document.getElementById(
            elementId
        );


    if (!element) {
        return;
    }


    if (!items || !items.length) {

        element.innerHTML =
            "<div>Loading...</div>";

        return;
    }


    element.innerHTML =
        items.map(item => {

            return `

                <div class="analytics-item">

                    <span>
                        ${escapeHtml(
                            item[labelKey]
                        )}
                    </span>

                    <strong>
                        ${escapeHtml(
                            String(
                                item.count
                            )
                        )}
                    </strong>

                </div>

            `;

        }).join("");
}


// ============================================================
// SHOW ANALYTICS ERROR
// ============================================================

function showAnalyticsError() {

    const ids = [

        "topSourcesList",
        "topDestinationsList",
        "remoteServicesList"

    ];


    ids.forEach(id => {

        const element =
            document.getElementById(id);


        if (element) {

            element.innerHTML =
                "<div>Unable to load analytics.</div>";

        }

    });

}


// ============================================================
// RISK BARS
// ============================================================

function updateRiskBars(data) {

    const high =
        Number(
            data.severity.High || 0
        );

    const medium =
        Number(
            data.severity.Medium || 0
        );

    const low =
        Number(
            data.severity.Low || 0
        );


    const total =
        high + medium + low;


    const highBar =
        document.getElementById(
            "highRiskBar"
        );

    const mediumBar =
        document.getElementById(
            "mediumRiskBar"
        );

    const lowBar =
        document.getElementById(
            "lowRiskBar"
        );


    if (total === 0) {
        return;
    }


    if (highBar) {

        highBar.style.width =
            `${(high / total) * 100}%`;

    }


    if (mediumBar) {

        mediumBar.style.width =
            `${(medium / total) * 100}%`;

    }


    if (lowBar) {

        lowBar.style.width =
            `${(low / total) * 100}%`;

    }

}


// ============================================================
// ATTACK PATH
// ============================================================

function updateAttackPath(events) {

    const container =
        document.getElementById(
            "attackPath"
        );


    if (!container) {
        return;
    }


    if (!events || !events.length) {

        container.innerHTML =
            "No attack path loaded.";

        return;

    }


    const event =
        events[0];


    container.innerHTML = `

        <div class="attack-path">

            <span class="source-node">
                ${escapeHtml(
                    event.source_ip
                )}
            </span>

            <span class="arrow">
                →
            </span>

            <span class="destination-node">
                ${escapeHtml(
                    event.destination_ip
                )}
            </span>

            <span class="port-node">
                Port ${escapeHtml(
                    String(event.port)
                )}
            </span>

            <span class="protocol-node">
                ${escapeHtml(
                    event.protocol
                )}
            </span>

        </div>

    `;
}


// ============================================================
// RUN SECURITY SCAN
// ============================================================

async function runScan() {

    try {

        const response =
            await fetch(
                "/api/scan",
                {
                    cache: "no-store"
                }
            );


        const result =
            await response.json();


        if (!response.ok) {

            throw new Error(
                result.message ||
                "Scan failed"
            );

        }


        alert(
            "Security analysis completed successfully."
        );


        await loadStats();

        await loadAnalytics();

        await loadEvents();


    } catch (error) {

        console.error(
            "Scan error:",
            error
        );


        alert(
            "Security scan failed."
        );

    }

}


// ============================================================
// EVENT FILTER
// ============================================================

function filterEvents() {

    const input =
        document.getElementById(
            "eventSearch"
        );


    if (!input) {
        return;
    }


    const search =
        input.value.toLowerCase();


    const rows =
        document.querySelectorAll(
            "#eventsTableBody tr"
        );


    rows.forEach(row => {

        const text =
            row.textContent.toLowerCase();


        row.style.display =
            text.includes(search)
                ? ""
                : "none";

    });

}


// ============================================================
// HTML ESCAPE
// ============================================================

function escapeHtml(value) {

    return String(value)

        .replace(
            /&/g,
            "&amp;"
        )

        .replace(
            /</g,
            "&lt;"
        )

        .replace(
            />/g,
            "&gt;"
        )

        .replace(
            /"/g,
            "&quot;"
        )

        .replace(
            /'/g,
            "&#039;"
        );

}


// ============================================================
// CSV ANALYSIS
// ============================================================

async function analyzeCSV() {

    const input =
        document.getElementById(
            "csvFile"
        );


    if (!input || !input.files.length) {

        alert(
            "Please select a CSV file."
        );

        return;

    }


    const formData =
        new FormData();


    formData.append(
        "file",
        input.files[0]
    );


    try {

        const response =
            await fetch(
                "/api/upload",
                {

                    method: "POST",

                    body: formData,

                    cache: "no-store"

                }
            );


        const result =
            await response.json();


        if (!response.ok) {

            throw new Error(
                result.message ||
                "CSV analysis failed"
            );

        }


        alert(
            `CSV analysis completed.\n\n` +
            `Logs: ${result.total_logs}\n` +
            `Alerts: ${result.total_alerts}`
        );


        await loadStats();

        await loadAnalytics();

        await loadEvents();


    } catch (error) {

        console.error(
            "CSV analysis error:",
            error
        );


        alert(
            error.message ||
            "CSV analysis failed."
        );

    }

}


// ============================================================
// PAGE INITIALIZATION
// ============================================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        console.log(
            "PivotGuard dashboard initialized."
        );


        loadStats();

        loadEvents();

        loadAnalytics();


        // Auto refresh every 10 seconds

        setInterval(
            function () {

                loadStats();

                loadEvents();

                loadAnalytics();

            },
            10000
        );

    }
);


// ============================================================
// GLOBAL FUNCTIONS
// ============================================================

window.runScan =
    runScan;

window.filterEvents =
    filterEvents;

window.updateAlertStatus =
    updateAlertStatus;

window.saveAlertStatus =
    saveAlertStatus;

window.analyzeCSV =
    analyzeCSV;