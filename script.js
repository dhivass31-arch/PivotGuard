async function runScan() {
    const button = document.getElementById("scanButton");

    button.disabled = true;
    button.innerText = "⏳ Scanning...";

    try {
        const response = await fetch("/api/scan");
        const data = await response.json();

        if (data.status === "success") {
            alert(
                "Security Scan Completed!\n\n" +
                "Logs Analyzed: " + data.total_logs +
                "\nAlerts Detected: " + data.alerts.length
            );
        }

        await loadStats();
        await loadEvents();

    } catch (error) {
        console.error("Scan error:", error);
        alert("Unable to connect to the security server.");
    }

    button.disabled = false;
    button.innerText = "🔍 Run Security Scan";
}


async function loadStats() {
    try {
        const response = await fetch("/api/stats");
        const data = await response.json();

        document.getElementById("totalEvents").innerText =
            data.total_events;

        document.getElementById("highEvents").innerText =
            data.high;

        document.getElementById("mediumEvents").innerText =
            data.medium;

        document.getElementById("lowEvents").innerText =
            data.low;

    } catch (error) {
        console.error("Stats error:", error);
    }
}


async function loadEvents() {
    try {
        const response = await fetch("/api/events");
        const events = await response.json();

        const table = document.getElementById("eventsTable");

        table.innerHTML = "";

        if (events.length === 0) {
            table.innerHTML = `
                <tr>
                    <td colspan="7" class="empty">
                        No security events detected.
                    </td>
                </tr>
            `;
            return;
        }

        events.forEach(event => {

            let severityClass = "";

            if (event.severity === "High") {
                severityClass = "severity-high";
            } 
            else if (event.severity === "Medium") {
                severityClass = "severity-medium";
            } 
            else {
                severityClass = "severity-low";
            }

            const row = document.createElement("tr");

            row.innerHTML = `
                <td>${event.timestamp}</td>
                <td>${event.source_ip}</td>
                <td>${event.destination_ip}</td>
                <td>${event.port}</td>
                <td>${event.protocol}</td>

                <td>
                    <span class="severity ${severityClass}">
                        ${event.severity}
                    </span>
                </td>

                <td>${event.reason}</td>
            `;

            table.appendChild(row);
        });

    } catch (error) {
        console.error("Events error:", error);
    }
}


// Load dashboard data when page opens
document.addEventListener("DOMContentLoaded", () => {
    loadStats();
    loadEvents();
});