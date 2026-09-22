from collections import defaultdict
from datetime import datetime


# ============================================================
# REMOTE SERVICES
# ============================================================

REMOTE_PORTS = {
    22: "SSH",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM",
    5986: "WinRM"
}


# ============================================================
# DETECTION ENGINE
# ============================================================

def detect_lateral_movement(logs):

    alerts = []

    source_destinations = defaultdict(set)
    source_ports = defaultdict(set)
    source_connections = defaultdict(int)

    # --------------------------------------------------------
    # PRE-PROCESS NETWORK LOGS
    # --------------------------------------------------------

    for log in logs:

        source = log.get("source_ip", "")
        destination = log.get("destination_ip", "")

        try:
            port = int(log.get("port", 0))
        except (ValueError, TypeError):
            port = 0

        source_destinations[source].add(destination)
        source_ports[source].add(port)
        source_connections[source] += 1


    # --------------------------------------------------------
    # ANALYZE EACH LOG
    # --------------------------------------------------------

    for log in logs:

        source = log.get("source_ip", "")
        destination = log.get("destination_ip", "")

        try:
            port = int(log.get("port", 0))
        except (ValueError, TypeError):
            port = 0

        protocol = log.get("protocol", "TCP")
        timestamp = log.get("timestamp", "")

        reasons = []
        severity = "Low"


        # ====================================================
        # PATTERN 1: MULTIPLE INTERNAL HOSTS
        # ====================================================

        if len(source_destinations[source]) >= 4:

            reasons.append(
                "Source contacted multiple internal hosts"
            )

            severity = "High"


        elif len(source_destinations[source]) >= 2:

            reasons.append(
                "Source contacted multiple internal hosts"
            )

            if severity == "Low":
                severity = "Medium"


        # ====================================================
        # PATTERN 2: REMOTE SERVICE DETECTION
        # ====================================================

        if port in REMOTE_PORTS:

            service = REMOTE_PORTS[port]

            reasons.append(
                f"Remote service detected ({service})"
            )

            if severity == "Low":
                severity = "Medium"


        # ====================================================
        # PATTERN 3: SAME SOURCE AND DESTINATION
        # ====================================================

        if source == destination:

            reasons.append(
                "Source and destination are identical"
            )

            severity = "Medium"


        # ====================================================
        # PATTERN 4: MULTIPLE REMOTE SERVICES
        # ====================================================

        remote_service_count = sum(
            1
            for p in source_ports[source]
            if p in REMOTE_PORTS
        )

        if remote_service_count >= 2:

            reasons.append(
                "Source used multiple remote services"
            )

            severity = "High"


        # ====================================================
        # PATTERN 5: REPEATED CONNECTIONS
        # ====================================================

        if source_connections[source] >= 5:

            reasons.append(
                "High number of connections from same source"
            )

            severity = "High"


        # ====================================================
        # PATTERN 6: POSSIBLE PORT SCANNING
        # ====================================================

        unique_ports = len(source_ports[source])

        if unique_ports >= 5:

            reasons.append(
                "Multiple destination ports detected from source"
            )

            severity = "High"


        # ====================================================
        # CREATE ALERT
        # ====================================================

        if reasons:

            alerts.append({

                "timestamp": timestamp,

                "source_ip": source,

                "destination_ip": destination,

                "port": port,

                "protocol": protocol,

                "event_type": "Lateral Movement",

                "severity": severity,

                "reason": " | ".join(reasons)

            })


    return alerts