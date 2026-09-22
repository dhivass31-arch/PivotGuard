from flask import (
    Flask,
    render_template,
    jsonify,
    request,
    session,
    redirect,
    url_for
)

from detector import detect_lateral_movement
from database import (
    init_db,
    get_events,
    add_event,
    update_event_status
)
from report import generate_security_report
from auth import check_login, login_required

import csv
import os
from collections import Counter


app = Flask(__name__)

# Demo secret key
app.secret_key = "pivotguard-secret-key-2026"

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"csv"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------------------------------------------------
# SAMPLE NETWORK LOGS
# ---------------------------------------------------------

SAMPLE_LOGS = [
    {
        "timestamp": "2026-09-18 09:10:21",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "port": 445,
        "protocol": "TCP"
    },
    {
        "timestamp": "2026-09-18 09:11:05",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.21",
        "port": 445,
        "protocol": "TCP"
    },
    {
        "timestamp": "2026-09-18 09:12:18",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.22",
        "port": 3389,
        "protocol": "TCP"
    },
    {
        "timestamp": "2026-09-18 09:13:42",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.23",
        "port": 22,
        "protocol": "TCP"
    },
    {
        "timestamp": "2026-09-18 09:14:30",
        "source_ip": "192.168.1.30",
        "destination_ip": "192.168.1.40",
        "port": 80,
        "protocol": "TCP"
    },
    {
        "timestamp": "2026-09-18 09:15:12",
        "source_ip": "192.168.1.31",
        "destination_ip": "192.168.1.41",
        "port": 443,
        "protocol": "TCP"
    }
]


# ---------------------------------------------------------
# REMOTE SERVICES
# ---------------------------------------------------------

REMOTE_SERVICES = {
    22: "SSH",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    3389: "RDP",
    5985: "WinRM",
    5986: "WinRM"
}


# ---------------------------------------------------------
# FILE VALIDATION
# ---------------------------------------------------------

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# ---------------------------------------------------------
# CSV READER
# ---------------------------------------------------------

def read_csv_logs(filepath):

    logs = []

    with open(
        filepath,
        "r",
        encoding="utf-8-sig",
        newline=""
    ) as csv_file:

        reader = csv.DictReader(csv_file)

        required_columns = {
            "timestamp",
            "source_ip",
            "destination_ip",
            "port",
            "protocol"
        }

        actual_columns = set(
            reader.fieldnames or []
        )

        if not required_columns.issubset(actual_columns):
            raise ValueError(
                "CSV must contain: "
                "timestamp, source_ip, destination_ip, "
                "port, protocol"
            )

        for row in reader:

            if not row.get("source_ip"):
                continue

            if not row.get("destination_ip"):
                continue

            try:
                port = int(
                    row.get("port", 0)
                )
            except (ValueError, TypeError):
                port = 0

            logs.append({
                "timestamp": row.get(
                    "timestamp",
                    ""
                ),
                "source_ip": row.get(
                    "source_ip",
                    ""
                ),
                "destination_ip": row.get(
                    "destination_ip",
                    ""
                ),
                "port": port,
                "protocol": row.get(
                    "protocol",
                    "TCP"
                )
            })

    return logs


# ---------------------------------------------------------
# LOGIN
# ---------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if session.get("logged_in"):
        return redirect(
            url_for("home")
        )

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if check_login(
            username,
            password
        ):

            session["logged_in"] = True
            session["username"] = username

            return redirect(
                url_for("home")
            )

        error = "Invalid username or password."

    return render_template(
        "login.html",
        error=error
    )


# ---------------------------------------------------------
# LOGOUT
# ---------------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ---------------------------------------------------------
# MAIN DASHBOARD
# ---------------------------------------------------------

@app.route("/")
@login_required
def home():

    events = get_events()

    high = sum(
        1
        for event in events
        if event["severity"] == "High"
    )

    medium = sum(
        1
        for event in events
        if event["severity"] == "Medium"
    )

    low = sum(
        1
        for event in events
        if event["severity"] == "Low"
    )

    stats = {
        "total_events": len(events),
        "high": high,
        "medium": medium,
        "low": low
    }

    return render_template(
        "index.html",
        events=events,
        stats=stats
    )


# ---------------------------------------------------------
# MONITORING PAGE
# ---------------------------------------------------------

@app.route("/monitoring")
@login_required
def monitoring():

    return render_template(
        "monitoring.html"
    )


# ---------------------------------------------------------
# SECURITY SCAN
# ---------------------------------------------------------

@app.route("/api/scan")
@login_required
def scan():

    alerts = detect_lateral_movement(
        SAMPLE_LOGS
    )

    for alert in alerts:
        add_event(alert)

    return jsonify({
        "status": "success",
        "message": "Security analysis completed",
        "total_logs": len(SAMPLE_LOGS),
        "alerts": alerts
    })


# ---------------------------------------------------------
# CSV UPLOAD
# ---------------------------------------------------------

@app.route(
    "/api/upload",
    methods=["POST"]
)
@login_required
def upload_csv():

    if "file" not in request.files:

        return jsonify({
            "status": "error",
            "message": "No CSV file selected"
        }), 400

    file = request.files["file"]

    if file.filename == "":

        return jsonify({
            "status": "error",
            "message": "No CSV file selected"
        }), 400

    if not allowed_file(
        file.filename
    ):

        return jsonify({
            "status": "error",
            "message": "Only CSV files are allowed"
        }), 400

    filename = os.path.basename(
        file.filename
    )

    filepath = os.path.join(
        UPLOAD_FOLDER,
        filename
    )

    try:

        file.save(filepath)

        logs = read_csv_logs(
            filepath
        )

        if not logs:

            return jsonify({
                "status": "error",
                "message": "CSV contains no valid network logs"
            }), 400

        alerts = detect_lateral_movement(
            logs
        )

        for alert in alerts:
            add_event(alert)

        return jsonify({
            "status": "success",
            "message": "CSV analysis completed",
            "filename": filename,
            "total_logs": len(logs),
            "total_alerts": len(alerts),
            "alerts": alerts
        })

    except Exception as error:

        return jsonify({
            "status": "error",
            "message": str(error)
        }), 500


# ---------------------------------------------------------
# GET ALL EVENTS
# ---------------------------------------------------------

@app.route("/api/events")
@login_required
def events():

    return jsonify(
        get_events()
    )


# ---------------------------------------------------------
# UPDATE ALERT STATUS
# ---------------------------------------------------------

@app.route(
    "/api/events/<int:event_id>/status",
    methods=["PUT"]
)
@login_required
def update_alert_status(
    event_id
):

    data = request.get_json(
        silent=True
    ) or {}

    status = data.get(
        "status",
        ""
    )

    allowed_statuses = {
        "New",
        "Acknowledged",
        "Investigating",
        "Resolved"
    }

    if status not in allowed_statuses:

        return jsonify({
            "status": "error",
            "message": "Invalid alert status"
        }), 400

    updated = update_event_status(
        event_id,
        status
    )

    if not updated:

        return jsonify({
            "status": "error",
            "message": "Alert not found"
        }), 404

    return jsonify({
        "status": "success",
        "message": "Alert status updated",
        "event_id": event_id,
        "new_status": status
    })


# ---------------------------------------------------------
# STATISTICS API
# ---------------------------------------------------------

@app.route("/api/stats")
@login_required
def stats():

    events = get_events()

    high = sum(
        1
        for event in events
        if event["severity"] == "High"
    )

    medium = sum(
        1
        for event in events
        if event["severity"] == "Medium"
    )

    low = sum(
        1
        for event in events
        if event["severity"] == "Low"
    )

    new = sum(
        1
        for event in events
        if event.get(
            "status",
            "New"
        ) == "New"
    )

    acknowledged = sum(
        1
        for event in events
        if event.get(
            "status"
        ) == "Acknowledged"
    )

    investigating = sum(
        1
        for event in events
        if event.get(
            "status"
        ) == "Investigating"
    )

    resolved = sum(
        1
        for event in events
        if event.get(
            "status"
        ) == "Resolved"
    )

    return jsonify({

        "total_events": len(events),

        "high": high,

        "medium": medium,

        "low": low,

        "new": new,

        "acknowledged": acknowledged,

        "investigating": investigating,

        "resolved": resolved
    })


# ---------------------------------------------------------
# ANALYTICS API
# ---------------------------------------------------------

@app.route("/api/analytics")
@login_required
def analytics():

    events = get_events()

    severity_counts = Counter(
        event.get(
            "severity",
            "Unknown"
        )
        for event in events
    )

    status_counts = Counter(
        event.get(
            "status",
            "New"
        )
        for event in events
    )

    source_counts = Counter(
        event.get(
            "source_ip",
            "Unknown"
        )
        for event in events
    )

    destination_counts = Counter(
        event.get(
            "destination_ip",
            "Unknown"
        )
        for event in events
    )

    service_counts = Counter()

    for event in events:

        try:
            port = int(
                event.get(
                    "port",
                    0
                )
            )
        except (ValueError, TypeError):

            port = 0

        service = REMOTE_SERVICES.get(
            port,
            "Other"
        )

        service_counts[service] += 1

    return jsonify({

        "total_events": len(events),

        "severity": {

            "High":
                severity_counts.get(
                    "High",
                    0
                ),

            "Medium":
                severity_counts.get(
                    "Medium",
                    0
                ),

            "Low":
                severity_counts.get(
                    "Low",
                    0
                )
        },

        "status": {

            "New":
                status_counts.get(
                    "New",
                    0
                ),

            "Acknowledged":
                status_counts.get(
                    "Acknowledged",
                    0
                ),

            "Investigating":
                status_counts.get(
                    "Investigating",
                    0
                ),

            "Resolved":
                status_counts.get(
                    "Resolved",
                    0
                )
        },

        "top_sources": [

            {
                "ip": ip,
                "count": count
            }

            for ip, count
            in source_counts.most_common(10)
        ],

        "top_destinations": [

            {
                "ip": ip,
                "count": count
            }

            for ip, count
            in destination_counts.most_common(10)
        ],

        "remote_services": [

            {
                "service": service,
                "count": count
            }

            for service, count
            in service_counts.most_common()
        ]
    })


# ---------------------------------------------------------
# SECURITY REPORT
# ---------------------------------------------------------

@app.route("/report")
@login_required
def report():

    events = get_events()

    report_html = generate_security_report(
        events
    )

    return report_html


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------

@app.route("/api/health")
@login_required
def health():

    return jsonify({

        "status": "online",

        "application": "PivotGuard",

        "detection_engine": "active",

        "database": "SQLite",

        "monitoring": "defensive",

        "server": "Flask"
    })


# ---------------------------------------------------------
# DATABASE INITIALIZATION
# ---------------------------------------------------------
# IMPORTANT:
# This runs when Flask/Gunicorn imports app.py.
# Required for Render deployment.

init_db()


# ---------------------------------------------------------
# LOCAL DEVELOPMENT
# ---------------------------------------------------------

if __name__ == "__main__":

    print()

    print("=" * 60)

    print(
        "        PIVOTING & LATERAL MOVEMENT"
    )

    print(
        "              DETECTION SYSTEM"
    )

    print("=" * 60)

    print()

    print(
        "  Login     : http://127.0.0.1:5000/login"
    )

    print(
        "  Dashboard : http://127.0.0.1:5000"
    )

    print(
        "  Monitoring: http://127.0.0.1:5000/monitoring"
    )

    print(
        "  Report    : http://127.0.0.1:5000/report"
    )

    print()

    print("=" * 60)

    print(
        "  PivotGuard server starting..."
    )

    print(
        "  Press CTRL+C to stop the server."
    )

    print("=" * 60)

    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )