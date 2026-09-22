import sqlite3


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DB_NAME = "security_events.db"


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    connection = sqlite3.connect(DB_NAME)

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def init_db():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            timestamp TEXT,

            source_ip TEXT,

            destination_ip TEXT,

            port INTEGER,

            protocol TEXT,

            event_type TEXT,

            severity TEXT,

            reason TEXT,

            status TEXT DEFAULT 'New',

            UNIQUE(
                timestamp,
                source_ip,
                destination_ip,
                port,
                protocol,
                event_type
            )
        )
    """)

    # --------------------------------------------------------
    # Add status column if an older database already exists
    # --------------------------------------------------------

    columns = connection.execute(
        "PRAGMA table_info(events)"
    ).fetchall()

    column_names = [
        column["name"]
        for column in columns
    ]

    if "status" not in column_names:

        connection.execute("""
            ALTER TABLE events
            ADD COLUMN status TEXT DEFAULT 'New'
        """)

    connection.commit()

    connection.close()


# ============================================================
# GET ALL EVENTS
# ============================================================

def get_events():

    connection = get_connection()

    events = connection.execute("""
        SELECT *
        FROM events
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return [
        dict(event)
        for event in events
    ]


# ============================================================
# ADD SECURITY EVENT
# ============================================================

def add_event(event):

    connection = get_connection()

    connection.execute("""
        INSERT OR IGNORE INTO events
        (
            timestamp,
            source_ip,
            destination_ip,
            port,
            protocol,
            event_type,
            severity,
            reason,
            status
        )

        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (

        event.get("timestamp", ""),

        event.get("source_ip", ""),

        event.get("destination_ip", ""),

        event.get("port", 0),

        event.get("protocol", "TCP"),

        event.get(
            "event_type",
            "Lateral Movement"
        ),

        event.get(
            "severity",
            "Low"
        ),

        event.get(
            "reason",
            ""
        ),

        event.get(
            "status",
            "New"
        )

    ))

    connection.commit()

    connection.close()


# ============================================================
# UPDATE ALERT STATUS
# ============================================================

def update_event_status(event_id, status):

    allowed_statuses = {

        "New",

        "Acknowledged",

        "Investigating",

        "Resolved"
    }

    if status not in allowed_statuses:

        return False


    connection = get_connection()

    cursor = connection.execute("""
        UPDATE events

        SET status = ?

        WHERE id = ?
    """, (

        status,

        event_id

    ))

    connection.commit()

    updated = cursor.rowcount > 0

    connection.close()

    return updated