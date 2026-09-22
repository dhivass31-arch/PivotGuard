from datetime import datetime
from collections import Counter
from html import escape


def generate_security_report(events):

    events = events or []

    total_events = len(events)

    high = sum(
        1 for event in events
        if event.get("severity") == "High"
    )

    medium = sum(
        1 for event in events
        if event.get("severity") == "Medium"
    )

    low = sum(
        1 for event in events
        if event.get("severity") == "Low"
    )

    new = sum(
        1 for event in events
        if event.get("status", "New") == "New"
    )

    acknowledged = sum(
        1 for event in events
        if event.get("status") == "Acknowledged"
    )

    investigating = sum(
        1 for event in events
        if event.get("status") == "Investigating"
    )

    resolved = sum(
        1 for event in events
        if event.get("status") == "Resolved"
    )


    # ==========================================
    # NETWORK ANALYTICS
    # ==========================================

    source_counter = Counter(
        event.get("source_ip", "Unknown")
        for event in events
    )

    destination_counter = Counter(
        event.get("destination_ip", "Unknown")
        for event in events
    )


    services = {
        22: "SSH",
        135: "RPC",
        139: "NetBIOS",
        445: "SMB",
        3389: "RDP",
        5985: "WinRM",
        5986: "WinRM"
    }

    service_counter = Counter()

    for event in events:

        try:
            port = int(
                event.get("port", 0)
            )
        except (ValueError, TypeError):
            port = 0

        service = services.get(
            port,
            "Other"
        )

        service_counter[service] += 1


    generated_at = datetime.now().strftime(
        "%d %b %Y, %I:%M:%S %p"
    )


    # ==========================================
    # EVENT ROWS
    # ==========================================

    rows = ""

    for event in events:

        severity = escape(
            str(event.get("severity", "Low"))
        )

        severity_class = severity.lower()

        status = escape(
            str(event.get("status", "New"))
        )

        rows += f"""
        <tr>

            <td>
                {escape(str(event.get("timestamp", "-")))}
            </td>

            <td class="source-ip">
                {escape(str(event.get("source_ip", "-")))}
            </td>

            <td class="destination-ip">
                {escape(str(event.get("destination_ip", "-")))}
            </td>

            <td class="port">
                {escape(str(event.get("port", "-")))}
            </td>

            <td>
                {escape(str(event.get("protocol", "-")))}
            </td>

            <td>
                <span class="severity {severity_class}">
                    {severity}
                </span>
            </td>

            <td class="reason">
                {escape(str(event.get("reason", "-")))}
            </td>

            <td>
                <span class="status">
                    {status}
                </span>
            </td>

        </tr>
        """


    if not rows:

        rows = """
        <tr>
            <td colspan="8" class="empty">
                No security events available.
            </td>
        </tr>
        """


    # ==========================================
    # TOP SOURCE
    # ==========================================

    if source_counter:

        top_source = source_counter.most_common(1)[0]

        top_source_ip = escape(
            str(top_source[0])
        )

        top_source_count = top_source[1]

    else:

        top_source_ip = "-"

        top_source_count = 0


    # ==========================================
    # TOP DESTINATION
    # ==========================================

    if destination_counter:

        top_destination = (
            destination_counter
            .most_common(1)[0]
        )

        top_destination_ip = escape(
            str(top_destination[0])
        )

        top_destination_count = (
            top_destination[1]
        )

    else:

        top_destination_ip = "-"

        top_destination_count = 0


    # ==========================================
    # MOST USED SERVICE
    # ==========================================

    if service_counter:

        most_used_service = (
            service_counter
            .most_common(1)[0][0]
        )

    else:

        most_used_service = "-"


    # ==========================================
    # REPORT HTML
    # ==========================================

    return f"""
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<title>
    PivotGuard | Security Report
</title>


<style>

/* =========================================================
   GLOBAL
   ========================================================= */

* {{
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}}


body {{

    font-family:
        "Segoe UI",
        Arial,
        Helvetica,
        sans-serif;

    background:
        #061014;

    color:
        #e8f2f4;

    line-height:
        1.5;

}}


.container {{

    width:
        min(
            1400px,
            calc(100% - 40px)
        );

    margin:
        auto;

}}


/* =========================================================
   HEADER
   ========================================================= */

header {{

    background:
        rgba(
            5,
            15,
            19,
            0.97
        );

    border-bottom:
        1px solid
        rgba(
            102,
            237,
            190,
            0.12
        );

}}


.header-inner {{

    min-height:
        76px;

    display:
        flex;

    align-items:
        center;

    justify-content:
        space-between;

    gap:
        20px;

}}


.brand {{

    display:
        flex;

    align-items:
        center;

    gap:
        13px;

}}


.logo {{

    width:
        45px;

    height:
        45px;

    display:
        flex;

    align-items:
        center;

    justify-content:
        center;

    border-radius:
        12px;

    background:
        rgba(
            67,
            239,
            182,
            0.07
        );

    border:
        1px solid
        rgba(
            67,
            239,
            182,
            0.18
        );

    font-size:
        23px;

}}


.brand h1 {{

    font-size:
        20px;

    font-weight:
        750;

}}


.brand p {{

    color:
        #6f858c;

    font-size:
        10px;

    margin-top:
        2px;

}}


.header-actions {{

    display:
        flex;

    gap:
        8px;

}}


.header-actions a {{

    padding:
        9px 13px;

    border-radius:
        8px;

    color:
        #91a7ad;

    background:
        rgba(
            255,
            255,
            255,
            0.035
        );

    border:
        1px solid
        rgba(
            255,
            255,
            255,
            0.07
        );

    text-decoration:
        none;

    font-size:
        10px;

    transition:
        0.2s ease;

}}


.header-actions a:hover {{

    color:
        #72ebbd;

    border-color:
        rgba(
            72,
            235,
            188,
            0.22
        );

}}


/* =========================================================
   MAIN
   ========================================================= */

main {{

    padding:
        35px 0 60px;

}}


/* =========================================================
   REPORT TITLE
   ========================================================= */

.report-title {{

    display:
        flex;

    align-items:
        flex-end;

    justify-content:
        space-between;

    gap:
        20px;

    margin-bottom:
        25px;

}}


.report-title h2 {{

    font-size:
        29px;

    font-weight:
        780;

}}


.report-title p {{

    margin-top:
        5px;

    color:
        #72888f;

    font-size:
        12px;

}}


.report-meta {{

    text-align:
        right;

    color:
        #71868d;

    font-size:
        10px;

}}


.report-meta strong {{

    display:
        block;

    color:
        #9eb3b8;

    margin-top:
        3px;

}}


/* =========================================================
   REPORT BANNER
   ========================================================= */

.report-banner {{

    padding:
        23px;

    margin-bottom:
        20px;

    border-radius:
        14px;

    background:
        linear-gradient(
            135deg,
            rgba(
                17,
                43,
                48,
                0.95
            ),
            rgba(
                8,
                24,
                29,
                0.95
            )
        );

    border:
        1px solid
        rgba(
            104,
            238,
            190,
            0.12
        );

}}


.report-banner-top {{

    display:
        flex;

    align-items:
        center;

    justify-content:
        space-between;

    gap:
        20px;

}}


.report-banner h3 {{

    font-size:
        17px;

}}


.report-banner p {{

    margin-top:
        4px;

    color:
        #70878e;

    font-size:
        10px;

}}


.classification {{

    padding:
        8px 12px;

    border-radius:
        999px;

    color:
        #72eabd;

    background:
        rgba(
            69,
            235,
            181,
            0.07
        );

    border:
        1px solid
        rgba(
            69,
            235,
            181,
            0.14
        );

    font-size:
        9px;

    font-weight:
        750;

    letter-spacing:
        0.6px;

}}


/* =========================================================
   SUMMARY CARDS
   ========================================================= */

.summary-grid {{

    display:
        grid;

    grid-template-columns:
        repeat(
            4,
            minmax(
                0,
                1fr
            )
        );

    gap:
        13px;

    margin-bottom:
        20px;

}}


.summary-card {{

    position:
        relative;

    overflow:
        hidden;

    padding:
        18px;

    border-radius:
        12px;

    background:
        rgba(
            13,
            29,
            34,
            0.95
        );

    border:
        1px solid
        rgba(
            139,
            192,
            202,
            0.09
        );

}}


.summary-card::before {{

    content:
        "";

    position:
        absolute;

    left:
        0;

    top:
        0;

    width:
        3px;

    height:
        100%;

    background:
        #62dfaf;

}}


.summary-card.high::before {{

    background:
        #ff707a;

}}


.summary-card.medium::before {{

    background:
        #f2c55d;

}}


.summary-card.low::before {{

    background:
        #62dca8;

}}


.summary-card span {{

    color:
        #71878e;

    font-size:
        9px;

    text-transform:
        uppercase;

    letter-spacing:
        0.6px;

}}


.summary-card strong {{

    display:
        block;

    margin-top:
        7px;

    font-size:
        27px;

}}


.summary-card.high strong {{

    color:
        #ff858d;

}}


.summary-card.medium strong {{

    color:
        #ffd171;

}}


.summary-card.low strong {{

    color:
        #72dfb0;

}}


/* =========================================================
   PANELS
   ========================================================= */

.panel-grid {{

    display:
        grid;

    grid-template-columns:
        repeat(
            3,
            minmax(
                0,
                1fr
            )
        );

    gap:
        15px;

    margin-bottom:
        20px;

}}


.panel {{

    background:
        rgba(
            11,
            27,
            32,
            0.95
        );

    border:
        1px solid
        rgba(
            139,
            192,
            202,
            0.09
        );

    border-radius:
        13px;

    overflow:
        hidden;

}}


.panel-header {{

    padding:
        16px 18px;

    border-bottom:
        1px solid
        rgba(
            255,
            255,
            255,
            0.055
        );

}}


.panel-header h3 {{

    font-size:
        13px;

}}


.panel-header p {{

    color:
        #6d838a;

    font-size:
        9px;

    margin-top:
        3px;

}}


.panel-body {{

    padding:
        17px;

}}


/* =========================================================
   ANALYTICS
   ========================================================= */

.analytics-item {{

    display:
        flex;

    align-items:
        center;

    justify-content:
        space-between;

    padding:
        10px 11px;

    margin-bottom:
        7px;

    border-radius:
        8px;

    background:
        rgba(
            255,
            255,
            255,
            0.025
        );

    border:
        1px solid
        rgba(
            255,
            255,
            255,
            0.045
        );

}}


.analytics-item:last-child {{

    margin-bottom:
        0;

}}


.analytics-item span {{

    color:
        #92a7ad;

    font-size:
        10px;

}}


.analytics-item strong {{

    color:
        #6fe6b9;

    font-size:
        10px;

}}


/* =========================================================
   STATUS
   ========================================================= */

.status-grid {{

    display:
        grid;

    grid-template-columns:
        repeat(
            4,
            minmax(
                0,
                1fr
            )
        );

    gap:
        9px;

}}


.status-box {{

    padding:
        13px;

    border-radius:
        9px;

    background:
        rgba(
            255,
            255,
            255,
            0.025
        );

    border:
        1px solid
        rgba(
            255,
            255,
            255,
            0.05
        );

}}


.status-box span {{

    color:
        #6f858c;

    font-size:
        8px;

    text-transform:
        uppercase;

}}


.status-box strong {{

    display:
        block;

    margin-top:
        5px;

    color:
        #e4f0f2;

    font-size:
        19px;

}}


/* =========================================================
   EVENTS
   ========================================================= */

.events-panel {{

    margin-bottom:
        20px;

}}


.table-wrapper {{

    overflow-x:
        auto;

}}


table {{

    width:
        100%;

    min-width:
        1050px;

    border-collapse:
        collapse;

}}


thead {{

    background:
        rgba(
            255,
            255,
            255,
            0.025
        );

}}


th {{

    padding:
        12px 13px;

    text-align:
        left;

    color:
        #71878e;

    font-size:
        8px;

    text-transform:
        uppercase;

    letter-spacing:
        0.7px;

    border-bottom:
        1px solid
        rgba(
            255,
            255,
            255,
            0.06
        );

}}


td {{

    padding:
        13px;

    color:
        #9db1b6;

    font-size:
        9px;

    border-bottom:
        1px solid
        rgba(
            255,
            255,
            255,
            0.045
        );

    vertical-align:
        middle;

}}


tbody tr:hover {{

    background:
        rgba(
            72,
            234,
            183,
            0.025
        );

}}


.source-ip {{

    color:
        #ff9fa6;

    font-weight:
        650;

}}


.destination-ip {{

    color:
        #72dfb2;

    font-weight:
        650;

}}


.port {{

    color:
        #c2d2d6;

    font-family:
        Consolas,
        monospace;

    font-weight:
        700;

}}


.reason {{

    max-width:
        360px;

    color:
        #82979d;

}}


/* =========================================================
   SEVERITY
   ========================================================= */

.severity {{

    display:
        inline-flex;

    padding:
        5px 9px;

    border-radius:
        999px;

    font-size:
        8px;

    font-weight:
        800;

    text-transform:
        uppercase;

}}


.severity.high {{

    color:
        #ff9da4;

    background:
        rgba(
            255,
            76,
            88,
            0.10
        );

    border:
        1px solid
        rgba(
            255,
            76,
            88,
            0.15
        );

}}


.severity.medium {{

    color:
        #ffd276;

    background:
        rgba(
            255,
            194,
            73,
            0.09
        );

}}


.severity.low {{

    color:
        #75e3b4;

    background:
        rgba(
            71,
            226,
            168,
            0.09
        );

}}


/* =========================================================
   EVENT STATUS
   ========================================================= */

.status {{

    display:
        inline-flex;

    padding:
        5px 8px;

    border-radius:
        6px;

    color:
        #9db1b6;

    background:
        rgba(
            255,
            255,
            255,
            0.045
        );

    font-size:
        8px;

}}


/* =========================================================
   INTERPRETATION
   ========================================================= */

.interpretation {{

    margin-bottom:
        20px;

}}


.interpretation-body {{

    padding:
        20px;

}}


.interpretation-body p {{

    color:
        #92a7ad;

    font-size:
        11px;

    line-height:
        1.8;

}}


.interpretation-body strong {{

    color:
        #d6e6e9;

}}


/* =========================================================
   DISCLAIMER
   ========================================================= */

.disclaimer {{

    padding:
        17px;

    border-radius:
        10px;

    background:
        rgba(
            255,
            255,
            255,
            0.022
        );

    border:
        1px solid
        rgba(
            255,
            255,
            255,
            0.055
        );

    color:
        #667c83;

    font-size:
        9px;

    line-height:
        1.7;

    margin-bottom:
        25px;

}}


/* =========================================================
   FOOTER
   ========================================================= */

footer {{

    padding:
        20px 0;

    border-top:
        1px solid
        rgba(
            255,
            255,
            255,
            0.055
        );

    text-align:
        center;

    color:
        #50666d;

    font-size:
        9px;

}}


/* =========================================================
   PRINT
   ========================================================= */

@media print {{

    body {{

        background:
            white;

        color:
            black;

    }}

    header,
    .header-actions {{

        display:
            none;

    }}

    .panel,
    .summary-card,
    .report-banner {{

        break-inside:
            avoid;

    }}

}}


/* =========================================================
   RESPONSIVE
   ========================================================= */

@media (max-width: 900px) {{

    .summary-grid {{

        grid-template-columns:
            repeat(
                2,
                minmax(
                    0,
                    1fr
                )
            );

    }}

    .panel-grid {{

        grid-template-columns:
            1fr;

    }}

}}


@media (max-width: 600px) {{

    .container {{

        width:
            calc(
                100% - 24px
            );

    }}

    .header-inner {{

        flex-wrap:
            wrap;

        padding:
            14px 0;

    }}

    .report-title {{

        flex-direction:
            column;

        align-items:
            flex-start;

    }}

    .report-meta {{

        text-align:
            left;

    }}

    .summary-grid {{

        grid-template-columns:
            1fr;

    }}

    .status-grid {{

        grid-template-columns:
            repeat(
                2,
                minmax(
                    0,
                    1fr
                )
            );

    }}

}}


</style>

</head>


<body>


<header>

    <div class="container header-inner">


        <div class="brand">

            <div class="logo">
                🛡️
            </div>

            <div>

                <h1>
                    PivotGuard
                </h1>

                <p>
                    Pivoting &amp; Lateral Movement Detection System
                </p>

            </div>

        </div>


        <div class="header-actions">

            <a href="/">
                Dashboard
            </a>

            <a href="/monitoring">
                Monitoring
            </a>

            <a href="/logout">
                Logout
            </a>

        </div>


    </div>

</header>



<main>

<div class="container">


    <!-- =====================================================
         TITLE
         ===================================================== -->

    <section class="report-title">

        <div>

            <h2>
                Security Analysis Report
            </h2>

            <p>
                Defensive network security event analysis and lateral movement detection
            </p>

        </div>


        <div class="report-meta">

            Generated

            <strong>
                {generated_at}
            </strong>

        </div>

    </section>



    <!-- =====================================================
         REPORT BANNER
         ===================================================== -->

    <section class="report-banner">

        <div class="report-banner-top">

            <div>

                <h3>
                    Defensive Security Assessment
                </h3>

                <p>
                    Automated analysis generated by the PivotGuard detection engine.
                </p>

            </div>


            <div class="classification">

                DEFENSIVE ANALYSIS

            </div>

        </div>

    </section>



    <!-- =====================================================
         SUMMARY
         ===================================================== -->

    <section class="summary-grid">


        <div class="summary-card">

            <span>
                Total Events
            </span>

            <strong>
                {total_events}
            </strong>

        </div>


        <div class="summary-card high">

            <span>
                High Risk
            </span>

            <strong>
                {high}
            </strong>

        </div>


        <div class="summary-card medium">

            <span>
                Medium Risk
            </span>

            <strong>
                {medium}
            </strong>

        </div>


        <div class="summary-card low">

            <span>
                Low Risk
            </span>

            <strong>
                {low}
            </strong>

        </div>


    </section>



    <!-- =====================================================
         ANALYTICS PANELS
         ===================================================== -->

    <section class="panel-grid">


        <!-- NETWORK OVERVIEW -->

        <div class="panel">

            <div class="panel-header">

                <h3>
                    Network Overview
                </h3>

                <p>
                    Observed source and destination activity
                </p>

            </div>


            <div class="panel-body">


                <div class="analytics-item">

                    <span>
                        Unique Source Hosts
                    </span>

                    <strong>
                        {len(source_counter)}
                    </strong>

                </div>


                <div class="analytics-item">

                    <span>
                        Unique Destination Hosts
                    </span>

                    <strong>
                        {len(destination_counter)}
                    </strong>

                </div>


                <div class="analytics-item">

                    <span>
                        Top Source
                    </span>

                    <strong>
                        {top_source_ip}
                    </strong>

                </div>


                <div class="analytics-item">

                    <span>
                        Top Destination
                    </span>

                    <strong>
                        {top_destination_ip}
                    </strong>

                </div>


            </div>

        </div>



        <!-- SERVICES -->

        <div class="panel">

            <div class="panel-header">

                <h3>
                    Remote Services
                </h3>

                <p>
                    Detected remote service activity
                </p>

            </div>


            <div class="panel-body">

                {
                    "".join(
                        f'''
                        <div class="analytics-item">
                            <span>{escape(str(service))}</span>
                            <strong>{count}</strong>
                        </div>
                        '''
                        for service, count
                        in service_counter.most_common()
                    )
                    if service_counter
                    else
                    '''
                    <div class="analytics-item">
                        <span>No services</span>
                        <strong>0</strong>
                    </div>
                    '''
                }

            </div>

        </div>



        <!-- ALERT STATUS -->

        <div class="panel">

            <div class="panel-header">

                <h3>
                    Alert Workflow
                </h3>

                <p>
                    Current investigation status
                </p>

            </div>


            <div class="panel-body">


                <div class="status-grid">


                    <div class="status-box">

                        <span>
                            New
                        </span>

                        <strong>
                            {new}
                        </strong>

                    </div>


                    <div class="status-box">

                        <span>
                            Acknowledged
                        </span>

                        <strong>
                            {acknowledged}
                        </strong>

                    </div>


                    <div class="status-box">

                        <span>
                            Investigating
                        </span>

                        <strong>
                            {investigating}
                        </strong>

                    </div>


                    <div class="status-box">

                        <span>
                            Resolved
                        </span>

                        <strong>
                            {resolved}
                        </strong>

                    </div>


                </div>


            </div>

        </div>


    </section>



    <!-- =====================================================
         EVENT TABLE
         ===================================================== -->

    <section class="panel events-panel">


        <div class="panel-header">

            <h3>
                Detected Security Events
            </h3>

            <p>
                Events identified by configured PivotGuard detection rules
            </p>

        </div>


        <div class="table-wrapper">

            <table>

                <thead>

                    <tr>

                        <th>
                            Timestamp
                        </th>

                        <th>
                            Source IP
                        </th>

                        <th>
                            Destination IP
                        </th>

                        <th>
                            Port
                        </th>

                        <th>
                            Protocol
                        </th>

                        <th>
                            Severity
                        </th>

                        <th>
                            Detection Reason
                        </th>

                        <th>
                            Status
                        </th>

                    </tr>

                </thead>


                <tbody>

                    {rows}

                </tbody>

            </table>

        </div>

    </section>



    <!-- =====================================================
         INTERPRETATION
         ===================================================== -->

    <section class="panel interpretation">


        <div class="panel-header">

            <h3>
                Detection Interpretation
            </h3>

            <p>
                Defensive analysis of observed network patterns
            </p>

        </div>


        <div class="interpretation-body">

            <p>

                PivotGuard detected network communication patterns
                that matched the configured lateral movement detection
                rules. The analysis considers repeated communication
                from the same source host, multiple internal
                destinations, and the use of common remote services.

                <br><br>

                The most frequently observed source host was
                <strong>
                    {top_source_ip}
                </strong>
                with
                <strong>
                    {top_source_count}
                </strong>
                detected event(s).

                The most frequently observed destination host was
                <strong>
                    {top_destination_ip}
                </strong>
                with
                <strong>
                    {top_destination_count}
                </strong>
                detected event(s).

                The most frequently observed remote service was
                <strong>
                    {escape(str(most_used_service))}
                </strong>.

                <br><br>

                Remote services such as SSH, SMB, RDP and WinRM
                may be legitimate administrative services. Therefore,
                detected patterns should be validated using
                authentication logs, endpoint telemetry, user context
                and other security evidence.

            </p>

        </div>

    </section>



    <!-- =====================================================
         DISCLAIMER
         ===================================================== -->

    <div class="disclaimer">

        <strong>
            Academic / Defensive Use:
        </strong>

        This report is generated for cybersecurity monitoring,
        defensive analysis and academic demonstration.
        Detected patterns represent indicators requiring
        investigation and do not by themselves establish
        malicious activity.

    </div>



</div>

</main>



<footer>

    PivotGuard • Pivoting &amp; Lateral Movement Detection System
    <br>
    Defensive Cybersecurity Monitoring • Academic Project

</footer>


</body>

</html>
"""