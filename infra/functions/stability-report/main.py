"""
48-Hour Stability Report Cloud Function

Queries GCP Monitoring uptime check results for the last 48 hours
and sends a summary email via the existing notification channel.
"""

import functions_framework
from google.cloud import monitoring_v3
from google.protobuf import timestamp_pb2
from datetime import datetime, timedelta, timezone

PROJECT_ID = "objects-devnet"
NOTIFICATION_CHANNEL = f"projects/{PROJECT_ID}/notificationChannels/9071061813963373197"

UPTIME_CHECKS = {
    "registry-health-OziyeK6kXKs": "Registry (registry.objects.foundation)",
    "bootstrap-us-health-OziyeK6kVQY": "Bootstrap US (104.154.168.138:3420)",
    "bootstrap-asia-health-FK5hrKnUaME": "Bootstrap Asia (34.146.198.253:3420)",
}


def query_uptime(client, check_id, start_time, end_time):
    """Query uptime check results for the last 48 hours."""
    interval = monitoring_v3.TimeInterval(
        start_time=start_time,
        end_time=end_time,
    )

    results = client.list_time_series(
        request={
            "name": f"projects/{PROJECT_ID}",
            "filter": (
                f'metric.type = "monitoring.googleapis.com/uptime_check/check_passed"'
                f' AND metric.labels.check_id = "{check_id}"'
            ),
            "interval": interval,
            "view": monitoring_v3.ListTimeSeriesRequest.TimeSeriesView.FULL,
            "aggregation": monitoring_v3.Aggregation(
                alignment_period={"seconds": 300},
                per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_FRACTION_TRUE,
                cross_series_reducer=monitoring_v3.Aggregation.Reducer.REDUCE_MEAN,
            ),
        }
    )

    total_points = 0
    passing_sum = 0.0

    for ts in results:
        for point in ts.points:
            total_points += 1
            passing_sum += point.value.double_value

    if total_points == 0:
        return None

    return (passing_sum / total_points) * 100


def build_report(results):
    """Format the uptime results into a readable report."""
    lines = [
        "OBJECTS Devnet - 48-Hour Stability Report",
        "=" * 42,
        "",
        f"Period: {datetime.now(timezone.utc) - timedelta(hours=48):%Y-%m-%d %H:%M UTC}"
        f" to {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC}",
        "",
    ]

    all_passed = True
    for name, uptime_pct in results.items():
        if uptime_pct is None:
            status = "NO DATA"
            all_passed = False
        elif uptime_pct >= 99.9:
            status = f"{uptime_pct:.2f}% - PASS"
        else:
            status = f"{uptime_pct:.2f}% - DEGRADED"
            all_passed = False

        lines.append(f"  {name}: {status}")

    lines.append("")
    if all_passed:
        lines.append("VERDICT: ALL CHECKS PASSED - Devnet is stable.")
        lines.append("Next step: Write quickstart README (A8).")
    else:
        lines.append("VERDICT: SOME CHECKS DEGRADED - Review before proceeding.")

    lines.append("")
    lines.append("Dashboard: https://console.cloud.google.com/monitoring/uptime?project=objects-devnet")

    return "\n".join(lines)


@functions_framework.http
def stability_report(request):
    """HTTP Cloud Function entry point."""
    client = monitoring_v3.MetricServiceClient()

    now = datetime.now(timezone.utc)
    start = now - timedelta(hours=48)

    start_ts = timestamp_pb2.Timestamp()
    start_ts.FromDatetime(start)
    end_ts = timestamp_pb2.Timestamp()
    end_ts.FromDatetime(now)

    results = {}
    for check_id, display_name in UPTIME_CHECKS.items():
        uptime_pct = query_uptime(client, check_id, start_ts, end_ts)
        results[display_name] = uptime_pct

    report = build_report(results)

    # Log the report — Cloud Logging captures this automatically.
    # A log-based alert on "STABILITY_REPORT_COMPLETE" sends to notify@objects.foundation.
    import logging
    logging.warning(f"STABILITY_REPORT_COMPLETE\n{report}")

    return report, 200
