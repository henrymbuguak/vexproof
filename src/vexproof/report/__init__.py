"""Turn findings into decisions: priority, an upgrade plan, OpenVEX and an HTML report.

This stage reads finished findings only. It never changes a verdict: the service profile and
exploit signals decide what to fix first, never whether code is reachable.
"""
