"""Google Calendar API client with OAuth authentication.

Manage Google Calendar events programmatically with OAuth 2.0 authentication.

Usage:
    from auth_utils.calendar import CalendarClient

    # Initialize (requires OAuth authorization)
    client = CalendarClient()

    # List calendars
    calendars = client.list_calendars()

    # List events
    events = client.list_events()

    # Create an event
    event = client.create_event(
        summary="Team Meeting",
        start="2026-01-25T10:00:00",
        end="2026-01-25T11:00:00",
    )

OAuth Setup:
    1. Download OAuth credentials from Google Cloud Console
    2. Import: auth-utils google import ~/Downloads/credentials.json
    3. Authorize: auth-utils calendar auth
"""

from __future__ import annotations

from auth_utils.calendar.client import Calendar, CalendarClient, Event

__all__ = ["CalendarClient", "Calendar", "Event"]
