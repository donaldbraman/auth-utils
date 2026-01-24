"""Google Calendar API client implementation."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from auth_utils.google import GoogleOAuth
from auth_utils.google.exceptions import AuthorizationRequired


@dataclass
class Calendar:
    """Represents a Google Calendar."""

    id: str
    summary: str
    description: str | None = None
    primary: bool = False
    time_zone: str | None = None


@dataclass
class Event:
    """Represents a Google Calendar event."""

    id: str
    summary: str
    start: datetime | None = None
    end: datetime | None = None
    description: str | None = None
    location: str | None = None
    status: str = "confirmed"
    html_link: str | None = None
    attendees: list[str] | None = None

    @property
    def is_all_day(self) -> bool:
        """Check if event is all-day (no time component)."""
        return self.start is not None and self.start.hour == 0 and self.start.minute == 0


class CalendarClient:
    """Google Calendar API client with OAuth authentication.

    Provides access to Google Calendar for managing calendars and events.

    Usage:
        client = CalendarClient()

        # List calendars
        calendars = client.list_calendars()

        # List events
        events = client.list_events()

        # Create an event
        event = client.create_event(
            summary="Meeting",
            start="2026-01-25T10:00:00",
            end="2026-01-25T11:00:00",
        )

    Note:
        Requires OAuth authorization. Run `auth-utils calendar auth` to authorize.
    """

    def __init__(
        self,
        scopes: list[str] | None = None,
    ) -> None:
        """Initialize Calendar client.

        Args:
            scopes: OAuth scopes. Defaults to ["calendar"].
        """
        self._scopes = scopes or ["calendar"]
        self._auth: GoogleOAuth | None = None
        self._service: Any = None

    def _get_service(self) -> Any:
        """Get or create Calendar API service."""
        if self._service is None:
            self._auth = GoogleOAuth(scopes=self._scopes)
            if not self._auth.is_authorized():
                raise AuthorizationRequired(
                    self._auth.get_authorization_url(),
                    "Calendar API requires OAuth authorization. "
                    "Run 'auth-utils calendar auth' to authorize.",
                )
            self._service = self._auth.build_service("calendar", "v3")
        return self._service

    def authorize(self, timeout: int = 120) -> bool:
        """Perform interactive OAuth authorization.

        Args:
            timeout: Seconds to wait for OAuth callback.

        Returns:
            True if authorization successful.

        Raises:
            AuthorizationRequired: If browser cannot be opened.
            TokenError: If authorization fails.
        """
        self._auth = GoogleOAuth(scopes=self._scopes)
        self._auth.authorize(timeout=timeout)
        self._service = None  # Force service recreation
        return True

    def is_authorized(self) -> bool:
        """Check if client is authorized."""
        try:
            auth = GoogleOAuth(scopes=self._scopes)
            return auth.is_authorized()
        except Exception:
            return False

    # =========================================================================
    # Calendars
    # =========================================================================

    def list_calendars(self) -> list[Calendar]:
        """List all calendars.

        Returns:
            List of Calendar objects.
        """
        service = self._get_service()
        results = service.calendarList().list().execute()
        items = results.get("items", [])

        return [self._parse_calendar(item) for item in items]

    def get_calendar(self, calendar_id: str = "primary") -> Calendar | None:
        """Get a specific calendar.

        Args:
            calendar_id: Calendar ID or "primary" for the main calendar.

        Returns:
            Calendar or None if not found.
        """
        service = self._get_service()
        try:
            result = service.calendarList().get(calendarId=calendar_id).execute()
            return self._parse_calendar(result)
        except Exception:
            return None

    def _parse_calendar(self, data: dict) -> Calendar:
        """Parse calendar from API response."""
        return Calendar(
            id=data["id"],
            summary=data.get("summary", ""),
            description=data.get("description"),
            primary=data.get("primary", False),
            time_zone=data.get("timeZone"),
        )

    # =========================================================================
    # Events
    # =========================================================================

    def list_events(
        self,
        calendar_id: str = "primary",
        max_results: int = 100,
        time_min: datetime | str | None = None,
        time_max: datetime | str | None = None,
        query: str | None = None,
    ) -> list[Event]:
        """List events in a calendar.

        Args:
            calendar_id: Calendar ID or "primary" for the main calendar.
            max_results: Maximum number of events to return.
            time_min: Start of time range (defaults to now).
            time_max: End of time range.
            query: Free text search query.

        Returns:
            List of Event objects.
        """
        service = self._get_service()

        # Default time_min to now if not specified
        if time_min is None:
            time_min = datetime.utcnow()

        # Format times
        time_min_str = self._format_datetime(time_min) if time_min else None
        time_max_str = self._format_datetime(time_max) if time_max else None

        kwargs: dict[str, Any] = {
            "calendarId": calendar_id,
            "maxResults": max_results,
            "singleEvents": True,
            "orderBy": "startTime",
        }

        if time_min_str:
            kwargs["timeMin"] = time_min_str
        if time_max_str:
            kwargs["timeMax"] = time_max_str
        if query:
            kwargs["q"] = query

        results = service.events().list(**kwargs).execute()
        items = results.get("items", [])

        return [self._parse_event(item) for item in items]

    def get_event(self, event_id: str, calendar_id: str = "primary") -> Event | None:
        """Get a specific event.

        Args:
            event_id: Event ID.
            calendar_id: Calendar ID.

        Returns:
            Event or None if not found.
        """
        service = self._get_service()
        try:
            result = service.events().get(calendarId=calendar_id, eventId=event_id).execute()
            return self._parse_event(result)
        except Exception:
            return None

    def create_event(
        self,
        summary: str,
        start: str | datetime,
        end: str | datetime | None = None,
        calendar_id: str = "primary",
        description: str | None = None,
        location: str | None = None,
        attendees: list[str] | None = None,
        all_day: bool = False,
    ) -> Event:
        """Create a new event.

        Args:
            summary: Event title.
            start: Start time as ISO string or datetime.
            end: End time (defaults to 1 hour after start).
            calendar_id: Calendar ID or "primary".
            description: Event description.
            location: Event location.
            attendees: List of attendee email addresses.
            all_day: Whether this is an all-day event.

        Returns:
            Created Event.
        """
        service = self._get_service()

        # Parse start time
        if isinstance(start, str):
            start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        else:
            start_dt = start

        # Default end to 1 hour after start
        if end is None:
            end_dt = start_dt + timedelta(hours=1)
        elif isinstance(end, str):
            end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
        else:
            end_dt = end

        # Build event body
        if all_day:
            body: dict[str, Any] = {
                "summary": summary,
                "start": {"date": start_dt.strftime("%Y-%m-%d")},
                "end": {"date": end_dt.strftime("%Y-%m-%d")},
            }
        else:
            body = {
                "summary": summary,
                "start": {"dateTime": start_dt.isoformat(), "timeZone": "UTC"},
                "end": {"dateTime": end_dt.isoformat(), "timeZone": "UTC"},
            }

        if description:
            body["description"] = description
        if location:
            body["location"] = location
        if attendees:
            body["attendees"] = [{"email": email} for email in attendees]

        result = service.events().insert(calendarId=calendar_id, body=body).execute()
        return self._parse_event(result)

    def update_event(
        self,
        event_id: str,
        calendar_id: str = "primary",
        summary: str | None = None,
        start: str | datetime | None = None,
        end: str | datetime | None = None,
        description: str | None = None,
        location: str | None = None,
    ) -> Event:
        """Update an existing event.

        Args:
            event_id: Event ID to update.
            calendar_id: Calendar ID.
            summary: New title (optional).
            start: New start time (optional).
            end: New end time (optional).
            description: New description (optional).
            location: New location (optional).

        Returns:
            Updated Event.
        """
        service = self._get_service()

        # Get current event
        current = service.events().get(calendarId=calendar_id, eventId=event_id).execute()

        # Update fields
        if summary is not None:
            current["summary"] = summary
        if description is not None:
            current["description"] = description
        if location is not None:
            current["location"] = location
        if start is not None:
            start_dt = (
                datetime.fromisoformat(start.replace("Z", "+00:00"))
                if isinstance(start, str)
                else start
            )
            current["start"] = {"dateTime": start_dt.isoformat(), "timeZone": "UTC"}
        if end is not None:
            end_dt = (
                datetime.fromisoformat(end.replace("Z", "+00:00")) if isinstance(end, str) else end
            )
            current["end"] = {"dateTime": end_dt.isoformat(), "timeZone": "UTC"}

        result = (
            service.events()
            .update(calendarId=calendar_id, eventId=event_id, body=current)
            .execute()
        )
        return self._parse_event(result)

    def delete_event(self, event_id: str, calendar_id: str = "primary") -> bool:
        """Delete an event.

        Args:
            event_id: Event ID to delete.
            calendar_id: Calendar ID.

        Returns:
            True if deleted successfully.
        """
        service = self._get_service()
        try:
            service.events().delete(calendarId=calendar_id, eventId=event_id).execute()
            return True
        except Exception:
            return False

    def _format_datetime(self, dt: datetime | str) -> str:
        """Format datetime for API."""
        if isinstance(dt, str):
            return dt
        return dt.isoformat() + "Z" if dt.tzinfo is None else dt.isoformat()

    def _parse_event(self, data: dict) -> Event:
        """Parse event from API response."""
        # Parse start time
        start = None
        start_data = data.get("start", {})
        if "dateTime" in start_data:
            with contextlib.suppress(Exception):
                start = datetime.fromisoformat(start_data["dateTime"].replace("Z", "+00:00"))
        elif "date" in start_data:
            with contextlib.suppress(Exception):
                start = datetime.fromisoformat(start_data["date"])

        # Parse end time
        end = None
        end_data = data.get("end", {})
        if "dateTime" in end_data:
            with contextlib.suppress(Exception):
                end = datetime.fromisoformat(end_data["dateTime"].replace("Z", "+00:00"))
        elif "date" in end_data:
            with contextlib.suppress(Exception):
                end = datetime.fromisoformat(end_data["date"])

        # Parse attendees
        attendees = None
        if data.get("attendees"):
            attendees = [a.get("email", "") for a in data["attendees"]]

        return Event(
            id=data["id"],
            summary=data.get("summary", ""),
            start=start,
            end=end,
            description=data.get("description"),
            location=data.get("location"),
            status=data.get("status", "confirmed"),
            html_link=data.get("htmlLink"),
            attendees=attendees,
        )
