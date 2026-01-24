"""Google Tasks API client implementation."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any

from auth_utils.google import GoogleOAuth
from auth_utils.google.exceptions import AuthorizationRequired


@dataclass
class TaskList:
    """Represents a Google Tasks list."""

    id: str
    title: str
    updated: datetime | None = None


@dataclass
class Task:
    """Represents a Google Task."""

    id: str
    title: str
    status: str  # "needsAction" or "completed"
    notes: str | None = None
    due: date | None = None
    completed: datetime | None = None
    parent: str | None = None
    position: str | None = None

    @property
    def is_completed(self) -> bool:
        """Check if task is completed."""
        return self.status == "completed"


class TasksClient:
    """Google Tasks API client with OAuth authentication.

    Provides access to Google Tasks for managing task lists and tasks.

    Usage:
        client = TasksClient()

        # List task lists
        lists = client.list_task_lists()

        # List tasks
        tasks = client.list_tasks()

        # Create a task
        task = client.create_task(title="Do something")

        # Complete a task
        client.complete_task(task.id)

    Note:
        Requires OAuth authorization. Run `auth-utils tasks auth` to authorize.
    """

    def __init__(
        self,
        scopes: list[str] | None = None,
    ) -> None:
        """Initialize Tasks client.

        Args:
            scopes: OAuth scopes. Defaults to ["tasks"].
        """
        self._scopes = scopes or ["tasks"]
        self._auth: GoogleOAuth | None = None
        self._service: Any = None

    def _get_service(self) -> Any:
        """Get or create Tasks API service."""
        if self._service is None:
            self._auth = GoogleOAuth(scopes=self._scopes)
            if not self._auth.is_authorized():
                raise AuthorizationRequired(
                    self._auth.get_authorization_url(),
                    "Tasks API requires OAuth authorization. "
                    "Run 'auth-utils tasks auth' to authorize.",
                )
            self._service = self._auth.build_service("tasks", "v1")
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
    # Task Lists
    # =========================================================================

    def list_task_lists(self) -> list[TaskList]:
        """List all task lists.

        Returns:
            List of TaskList objects.
        """
        service = self._get_service()
        results = service.tasklists().list().execute()
        items = results.get("items", [])

        return [self._parse_task_list(item) for item in items]

    def get_task_list(self, tasklist_id: str = "@default") -> TaskList | None:
        """Get a specific task list.

        Args:
            tasklist_id: Task list ID or "@default" for primary list.

        Returns:
            TaskList or None if not found.
        """
        service = self._get_service()
        try:
            result = service.tasklists().get(tasklist=tasklist_id).execute()
            return self._parse_task_list(result)
        except Exception:
            return None

    def create_task_list(self, title: str) -> TaskList:
        """Create a new task list.

        Args:
            title: Name of the new task list.

        Returns:
            Created TaskList.
        """
        service = self._get_service()
        result = service.tasklists().insert(body={"title": title}).execute()
        return self._parse_task_list(result)

    def delete_task_list(self, tasklist_id: str) -> bool:
        """Delete a task list.

        Args:
            tasklist_id: Task list ID to delete.

        Returns:
            True if deleted successfully.
        """
        service = self._get_service()
        try:
            service.tasklists().delete(tasklist=tasklist_id).execute()
            return True
        except Exception:
            return False

    def _parse_task_list(self, data: dict) -> TaskList:
        """Parse task list from API response."""
        updated = None
        if data.get("updated"):
            with contextlib.suppress(Exception):
                updated = datetime.fromisoformat(data["updated"].replace("Z", "+00:00"))

        return TaskList(
            id=data["id"],
            title=data.get("title", ""),
            updated=updated,
        )

    # =========================================================================
    # Tasks
    # =========================================================================

    def list_tasks(
        self,
        tasklist_id: str = "@default",
        show_completed: bool = True,
        show_hidden: bool = False,
        max_results: int = 100,
    ) -> list[Task]:
        """List tasks in a task list.

        Args:
            tasklist_id: Task list ID or "@default" for primary list.
            show_completed: Include completed tasks.
            show_hidden: Include hidden tasks.
            max_results: Maximum number of tasks to return.

        Returns:
            List of Task objects.
        """
        service = self._get_service()
        results = (
            service.tasks()
            .list(
                tasklist=tasklist_id,
                showCompleted=show_completed,
                showHidden=show_hidden,
                maxResults=max_results,
            )
            .execute()
        )
        items = results.get("items", [])

        return [self._parse_task(item) for item in items]

    def get_task(self, task_id: str, tasklist_id: str = "@default") -> Task | None:
        """Get a specific task.

        Args:
            task_id: Task ID.
            tasklist_id: Task list ID.

        Returns:
            Task or None if not found.
        """
        service = self._get_service()
        try:
            result = service.tasks().get(tasklist=tasklist_id, task=task_id).execute()
            return self._parse_task(result)
        except Exception:
            return None

    def create_task(
        self,
        title: str,
        tasklist_id: str = "@default",
        notes: str | None = None,
        due: str | date | None = None,
        parent: str | None = None,
    ) -> Task:
        """Create a new task.

        Args:
            title: Task title.
            tasklist_id: Task list ID or "@default" for primary list.
            notes: Task notes/description.
            due: Due date as "YYYY-MM-DD" string or date object.
            parent: Parent task ID for subtasks.

        Returns:
            Created Task.
        """
        service = self._get_service()

        body: dict[str, Any] = {"title": title}
        if notes:
            body["notes"] = notes
        if due:
            due_str = due.isoformat() if isinstance(due, date) else due
            # Google Tasks API expects RFC 3339 format
            body["due"] = f"{due_str}T00:00:00.000Z"

        kwargs: dict[str, Any] = {"tasklist": tasklist_id, "body": body}
        if parent:
            kwargs["parent"] = parent

        result = service.tasks().insert(**kwargs).execute()
        return self._parse_task(result)

    def update_task(
        self,
        task_id: str,
        tasklist_id: str = "@default",
        title: str | None = None,
        notes: str | None = None,
        due: str | date | None = None,
        status: str | None = None,
    ) -> Task:
        """Update an existing task.

        Args:
            task_id: Task ID to update.
            tasklist_id: Task list ID.
            title: New title (optional).
            notes: New notes (optional).
            due: New due date (optional).
            status: New status ("needsAction" or "completed").

        Returns:
            Updated Task.
        """
        service = self._get_service()

        # Get current task
        current = service.tasks().get(tasklist=tasklist_id, task=task_id).execute()

        # Update fields
        if title is not None:
            current["title"] = title
        if notes is not None:
            current["notes"] = notes
        if due is not None:
            due_str = due.isoformat() if isinstance(due, date) else due
            current["due"] = f"{due_str}T00:00:00.000Z"
        if status is not None:
            current["status"] = status

        result = service.tasks().update(tasklist=tasklist_id, task=task_id, body=current).execute()
        return self._parse_task(result)

    def complete_task(self, task_id: str, tasklist_id: str = "@default") -> Task:
        """Mark a task as completed.

        Args:
            task_id: Task ID to complete.
            tasklist_id: Task list ID.

        Returns:
            Updated Task.
        """
        return self.update_task(task_id, tasklist_id, status="completed")

    def uncomplete_task(self, task_id: str, tasklist_id: str = "@default") -> Task:
        """Mark a task as not completed.

        Args:
            task_id: Task ID to uncomplete.
            tasklist_id: Task list ID.

        Returns:
            Updated Task.
        """
        return self.update_task(task_id, tasklist_id, status="needsAction")

    def delete_task(self, task_id: str, tasklist_id: str = "@default") -> bool:
        """Delete a task.

        Args:
            task_id: Task ID to delete.
            tasklist_id: Task list ID.

        Returns:
            True if deleted successfully.
        """
        service = self._get_service()
        try:
            service.tasks().delete(tasklist=tasklist_id, task=task_id).execute()
            return True
        except Exception:
            return False

    def clear_completed(self, tasklist_id: str = "@default") -> bool:
        """Clear all completed tasks from a list.

        Args:
            tasklist_id: Task list ID.

        Returns:
            True if cleared successfully.
        """
        service = self._get_service()
        try:
            service.tasks().clear(tasklist=tasklist_id).execute()
            return True
        except Exception:
            return False

    def _parse_task(self, data: dict) -> Task:
        """Parse task from API response."""
        due = None
        if data.get("due"):
            with contextlib.suppress(Exception):
                # Due date is in RFC 3339 format
                due_str = data["due"].split("T")[0]
                due = date.fromisoformat(due_str)

        completed = None
        if data.get("completed"):
            with contextlib.suppress(Exception):
                completed = datetime.fromisoformat(data["completed"].replace("Z", "+00:00"))

        return Task(
            id=data["id"],
            title=data.get("title", ""),
            status=data.get("status", "needsAction"),
            notes=data.get("notes"),
            due=due,
            completed=completed,
            parent=data.get("parent"),
            position=data.get("position"),
        )
