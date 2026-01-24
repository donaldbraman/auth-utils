"""Google Tasks API client with OAuth authentication.

Manage Google Tasks programmatically with OAuth 2.0 authentication.

Usage:
    from auth_utils.tasks import TasksClient

    # Initialize (requires OAuth authorization)
    client = TasksClient()

    # List task lists
    lists = client.list_task_lists()

    # List tasks in default list
    tasks = client.list_tasks()

    # Create a task
    task = client.create_task(
        title="Review PR",
        notes="Check the auth-utils changes",
        due="2026-01-25",
    )

    # Complete a task
    client.complete_task(task["id"])

OAuth Setup:
    1. Download OAuth credentials from Google Cloud Console
    2. Import: auth-utils google import ~/Downloads/credentials.json
    3. Authorize: auth-utils tasks auth
"""

from __future__ import annotations

from auth_utils.tasks.client import Task, TaskList, TasksClient

__all__ = ["TasksClient", "Task", "TaskList"]
