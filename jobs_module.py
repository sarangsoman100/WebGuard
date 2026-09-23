"""Lightweight persistent background scan worker for WebGuard.

Designed for the single-user MCA project deployment. It uses a small
in-process thread pool and SQLite job state instead of Redis/Celery.
"""

from concurrent.futures import ThreadPoolExecutor
import traceback

from database import create_scan_job, update_scan_job


_EXECUTOR = ThreadPoolExecutor(max_workers=2, thread_name_prefix="webguard-scan")


def submit_scan_job(target, mode, scan_callable):
    """Create a job record and submit the scan callable to the worker pool."""
    job_id = create_scan_job(target, mode)
    _EXECUTOR.submit(_run_job, job_id, target, mode, scan_callable)
    return job_id


def _run_job(job_id, target, mode, scan_callable):
    try:
        update_scan_job(
            job_id,
            status="running",
            progress=5,
            stage="Initializing",
            message="Starting scanner...",
            started=True,
        )

        def progress_callback(progress, stage, message):
            update_scan_job(
                job_id,
                status="running",
                progress=progress,
                stage=stage,
                message=message,
            )

        scan_id = scan_callable(
            target,
            mode,
            progress_callback,
        )

        update_scan_job(
            job_id,
            status="completed",
            progress=100,
            stage="Completed",
            message="Scan completed successfully.",
            scan_id=scan_id,
            completed=True,
        )

    except Exception as exc:
        error_message = str(exc) or exc.__class__.__name__
        traceback.print_exc()

        update_scan_job(
            job_id,
            status="failed",
            progress=100,
            stage="Failed",
            message="Scan failed.",
            error=error_message,
            completed=True,
        )
