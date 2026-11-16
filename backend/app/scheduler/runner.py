"""
APScheduler runner — wires the pure job functions in jobs.py to actual
cron-style triggers, started from main.py's FastAPI lifespan.

Design decision: BackgroundScheduler (thread-based), not a separate
worker process. For a single-instance deployment (this portfolio's
scale) that's the right tradeoff — zero extra infrastructure. The
moment this runs on more than one instance, these jobs would double-fire
unless coordinated (e.g. a Redis lock or moving to Celery Beat) — worth
naming explicitly, same as Module 4's background-task limitation.
"""
import logging

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from app.scheduler.jobs import nightly_enrichment_job, nightly_risk_recalculation_job, sla_breach_notification_job

logger = logging.getLogger("triageiq.scheduler")

_scheduler: BackgroundScheduler | None = None


def start_scheduler() -> BackgroundScheduler:
    global _scheduler
    if _scheduler is not None:
        return _scheduler

    scheduler = BackgroundScheduler(timezone="UTC")

    # Sequenced deliberately: enrichment first (so freshest CVSS/EPSS/KEV
    # data exists), THEN risk recalculation (so it uses that fresh data
    # the same night), THEN SLA checks (independent of the other two).
    scheduler.add_job(nightly_enrichment_job, CronTrigger(hour=2, minute=0), id="nightly_enrichment", replace_existing=True)
    scheduler.add_job(nightly_risk_recalculation_job, CronTrigger(hour=2, minute=30), id="nightly_risk_recalc", replace_existing=True)
    scheduler.add_job(sla_breach_notification_job, CronTrigger(hour=3, minute=0), id="sla_breach_check", replace_existing=True)

    scheduler.start()
    logger.info("Scheduler started: enrichment 02:00 UTC, risk recalc 02:30 UTC, SLA check 03:00 UTC")
    _scheduler = scheduler
    return scheduler


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
