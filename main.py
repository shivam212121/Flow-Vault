"""
Main FastAPI application for FlowVault MCP Server.
"""
import os
import logging
import uuid
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from tasks import celery_app, generate_screenshots_task # Import from tasks.py
from routers import collections_router, teams_router, admin_router, stripe_router # Import collections, teams, admin, and stripe routers

# Configure logging first
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="FlowVault MCP Server",
    description="Master Control Program for generating website flow screenshots.",
    version="0.1.0"
)

# Include routers
app.include_router(collections_router.router)
app.include_router(teams_router.router)
app.include_router(admin_router.router)
app.include_router(stripe_router.router)

class ScreenshotRequest(BaseModel):
    url: str
    # user_id: str # To associate the job with a user, will be fetched from auth context later

@app.post("/api/v1/generate-swipe", status_code=202)
async def request_swipe_generation(request: ScreenshotRequest, background_tasks: BackgroundTasks):
    """Endpoint to submit a URL for swipe file generation.

    This will create an MCP job and queue it for processing.
    """
    # 1. Create an mcp_job record in the database (status: 'queued', target_url: request.url, submitted_by_user_id: ...)
    # For now, let's generate a placeholder job ID
    mcp_job_id = str(uuid.uuid4())
    logger.info(f"[MCP Job {mcp_job_id}] Received request to generate swipe for URL: {request.url}")
    
    # In a real app, you'd save this job_id to your database (e.g., mcp_jobs table)
    # with status 'queued' before dispatching the Celery task.

    # Dispatch the task to Celery
    # Using .delay() is a shortcut for .send_task().
    task_info = generate_screenshots_task.delay(target_url=request.url, mcp_job_id=mcp_job_id)
    
    logger.info(f"[MCP Job {mcp_job_id}] Task enqueued with Celery ID: {task_info.id}")
    
    return {
        "message": "Screenshot generation request received and queued.",
        "mcp_job_id": mcp_job_id, # This is your internal job ID
        "celery_task_id": task_info.id # This is the Celery task ID for tracking
    }

@app.get("/api/v1/job-status/{mcp_job_id}")
async def get_job_status(mcp_job_id: str):
    """Endpoint to check the status of a screenshot generation job.

    In a real app, this would query the `mcp_jobs` table.
    For Celery task status, you'd use the celery_task_id.
    """
    # Placeholder: In a real app, query your database for the job status using mcp_job_id
    # For Celery task status itself (if you want to expose it):
    # task_result = celery_app.AsyncResult(celery_task_id_from_db)
    # return {"mcp_job_id": mcp_job_id, "status": task_result.status, "result": task_result.result}
    logger.info(f"Request for job status: {mcp_job_id}")
    # This is a mock response. You'd fetch actual status from your DB.
    return {"mcp_job_id": mcp_job_id, "status": "processing", "progress_percentage": 50, "message": "Fetching actual status from DB is not yet implemented."}


@app.get("/")
async def root():
    return {"message": "FlowVault MCP Server is running."}

# To run this app (from /home/ubuntu/flowvault_backend_fastapi):
# 1. Start Redis server if not already running (e.g., `redis-server --daemonize yes`)
# 2. Start Celery worker: `source venv/bin/activate && celery -A tasks.celery_app worker -l info --logfile=/home/ubuntu/celery_worker.log --pidfile=/home/ubuntu/celery_worker.pid --detach` (from the directory containing main.py and tasks.py)
# 3. Start FastAPI app: `source venv/bin/activate && uvicorn main:app --reload --port 8000`

