import asyncio

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient

from .config import settings
from .routes.feeds import router as feeds_router
from .tasks import periodic_feed_sync

app = FastAPI(title="Threat Intel Feed Integrator", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    app.state.mongo_client = AsyncIOMotorClient(settings.MONGODB_URI)
    app.state.db = app.state.mongo_client[settings.DB_NAME]
    app.state.background_task = asyncio.create_task(periodic_feed_sync(app.state.db))

@app.on_event("shutdown")
async def shutdown_event():
    task = getattr(app.state, "background_task", None)
    if task:
        task.cancel()
    app.state.mongo_client.close()

app.include_router(feeds_router)
