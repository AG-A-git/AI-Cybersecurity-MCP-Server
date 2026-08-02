from fastapi import FastAPI
from database import engine
from models import Base
from config import PROJECT_NAME
from config import PROJECT_VERSION
from config import PROJECT_DESCRIPTION
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=PROJECT_NAME,
    version=PROJECT_VERSION,
    description=PROJECT_DESCRIPTION
)
@app.get("/")
def home():
    return {
        "message": "Welcome to AI Cybersecurity MCP Server!"
    }