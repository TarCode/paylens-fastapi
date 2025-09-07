from fastapi import FastAPI
from controllers.auth import auth_router

app = FastAPI()
app.include_router(auth_router)