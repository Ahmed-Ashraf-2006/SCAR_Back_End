import os
from dotenv import load_dotenv

load_dotenv()

APP_NAME = os.getenv("APP_NAME", "SCAR Backend")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./scar.db")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
API_TOKEN = os.getenv("API_TOKEN", "")
