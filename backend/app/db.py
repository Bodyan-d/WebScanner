from databases import Database
from .config import DATABASE_URL
database = Database(DATABASE_URL)
async def connect():
    await database.connect()
async def disconnect():
    await database.disconnect()
