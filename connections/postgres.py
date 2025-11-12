import os
import psycopg2 as pg
from dotenv import load_dotenv

load_dotenv()

connection = pg.connect(
    host=os.getenv("POSTGRES_HOST"),
    port=int(os.getenv("POSTGRES_PORT")),
    user=os.getenv("POSTGRES_USER"),
    password=os.getenv("POSTGRES_PASSWORD"),
    database=os.getenv("POSTGRES_DATABASE")
)
connection.autocommit=False

