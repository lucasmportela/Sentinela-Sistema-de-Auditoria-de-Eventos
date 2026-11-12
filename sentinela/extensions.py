import threading

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
WRITE_LOCK = threading.RLock()
