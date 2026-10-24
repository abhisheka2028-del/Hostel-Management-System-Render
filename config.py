import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_DIR = os.environ.get('DATABASE_DIR', os.path.join(BASE_DIR, 'database'))
os.makedirs(DB_DIR, exist_ok=True)

class Config:
    # Determine if running in production (e.g. Render, production container)
    IS_PRODUCTION = os.environ.get('FLASK_ENV') == 'production' or os.environ.get('RENDER') == 'true'

    # Secret key handling: strictly require SECRET_KEY in production to prevent insecure deployments
    _env_secret = os.environ.get('SECRET_KEY')
    if IS_PRODUCTION and not _env_secret:
        raise ValueError(
            "FATAL: SECRET_KEY environment variable is required in production! "
            "Please configure a strong SECRET_KEY in your deployment environment variables."
        )
    SECRET_KEY = _env_secret or 'hostel-dev-secret-key-replace-in-production'

    # Database URL handling:
    # Render provides PostgreSQL connection strings starting with postgres:// or postgresql://.
    # When psycopg2-binary is installed, SQLAlchemy requires postgresql+psycopg2://
    # to avoid defaulting to psycopg (v3). Preserve any explicitly specified driver schemes.
    _raw_db_url = os.environ.get('DATABASE_URL')
    if _raw_db_url:
        if _raw_db_url.startswith('postgres://'):
            _raw_db_url = _raw_db_url.replace('postgres://', 'postgresql+psycopg2://', 1)
        elif _raw_db_url.startswith('postgresql://'):
            _raw_db_url = _raw_db_url.replace('postgresql://', 'postgresql+psycopg2://', 1)
        SQLALCHEMY_DATABASE_URI = _raw_db_url
    else:
        # Fallback to local SQLite for development and testing
        SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(DB_DIR, 'hostel.db')}"

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # Prevents unexpected token timeout during viva/demo
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    # Enable secure cookie in production over HTTPS unless explicitly overridden
    if IS_PRODUCTION:
        SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() in ('true', '1')
    else:
        SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() in ('true', '1')

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
