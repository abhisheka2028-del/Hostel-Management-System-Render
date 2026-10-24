import os
import pytest
from unittest.mock import patch
from app import create_app
from models import db
from sqlalchemy import create_engine

def test_production_secret_key_enforcement():
    """Verify that in production, a missing SECRET_KEY raises a clear ValueError."""
    with patch.dict(os.environ, {'FLASK_ENV': 'production'}, clear=True):
        with pytest.raises(ValueError) as excinfo:
            import importlib
            import config
            importlib.reload(config)
        assert "SECRET_KEY environment variable is required in production" in str(excinfo.value)

def test_postgres_url_normalization_with_psycopg2():
    """Verify that postgres:// and postgresql:// URLs are normalized to postgresql+psycopg2://."""
    import importlib
    import config

    # 1. Test postgres:// scheme (Render legacy)
    with patch.dict(os.environ, {
        'DATABASE_URL': 'postgres://render_user:secret_pass@dpg-host:5432/hostel_db',
        'SECRET_KEY': 'test-secret'
    }, clear=True):
        importlib.reload(config)
        uri = config.Config.SQLALCHEMY_DATABASE_URI
        assert uri.startswith('postgresql+psycopg2://')
        assert 'postgres://' not in uri

    # 2. Test standard postgresql:// scheme without explicit driver
    with patch.dict(os.environ, {
        'DATABASE_URL': 'postgresql://render_user:secret_pass@dpg-host:5432/hostel_db',
        'SECRET_KEY': 'test-secret'
    }, clear=True):
        importlib.reload(config)
        uri = config.Config.SQLALCHEMY_DATABASE_URI
        assert uri.startswith('postgresql+psycopg2://')

    # 3. Test explicit driver scheme preservation
    with patch.dict(os.environ, {
        'DATABASE_URL': 'postgresql+pg8000://render_user:secret_pass@dpg-host:5432/hostel_db',
        'SECRET_KEY': 'test-secret'
    }, clear=True):
        importlib.reload(config)
        uri = config.Config.SQLALCHEMY_DATABASE_URI
        assert uri.startswith('postgresql+pg8000://')

    # 4. Verify SQLAlchemy create_engine selects psycopg2 driver without attempting psycopg v3
    with patch.dict(os.environ, {
        'DATABASE_URL': 'postgres://render_user:secret_pass@dpg-host:5432/hostel_db',
        'SECRET_KEY': 'test-secret'
    }, clear=True):
        importlib.reload(config)
        engine = create_engine(config.Config.SQLALCHEMY_DATABASE_URI)
        assert engine.dialect.driver == 'psycopg2'

def test_health_check_failure_sanitization(client, app):
    """Verify /health returns 503 and does NOT leak connection errors/credentials."""
    with app.app_context():
        with patch.object(db.session, 'execute', side_effect=Exception("FATAL: password authentication failed for user 'render_user'")):
            res = client.get('/health')
            assert res.status_code == 503
            data = res.get_json()
            assert data['status'] == 'unhealthy'
            assert data['database'] == 'unavailable'
            # Must NOT leak exception details or user credentials
            assert 'render_user' not in str(data)
            assert 'password' not in str(data)

def test_gunicorn_import_target():
    """Verify that gunicorn app:app target is importable."""
    import app
    assert hasattr(app, 'app')
    assert hasattr(app, 'create_app')
    assert app.app is not None
