import os
import pytest
from unittest.mock import patch
from app import create_app
from models import db

def test_production_secret_key_enforcement():
    """Verify that in production, a missing SECRET_KEY raises a clear ValueError."""
    with patch.dict(os.environ, {'FLASK_ENV': 'production'}, clear=True):
        with pytest.raises(ValueError) as excinfo:
            import importlib
            import config
            importlib.reload(config)
        assert "SECRET_KEY environment variable is required in production" in str(excinfo.value)

def test_postgres_url_normalization():
    """Verify that postgres:// URLs from Render are normalized to postgresql://."""
    mock_env = {
        'FLASK_ENV': 'development',
        'DATABASE_URL': 'postgres://render_user:secret_pass@dpg-host:5432/hostel_db',
        'SECRET_KEY': 'test-secret'
    }
    with patch.dict(os.environ, mock_env, clear=True):
        import importlib
        import config
        importlib.reload(config)
        assert config.Config.SQLALCHEMY_DATABASE_URI.startswith('postgresql://')
        assert 'postgres://' not in config.Config.SQLALCHEMY_DATABASE_URI

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
