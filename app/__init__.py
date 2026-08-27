"""
Application factory and initialization.
"""
import struct
import re

from flask import Flask
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import event
from config import Config

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()


def configure_database_auth(app):
    """Attach Microsoft Entra access tokens to SQL Server connections."""
    database_uri = app.config['SQLALCHEMY_DATABASE_URI']
    authentication = app.config.get('DB_AUTHENTICATION', '').lower()
    if not database_uri.startswith('mssql+pyodbc') or authentication not in {
        'managed_identity', 'entra', 'token', 'local', 'azure_cli'
    }:
        return

    from azure.identity import AzureCliCredential, DefaultAzureCredential

    if authentication in {'local', 'azure_cli'}:
        credential = AzureCliCredential()
    else:
        credential = DefaultAzureCredential()
    sql_access_token_attribute = 1256  # SQL_COPT_SS_ACCESS_TOKEN

    with app.app_context():
        engine = db.engine

    def add_access_token(dialect, connection_record, connection_args, connection_kwargs):
        access_token = credential.get_token(
            app.config['DB_ACCESS_TOKEN_SCOPE']
        ).token
        connection_args[0] = re.sub(
            r';?Trusted_Connection=Yes', '', connection_args[0], flags=re.IGNORECASE
        )
        token_bytes = access_token.encode('utf-16-le')
        token_struct = struct.pack('=i', len(token_bytes)) + token_bytes
        connection_kwargs['attrs_before'] = {
            sql_access_token_attribute: token_struct
        }

    event.listen(engine, 'do_connect', add_access_token)


def create_app(config_class=Config):
    """
    Application factory pattern.
    Creates and configures the Flask application instance.
    """
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    from app import models
    configure_database_auth(app)
    
    # Register context processor to make config available in templates
    @app.context_processor
    def inject_config():
        return {'config': app.config}
    
    # Register blueprints
    from app.routes import bp as main_bp
    app.register_blueprint(main_bp)
    
    # Log startup info
    with app.app_context():
        app.logger.info("SecurityScan starting (simplified version - no database)...")
        app.logger.info(f"Azure Client ID configured: {'Yes' if app.config.get('AZURE_CLIENT_ID') else 'No'}")
        app.logger.info(f"Azure Client Secret configured: {'Yes' if app.config.get('AZURE_CLIENT_SECRET') else 'No'}")
    
    return app

