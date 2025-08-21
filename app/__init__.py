from flask import Flask
from config import Config
from app.extensions import db, migrate, jwt
from app.routes.admin_routes import admin_bp
from app.routes.auth_routes import auth_bp
from app.routes.annotator_routes import annotator_bp
from app.routes.reviewer_routes import reviewer_bp
from flask_mail import Mail


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Initialize extensions
    mail = Mail(app)
    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    # Register blueprints
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(admin_bp, url_prefix="/api/admin")
    app.register_blueprint(annotator_bp, url_prefix="/api/annotator")
    app.register_blueprint(reviewer_bp, url_prefix="/api/reviewer")

    return app
