from .admin import bp as admin_bp
from .auth import bp as auth_bp
from .events import bp as events_bp
from .web import bp as web_bp


def register_blueprints(app):
    app.register_blueprint(web_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(events_bp)
    app.register_blueprint(admin_bp)
