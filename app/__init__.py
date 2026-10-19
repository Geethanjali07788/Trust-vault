from flask import Flask, jsonify
from config import Config
from app.services import db
from app.services.auth import get_current_user

def create_app(config_class=Config):
    """
    Application Factory for TrustVault.
    Initializes Flask, binds database hooks, and registers blueprints.
    """
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Database hooks (connection teardown)
    db.init_app(app)

    # Register Route Blueprints
    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp)

    # Context processor to make current_user available to all templates safely
    @app.context_processor
    def inject_user():
        return dict(current_user=get_current_user())

    # JSON error handlers for consistent security error responses
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"error": "Bad request", "details": str(error)}), 400

    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({"error": "Unauthorized. Please authenticate."}), 401

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({"error": "Forbidden. You do not have permission to access this resource."}), 403

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"error": "Resource not found."}), 404

    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({"error": "Internal server error occurred."}), 500

    return app
