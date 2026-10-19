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
    from app.routes.documents import doc_bp
    from app.routes.admin import admin_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(doc_bp)
    app.register_blueprint(admin_bp)

    from app.services.csrf import generate_csrf_token
    from flask import redirect, url_for

    # Root endpoint: redirects to vault or login
    @app.route("/")
    def root():
        user = get_current_user()
        if user:
            if user["role"] == "admin":
                return redirect(url_for("admin.dashboard_view"))
            return redirect(url_for("documents.list_documents"))
        return redirect(url_for("auth.login_view"))

    # Expose CSRF token endpoint
    @app.route("/auth/csrf-token", methods=["GET"])
    def get_csrf_endpoint():
        return jsonify({"csrf_token": generate_csrf_token()}), 200

    # Context processor to make current_user and csrf_token available to all templates safely
    @app.context_processor
    def inject_security_context():
        return dict(
            current_user=get_current_user(),
            csrf_token=generate_csrf_token()
        )

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
