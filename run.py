"""
TrustVault Application Server Entrypoint
Usage:
    python run.py
"""
import os
from app import create_app
from config import Config
from app.services.db import init_db

app = create_app(Config)

if __name__ == "__main__":
    # Ensure database tables and indexes exist
    with app.app_context():
        init_db()

    port = int(os.environ.get("PORT", 5000))
    print("\n" + "=" * 60)
    print("  TrustVault Server Starting on http://127.0.0.1:" + str(port))
    print("  Open your web browser and navigate to: http://127.0.0.1:" + str(port))
    print("=" * 60 + "\n")
    app.run(host="127.0.0.1", port=port, debug=False)
