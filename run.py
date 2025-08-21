from app import create_app
from flask_cors import CORS

app = create_app()

# Configure CORS
CORS(
    app,
    resources={
        r"/api/*": {
            "origins": ["http://localhost:3000"],  # Your frontend URL
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
        }
    },
)

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
