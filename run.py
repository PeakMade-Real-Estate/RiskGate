"""
Application entry point.
Run this file to start the Flask development server.
"""
from app import create_app

# Create the Flask application instance
app = create_app()


# Shell context processor - simplified version
@app.shell_context_processor
def make_shell_context():
    """Add objects to the Flask shell context for easier testing."""
    return {}


if __name__ == '__main__':
    import os
    # Run the development server with HTTPS
    # debug=True enables auto-reload and detailed error pages
    # host='0.0.0.0' makes the server accessible from other devices on the network
    # ssl_context uses self-signed certificate for local HTTPS development
    # port is configurable via PORT environment variable (default: 5003)
    app.run(
        debug=True, 
        host='0.0.0.0', 
        port=int(os.environ.get('PORT', 5003)),
        ssl_context=('cert.pem', 'key.pem')
    )
