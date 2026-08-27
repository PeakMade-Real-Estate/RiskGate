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
    local_http = os.environ.get('RISKGATE_LOCAL_HTTP', '').lower() == 'true'
    app.run(
        debug=False,
        host='0.0.0.0', 
        port=int(os.environ.get('PORT', 5003)),
        use_reloader=False,
        **({} if local_http else {'ssl_context': ('cert.pem', 'key.pem')}),
    )
