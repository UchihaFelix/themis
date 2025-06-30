import os
import secrets
import requests
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, redirect, url_for, session, render_template_string
from authlib.integrations.flask_client import OAuth
from functools import wraps
import json
import mysql.connector
from mysql.connector import Error

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "ehwodbwelenwkshyuxisid"

# Discord OAuth2 Configuration
DISCORD_CLIENT_ID = 138934705743266211
DISCORD_CLIENT_SECRET = "Bb9wrx5aQWGFL0sa020AtqKJu4uMa_Sr"
DISCORD_REDIRECT_URI = os.environ.get('DISCORD_REDIRECT_URI', 'https://fxs-host.xyz/auth/discord/callback')

# Database Configuration
DB_CONFIG = {
    'host': "uk02-sql.pebblehost.com",
    'user': "customer_981025_sql",
    'password': "NdSyBj2@++36J^tcPVUUor8I",
    'database': "customer_981025_sql",
    'port': 3306
}

BOT_OWNER_ID = 937721482170216468

# Initialize OAuth
oauth = OAuth(app)
discord = oauth.register(
    name='discord',
    client_id=DISCORD_CLIENT_ID,
    client_secret=DISCORD_CLIENT_SECRET,
    server_metadata_url='https://discord.com/.well-known/openid_configuration',
    client_kwargs={
        'scope': 'identify guilds'
    }
)

# Database Functions
def get_db_connection():
    """Create a database connection"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None

def is_staff(discord_id):
    """Check if a Discord ID is authorized staff"""
    try:
        # Convert to string for consistent comparison
        discord_id = str(discord_id)
        
        # Check if user is the bot owner
        if discord_id == str(BOT_OWNER_ID):
            return True
            
        connection = get_db_connection()
        if connection is None:
            return False
            
        cursor = connection.cursor()
        
        # Check if the discord_id exists in staff_members table
        query = "SELECT userid FROM staff_members WHERE userid = %s"
        cursor.execute(query, (discord_id,))
        result = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        return result is not None
        
    except Error as e:
        print(f"Database error in is_staff: {e}")
        return False
    except Exception as e:
        print(f"General error in is_staff: {e}")
        return False

def get_staff_info(discord_id):
    """Get staff information from database"""
    try:
        discord_id = str(discord_id)
        
        # If bot owner, return special info
        if discord_id == str(BOT_OWNER_ID):
            return {
                'discord_id': discord_id,
                'role': 'owner',
                'username': 'Bot Owner'
            }
            
        connection = get_db_connection()
        if connection is None:
            return None
            
        cursor = connection.cursor(dictionary=True)
        
        # Get staff member info (assuming there might be more columns in the future)
        query = "SELECT * FROM staff_members WHERE userid = %s"
        cursor.execute(query, (discord_id,))
        result = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        if result:
            return {
                'discord_id': discord_id,
                'role': result.get('role', 'staff'),  # Default to 'staff' if no role column
                'username': result.get('username', 'Staff Member')  # Default username
            }
        
        return None
        
    except Error as e:
        print(f"Database error in get_staff_info: {e}")
        return None
    except Exception as e:
        print(f"General error in get_staff_info: {e}")
        return None

# Utility Functions
def login_required(f):
    """Decorator to require login for protected routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def staff_required(f):
    """Decorator to require staff privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401
            
        discord_id = session['user'].get('id')
        if not is_staff(discord_id):
            return jsonify({'error': 'Insufficient privileges'}), 403
            
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    """Serve the main landing page"""
    try:
        with open('templates/index.html', 'r') as f:
            html_content = f.read()
        return html_content
    except FileNotFoundError:
        # Fallback HTML if file doesn't exist
        return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Themis - Admin System</title>
            <style>
                body { font-family: Arial, sans-serif; background: #0a0a0a; color: white; padding: 2rem; }
                .container { max-width: 800px; margin: 0 auto; text-align: center; }
                .btn { background: #5865f2; color: white; padding: 1rem 2rem; text-decoration: none; border-radius: 8px; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Themis Administration System</h1>
                <p>Advanced Discord & Roblox administration system</p>
                <a href="/auth/discord" class="btn">Login with Discord</a>
            </div>
        </body>
        </html>
        ''')

@app.route('/auth/discord')
def discord_login():
    """Initiate Discord OAuth2 login"""
    redirect_uri = url_for('discord_callback', _external=True)
    return discord.authorize_redirect(redirect_uri)

@app.route('/auth/discord/callback')
def discord_callback():
    """Handle Discord OAuth2 callback"""
    try:
        token = discord.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            return jsonify({'error': 'Failed to get user information'}), 400
            
        discord_id = user_info.get('sub')
        
        # Check if user is authorized staff
        if not is_staff(discord_id):
            return render_template_string('''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Access Denied</title>
                <style>
                    body { font-family: Arial, sans-serif; background: #0a0a0a; color: white; padding: 2rem; text-align: center; }
                    .error { background: rgba(220, 38, 38, 0.1); border: 1px solid rgba(220, 38, 38, 0.3); padding: 1rem; border-radius: 8px; }
                </style>
            </head>
            <body>
                <div class="error">
                    <h2>Access Denied</h2>
                    <p>You are not authorized to access this system.</p>
                    <p>Only fx-Studios staff members have access.</p>
                    <a href="/" style="color: #5865f2;">Return to Home</a>
                </div>
            </body>
            </html>
            '''), 403
            
        # Get additional user info from Discord API
        headers = {'Authorization': f'Bearer {token["access_token"]}'}
        user_response = requests.get('https://discord.com/api/users/@me', headers=headers)
        
        if user_response.status_code == 200:
            discord_user = user_response.json()
            staff_info = get_staff_info(discord_user['id'])
            
            # Store user session
            session['user'] = {
                'id': discord_user['id'],
                'username': discord_user['username'],
                'discriminator': discord_user.get('discriminator', '0'),
                'avatar': discord_user.get('avatar'),
                'avatar_url': f"https://cdn.discordapp.com/avatars/{discord_user['id']}/{discord_user['avatar']}.png" if discord_user.get('avatar') else None,
                'staff_info': staff_info or {}
            }
            
            return redirect(url_for('admin_panel'))
        else:
            return jsonify({'error': 'Failed to fetch user details'}), 400
            
    except Exception as e:
        return jsonify({'error': f'Authentication failed: {str(e)}'}), 400

@app.route('/logout')
def logout():
    """Logout user"""
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/api/me')
def get_current_user():
    """Get current user information"""
    if 'user' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
        
    return jsonify(session['user'])

@app.route('/admin')
@login_required
@staff_required
def admin_panel():
    """Admin panel dashboard - Stub for now"""
    user = session['user']
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Themis Admin Panel</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                background: #0a0a0a;
                color: #ffffff;
                line-height: 1.6;
            }
            .header {
                background: rgba(10, 10, 10, 0.9);
                border-bottom: 1px solid rgba(169, 119, 248, 0.3);
                padding: 1rem 2rem;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .logo { font-size: 1.5rem; font-weight: 600; color: #a977f8; }
            .user-info {
                display: flex;
                align-items: center;
                gap: 1rem;
                background: rgba(255, 255, 255, 0.05);
                padding: 0.5rem 1rem;
                border-radius: 8px;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            .user-avatar {
                width: 32px;
                height: 32px;
                border-radius: 50%;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                padding: 2rem;
                text-align: center;
            }
            .welcome-card {
                background: rgba(255, 255, 255, 0.03);
                border: 1px solid rgba(169, 119, 248, 0.2);
                border-radius: 12px;
                padding: 3rem;
                margin: 2rem 0;
            }
            .welcome-card h2 {
                color: #a977f8;
                font-size: 2rem;
                margin-bottom: 1rem;
            }
            .welcome-card p {
                color: #a0a0a0;
                font-size: 1.1rem;
                margin-bottom: 1.5rem;
            }
            .status-badge {
                background: rgba(34, 197, 94, 0.1);
                border: 1px solid rgba(34, 197, 94, 0.3);
                color: #22c55e;
                padding: 0.5rem 1rem;
                border-radius: 6px;
                font-weight: 500;
                display: inline-block;
            }
            .logout-btn {
                background: rgba(220, 38, 38, 0.1);
                color: #ffffff;
                border: 1px solid rgba(220, 38, 38, 0.3);
                padding: 0.5rem 1rem;
                border-radius: 6px;
                text-decoration: none;
                font-size: 0.9rem;
                transition: all 0.2s ease;
            }
            .logout-btn:hover {
                background: rgba(220, 38, 38, 0.2);
                border-color: rgba(220, 38, 38, 0.5);
            }
        </style>
    </head>
    <body>
        <header class="header">
            <div class="logo">Themis Admin Panel</div>
            <div class="user-info">
                {% if user.avatar_url %}
                <img src="{{ user.avatar_url }}" alt="Avatar" class="user-avatar">
                {% endif %}
                <div>
                    <div>{{ user.username }}#{{ user.discriminator }}</div>
                    <div style="font-size: 0.8rem; color: #a0a0a0;">{{ user.staff_info.role|title or 'Staff' }}</div>
                </div>
                <a href="/logout" class="logout-btn">Logout</a>
            </div>
        </header>
        
        <div class="container">
            <div class="welcome-card">
                <h2>Welcome to Themis Admin Panel</h2>
                <p>Authentication successful! You are now logged in as an authorized staff member.</p>
                <div class="status-badge">✓ Authentication Complete</div>
                
                <div style="margin-top: 2rem; padding: 1.5rem; background: rgba(255, 255, 255, 0.02); border-radius: 8px;">
                    <h3 style="color: #ffffff; margin-bottom: 1rem;">User Information</h3>
                    <p style="color: #a0a0a0; margin-bottom: 0.5rem;"><strong>Discord ID:</strong> {{ user.id }}</p>
                    <p style="color: #a0a0a0; margin-bottom: 0.5rem;"><strong>Username:</strong> {{ user.username }}#{{ user.discriminator }}</p>
                    <p style="color: #a0a0a0; margin-bottom: 0.5rem;"><strong>Role:</strong> {{ user.staff_info.role|title or 'Staff' }}</p>
                    <p style="color: #a0a0a0;"><strong>Access Level:</strong> Authorized Staff Member</p>
                </div>
                
                <div style="margin-top: 2rem; padding: 1rem; background: rgba(169, 119, 248, 0.05); border: 1px solid rgba(169, 119, 248, 0.2); border-radius: 8px;">
                    <p style="color: #c0c0c0; font-size: 0.9rem; margin: 0;">
                        <strong>Note:</strong> This is a stub page for the admin panel. Full dashboard functionality will be implemented in the next phase.
                    </p>
                </div>
            </div>
        </div>
    </body>
    </html>
    ''', user=user)

# Database initialization route (for testing)
@app.route('/init-db')
def init_database():
    """Initialize the staff_members table (for testing purposes)"""
    try:
        connection = get_db_connection()
        if connection is None:
            return jsonify({'error': 'Failed to connect to database'}), 500
            
        cursor = connection.cursor()
        
        # Create table if it doesn't exist
        create_table_query = """
        CREATE TABLE IF NOT EXISTS staff_members (
            id INT AUTO_INCREMENT PRIMARY KEY,
            userid VARCHAR(255) NOT NULL UNIQUE,
            username VARCHAR(255),
            role VARCHAR(100) DEFAULT 'staff',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
        
        cursor.execute(create_table_query)
        connection.commit()
        
        cursor.close()
        connection.close()
        
        return jsonify({'message': 'Database table initialized successfully'})
        
    except Error as e:
        return jsonify({'error': f'Database error: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'error': f'General error: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)