import os
import secrets
import requests # type: ignore
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, redirect, url_for, session, render_template_string # type: ignore
from authlib.integrations.flask_client import OAuth # type: ignore
from functools import wraps
import json
import mysql.connector # type: ignore
from mysql.connector import Error # type: ignore

# For R2 file upload and proxy
import boto3 # type: ignore
from werkzeug.utils import secure_filename # type: ignore
from dotenv import load_dotenv # type: ignore
from flask import Response # type: ignore

load_dotenv()

# Initialize Flask app
# Use a strong secret key from environment variable for production
SECRET_KEY = os.getenv('SECRET_KEY')
app = Flask(__name__)
app.secret_key = SECRET_KEY

# --- Rank Authorization Mapping and Decorators ---
# Rank order: lower number = higher privilege
RANK_LEVELS = {
    'Executive Director': 1,
    'Administration Director': 2,
    'Project Director': 3,
    'Community Director': 4,
    'Administrator': 5,
    'Junior Administrator': 6,
    'Senior Moderator': 7,
    'Moderator': 8,
    'Trial Moderator': 9,
    'Senior Developer': 10,
    'Developer': 11,
    'Junior Developer': 12,
    'Senior Coordinator': 13,
    'Coordinator': 14
}

# Rank color mapping for user info box
# Set the colours to match staff server role colours for consistency. (can't be bothered changing the colour names)
RANK_COLORS = {
    'Executive Director': '#3d0079',         # indigo purple
    'Administration Director': '#a11a1a',    # darker-red
    'Project Director': "#70006c",           # dark blue
    'Community Director': '#166534',         # dark green
    'Administrator': '#8b0000',              # darkish-red
    'Junior Administrator': '#ff0000',       # red
    'Senior Moderator': '#992d22',           # dark orange
    'Moderator': '#f59e42',                  # orange
    'Trial Moderator': '#c27c0e',            # yellow
    'Senior Developer': '#0004d3',           # dark blue
    'Developer': '#4750ff',                  # blue
    'Junior Developer': '#848cff',           # pastel blue
    'Senior Coordinator': '#006428',         # darkish green
    'Coordinator': "#2ecc71"                 # neon green
}

def require_rank(min_rank):
    """Decorator to require a minimum staff rank (inclusive)."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = session.get('user', {})
            user_rank = user.get('staff_info', {}).get('role', 'Staff')
            user_level = RANK_LEVELS.get(user_rank, 99)
            min_level = RANK_LEVELS.get(min_rank, 99)
            if user_level > min_level:
                return render_template_string('<div style="color:red;text-align:center;padding:2rem;">Insufficient rank to access this page.</div>'), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_ranks(allowed_ranks):
    """Decorator to require that the user's rank is in the allowed_ranks list."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = session.get('user', {})
            user_rank = user.get('staff_info', {}).get('role', 'Staff')
            if user_rank not in allowed_ranks:
                return render_template_string('<div style="color:red;text-align:center;padding:2rem;">You do not have permission to access this page.</div>'), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator



# R2 Storage Client
s3 = boto3.client(
    's3',
    endpoint_url=os.getenv('R2_ENDPOINT'),
    aws_access_key_id=os.getenv('R2_ACCESS_KEY'),
    aws_secret_access_key=os.getenv('R2_SECRET_KEY')
)


BUCKET_NAME = os.getenv('R2_BUCKET')

# Utility Functions
# Routes

# Evidence upload route
@app.route('/api/evidence/upload', methods=['POST'])
def upload_evidence():
    if 'file' not in request.files or 'case_id' not in request.form:
        return jsonify({'error': 'Missing file or case ID'}), 400

    file = request.files['file']
    case_id = request.form['case_id']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    filename = secure_filename(file.filename)
    object_name = f"{case_id}/{filename}"

    try:
        s3.upload_fileobj(file, BUCKET_NAME, object_name, ExtraArgs={'ACL': 'public-read'})
        # File URL through proxy
        file_url = f"https://fxs-host.xyz/files/{object_name}"

        # Save file_url to the evidence column in the discord table
        connection = get_db_connection()
        if connection is None:
            return jsonify({'error': 'DB connection error'}), 500
        cursor = connection.cursor(dictionary=True)
        # Fetch current evidence (if any)
        cursor.execute("SELECT evidence FROM discord WHERE reference_id = %s", (case_id,))
        row = cursor.fetchone()
        if row and row.get('evidence'):
            import ast
            try:
                evidence_list = ast.literal_eval(row['evidence']) if row['evidence'].strip().startswith('[') else [url.strip() for url in row['evidence'].split('\n') if url.strip()]
            except Exception:
                evidence_list = [url.strip() for url in row['evidence'].split('\n') if url.strip()]
        else:
            evidence_list = []
        evidence_list.append(file_url)
        # Save back as stringified list
        cursor.execute("UPDATE discord SET evidence = %s WHERE reference_id = %s", (str(evidence_list), case_id))
        connection.commit()
        cursor.close()
        connection.close()

        return jsonify({'message': 'Upload successful', 'url': file_url}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Proxy route for serving files from R2
@app.route('/files/<path:filename>')
def proxy_file(filename):
    # You may want to make these configurable
    r2_url = f"https://5d3202cb117dd821c36c9519a2188163.r2.cloudflarestorage.com/themis-storage/{filename}"
    r = requests.get(r2_url, stream=True)
    if r.status_code != 200:
        return 'File not found', 404
    return Response(r.iter_content(chunk_size=1024), content_type=r.headers.get('Content-Type'))

# Steve's one commit - cookies, just not as edible.
app.permanent_session_lifetime = timedelta(days=30) # CHANGE IF NEEDED
app.config['SESSION_COOKIE_NAME'] = 'fxs-sites'
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'     # Adjust as needed

# Discord OAuth2 Configuration
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv('DISCORD_REDIRECT_URI')

# Database Configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_DATABASE'),
    'port': int(os.getenv('DB_PORT', 3306))
}

BOT_OWNER_ID = os.getenv("BOT_OWNER_ID")

# Initialize OAuth
oauth = OAuth(app)
discord = oauth.register(
    name='discord',
    client_id=DISCORD_CLIENT_ID,
    client_secret=DISCORD_CLIENT_SECRET,
    access_token_url='https://discord.com/api/oauth2/token',
    authorize_url='https://discord.com/api/oauth2/authorize',
    api_base_url='https://discord.com/api/',
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
        query = "SELECT user_id FROM staff_members WHERE user_id = %s"
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
        connection = get_db_connection()
        if connection is None:
            return None
        cursor = connection.cursor(dictionary=True)
        
        # Get staff member info (assuming there might be more columns in the future)
        query = "SELECT * FROM staff_members WHERE user_id = %s"
        cursor.execute(query, (discord_id,))
        result = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        if result:
            return {
                'discord_id': discord_id,
                'role': result.get('rank', 'staff'),  # Default to 'staff' if no role column
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
    redirect_uri = url_for('discord_callback', _external=True, _scheme='https')
    return discord.authorize_redirect(redirect_uri)

@app.route('/auth/discord/callback')
def discord_callback():
    """Handle Discord OAuth2 callback"""
    try:
        token = discord.authorize_access_token()
        
        # Fetch user information from Discord
        resp = discord.get('users/@me', token=token)
        discord_user = resp.json()
        
        if not discord_user:
            return jsonify({'error': 'Failed to get user information'}), 400
            
        discord_id = discord_user.get('id')
        
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

            session.permanent = True  # Make session cookie persistent
            
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

from flask import redirect # type: ignore

@app.route('/admin')
@login_required
@staff_required
def admin_panel():
    return redirect('/admin/dashboard')

@app.route('/admin/meeting')
@login_required
@staff_required
def admin_meeting():
    html_meeting = r'''<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Senior Coordinator Onboarding - fx-Studios</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
    
            body {
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #1e293b 0%, #334155 50%, #475569 100%);
                color: #f8fafc;
                line-height: 1.6;
                overflow: hidden;
                height: 100vh;
            }
    
            .container {
                width: 100vw;
                height: 100vh;
                display: flex;
                flex-direction: column;
                position: relative;
            }
    
            .slide {
                background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
                color: #1e293b;
                height: 100vh;
                width: 100vw;
                padding: 60px 80px;
                display: none;
                position: absolute;
                top: 0;
                left: 0;
                animation: slideIn 0.5s ease-out;
                overflow-y: auto;
                border: none;
                box-shadow: none;
            }
    
            .slide.active {
                display: block;
            }
    
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateX(30px);
                }
                to {
                    opacity: 1;
                    transform: translateX(0);
                }
            }
    
            h1 {
                color: #0f172a;
                font-size: 3.5em;
                margin-bottom: 30px;
                text-align: center;
                font-weight: 700;
                border-bottom: 3px solid #3b82f6;
                padding-bottom: 20px;
                position: relative;
            }
    
            h1::after {
                content: '';
                position: absolute;
                bottom: -3px;
                left: 50%;
                transform: translateX(-50%);
                width: 120px;
                height: 3px;
                background: linear-gradient(90deg, #3b82f6, #1d4ed8);
            }
    
            h2 {
                color: #0f172a;
                font-size: 2.5em;
                margin-bottom: 30px;
                text-align: center;
                font-weight: 600;
            }
    
            h3 {
                color: #374151;
                font-size: 1.8em;
                margin-bottom: 25px;
                border-left: 4px solid #3b82f6;
                padding-left: 20px;
                font-weight: 600;
            }
    
            .logo {
                text-align: center;
                margin-bottom: 50px;
            }
    
            .logo-text {
                font-size: 4em;
                font-weight: 800;
                background: linear-gradient(135deg, #3b82f6, #1d4ed8);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                letter-spacing: -2px;
            }
    
            .orgchart {
                display: flex;
                flex-direction: column;
                align-items: center;
                gap: 40px;
                margin: 40px 0;
            }
    
            .level {
                display: flex;
                justify-content: center;
                gap: 60px;
                flex-wrap: wrap;
            }
    
            .position {
                background: linear-gradient(135deg, #ffffff, #f1f5f9);
                border: 2px solid #e2e8f0;
                border-radius: 8px;
                padding: 25px 35px;
                text-align: center;
                min-width: 220px;
                transition: all 0.3s ease;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
    
            .position:hover {
                transform: translateY(-5px);
                box-shadow: 0 8px 25px rgba(59, 130, 246, 0.2);
                border-color: #3b82f6;
            }
    
            .position.executive {
                background: linear-gradient(135deg, #3b82f6, #1d4ed8);
                color: white;
                border-color: #1e40af;
                font-size: 1.1em;
                font-weight: 600;
            }
    
            .position.director {
                background: linear-gradient(135deg, #06b6d4, #0891b2);
                color: white;
                border-color: #0e7490;
                font-weight: 600;
            }
    
            .position.senior {
                background: linear-gradient(135deg, #10b981, #059669);
                color: white;
                border-color: #047857;
                font-weight: 600;
            }
    
            .position.coordinator {
                background: linear-gradient(135deg, #f59e0b, #d97706);
                color: white;
                border-color: #b45309;
                font-weight: 600;
            }
    
            .team-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
                gap: 50px;
                margin: 40px 0;
            }
    
            .team-card {
                background: linear-gradient(135deg, #ffffff, #f8fafc);
                border: 2px solid #e2e8f0;
                border-radius: 8px;
                padding: 35px;
                transition: all 0.3s ease;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }
    
            .team-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 8px 25px rgba(59, 130, 246, 0.15);
                border-color: #3b82f6;
            }
    
            .team-title {
                color: #3b82f6;
                font-size: 1.6em;
                font-weight: 700;
                margin-bottom: 25px;
                text-align: center;
                padding-bottom: 15px;
                border-bottom: 2px solid #e2e8f0;
            }
    
            .member {
                background: linear-gradient(135deg, #ffffff, #f8fafc);
                border-radius: 6px;
                padding: 18px 25px;
                margin: 18px 0;
                border-left: 4px solid #3b82f6;
                transition: all 0.3s ease;
                box-shadow: 0 2px 4px rgba(0,0,0,0.05);
            }
    
            .member:hover {
                transform: translateX(8px);
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }
    
            .member.senior {
                border-left-color: #10b981;
                background: linear-gradient(135deg, #ecfdf5, #ffffff);
            }
    
            .member.coordinator {
                border-left-color: #f59e0b;
                background: linear-gradient(135deg, #fffbeb, #ffffff);
            }
    
            .key-points {
                background: linear-gradient(135deg, #fee2e2, #fecaca);
                border-radius: 8px;
                padding: 30px;
                margin: 30px 0;
                border-left: 4px solid #dc2626;
                position: relative;
            }
    
            .key-points::before {
                content: '⚠️';
                position: absolute;
                top: 20px;
                right: 25px;
                font-size: 1.5em;
            }
    
            .key-points h3 {
                color: #7f1d1d;
                border-left: none;
                padding-left: 0;
            }
    
            ul {
                padding-left: 30px;
                margin: 25px 0;
            }
    
            li {
                margin: 15px 0;
                padding-left: 10px;
                position: relative;
                font-size: 1.1em;
            }
    
            li::marker {
                color: #3b82f6;
            }
    
            .navigation {
                position: fixed;
                bottom: 40px;
                left: 50%;
                transform: translateX(-50%);
                display: flex;
                gap: 20px;
                z-index: 1000;
            }
    
            .nav-btn {
                background: linear-gradient(135deg, #3b82f6, #1d4ed8);
                color: white;
                border: none;
                padding: 18px 30px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 16px;
                font-weight: 600;
                transition: all 0.3s ease;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                min-width: 120px;
            }
    
            .nav-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(59, 130, 246, 0.3);
                background: linear-gradient(135deg, #2563eb, #1d4ed8);
            }
    
            .nav-btn:active {
                transform: translateY(0);
            }
    
            .nav-btn:disabled {
                opacity: 0.5;
                cursor: not-allowed;
                transform: none;
            }
    
            .slide-counter {
                position: fixed;
                top: 40px;
                right: 40px;
                background: rgba(255, 255, 255, 0.95);
                color: #1e293b;
                padding: 18px 25px;
                border-radius: 6px;
                font-weight: 700;
                z-index: 1000;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
                border: 2px solid #e2e8f0;
                font-size: 1.1em;
            }
    
            .highlight {
                background: linear-gradient(135deg, #fef3c7, #fde68a);
                padding: 25px;
                border-radius: 8px;
                margin: 25px 0;
                border-left: 4px solid #f59e0b;
                position: relative;
            }
    
            .highlight::before {
                content: '💡';
                position: absolute;
                top: 20px;
                right: 25px;
                font-size: 1.3em;
            }
    
            .connection-line {
                width: 4px;
                height: 30px;
                background: linear-gradient(180deg, #3b82f6, #1d4ed8);
                margin: 0 auto;
                border-radius: 2px;
            }
    
            .welcome-stats {
                background: linear-gradient(135deg, #ecfdf5, #d1fae5);
                border-radius: 8px;
                padding: 35px;
                margin: 40px 0;
                border-left: 4px solid #10b981;
                text-align: center;
            }
    
            .welcome-stats h3 {
                color: #064e3b;
                border-left: none;
                padding-left: 0;
                margin-bottom: 20px;
            }
    
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                gap: 25px;
                margin-top: 20px;
            }
    
            .stat-item {
                background: white;
                padding: 20px;
                border-radius: 6px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                border: 1px solid #e5e7eb;
            }
    
            .stat-number {
                font-size: 2em;
                font-weight: 800;
                color: #3b82f6;
            }
    
            .stat-label {
                font-size: 0.9em;
                color: #6b7280;
                margin-top: 8px;
                font-weight: 500;
            }
    
            /* Fullscreen optimizations */
            @media screen and (min-width: 1920px) {
                .slide {
                    padding: 100px 120px;
                }
                
                h1 {
                    font-size: 4em;
                }
                
                h2 {
                    font-size: 3em;
                }
                
                .logo-text {
                    font-size: 5em;
                }
            }
    
            @media (max-width: 1200px) {
                .team-grid {
                    grid-template-columns: 1fr;
                }
                
                .level {
                    flex-direction: column;
                    align-items: center;
                }
                
                .slide {
                    padding: 40px 60px;
                }
    
                .logo-text {
                    font-size: 3em;
                }
    
                h1 {
                    font-size: 2.5em;
                }
    
                h2 {
                    font-size: 2em;
                }
    
                .navigation {
                    bottom: 30px;
                }
    
                .slide-counter {
                    top: 30px;
                    right: 30px;
                    padding: 15px 20px;
                }
            }
    
            @media (max-width: 768px) {
                .slide {
                    padding: 30px 40px;
                }
                
                .stats-grid {
                    grid-template-columns: repeat(2, 1fr);
                }
                
                .team-grid {
                    grid-template-columns: 1fr;
                }
                
                .navigation {
                    bottom: 20px;
                }
                
                .slide-counter {
                    top: 20px;
                    right: 20px;
                    padding: 12px 18px;
                    font-size: 1em;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="slide-counter">
                <span id="current-slide">1</span> / <span id="total-slides">7</span>
            </div>
    
            <!-- Slide 1: Welcome -->
            <div class="slide active">
                <div class="logo">
                    <div class="logo-text">fx-Studios</div>
                </div>
                <h1>Senior Coordinator Onboarding</h1>
                <div style="text-align: center; margin: 50px 0;">
                    <h2 style="color: #3b82f6; margin-bottom: 25px;">Welcome to Leadership Excellence</h2>
                    <p style="font-size: 1.4em; color: #6b7280; max-width: 800px; margin: 0 auto; line-height: 1.8;">
                        This comprehensive presentation will guide you through your elevated responsibilities as Senior Coordinators 
                        and introduce you to the dynamic team structure within fx-Studios.
                    </p>
                </div>
                <div class="welcome-stats">
                    <h3>🎯 Your Leadership Journey Begins</h3>
                    <p style="margin-bottom: 25px; color: #064e3b;">You're joining an elite group of leaders driving fx-Studios forward</p>
                    <div class="stats-grid">
                        <div class="stat-item">
                            <div class="stat-number">2</div>
                            <div class="stat-label">Senior Positions</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number">5</div>
                            <div class="stat-label">Team Members</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number">3</div>
                            <div class="stat-label">Time Zones</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-number">24/7</div>
                            <div class="stat-label">Coverage</div>
                        </div>
                    </div>
                    <p style="margin-top: 20px; font-style: italic; color: #047857;">
                        <strong>Created by Leadership Team</strong> • Updated July 2025 • Maintained by Steve & fxllenfx
                    </p>
                </div>
            </div>
    
            <!-- Slide 2: Organizational Structure -->
            <div class="slide">
                <h2>fx-Studios Organizational Structure</h2>
                <div class="orgchart">
                    <div class="level">
                        <div class="position executive">
                            <strong>Executive Director</strong><br>
                            fxllenfx
                        </div>
                    </div>
                    <div class="connection-line"></div>
                    <div class="level">
                        <div class="position director">Administration Director</div>
                        <div class="position director">Project Director<br>Steve</div>
                        <div class="position director">Community Director<br>Feliks</div>
                    </div>
                    <div class="connection-line"></div>
                    <div class="level">
                        <div class="position">Studio Administration</div>
                        <div class="position">Moderation Division</div>
                        <div class="position">Development Team</div>
                        <div class="position" style="background: linear-gradient(135deg, #3b82f6, #1d4ed8); color: white; border: 2px solid #1e40af;">
                            <strong>Community Coordination</strong><br>
                            <em>Your Division</em>
                        </div>
                    </div>
                </div>
            </div>
    
            <!-- Slide 3: Community Coordination Teams -->
            <div class="slide">
                <h2>Community Coordination Team Structure</h2>
                <div class="team-grid">
                    <div class="team-card">
                        <div class="team-title">🛒 Procurement Team</div>
                        <div class="member senior">
                            <strong>Senior Coordinator</strong><br>
                            CodaCulture (UTC+1)
                        </div>
                        <div class="member coordinator">
                            <strong>Coordinator</strong><br>
                            Abdullah (UTC+2)
                        </div>
                        <div class="member coordinator">
                            <strong>Coordinator</strong><br>
                            Nick (UTC+0)
                        </div>
                        <div class="member coordinator">
                            <strong>Trainee Moderator</strong><br>
                            Person (UTC+2)
                        </div>
                    </div>
                    <div class="team-card">
                        <div class="team-title">🎯 Campaigns & Ideas Team</div>
                        <div class="member senior">
                            <strong>Senior Coordinator</strong><br>
                            Bl1tzer1n (UTC+2)
                        </div>
                        <div class="member coordinator">
                            <strong>Coordinator</strong><br>
                            2hn (EST)
                        </div>
                        <div class="member coordinator">
                            <strong>Coordinator</strong><br>
                            K3bhi (UTC-4)
                        </div>
                    </div>
                </div>
            </div>
    
            <!-- Slide 4: Senior Coordinator Hierarchy -->
            <div class="slide">
                <h2>Leadership Hierarchy & Training Responsibilities</h2>
                <div class="key-points">
                    <h3>🎖️ Critical Leadership Structure</h3>
                    <ul>
                        <li><strong>Senior Coordinators</strong> are responsible for training and developing Coordinators</li>
                        <li><strong>Coordinators report directly to Senior Coordinators</strong> within their teams</li>
                        <li>Senior Coordinators must mentor, guide, and evaluate Coordinator performance</li>
                        <li>All escalations from Coordinators go through Senior Coordinators first</li>
                    </ul>
                </div>
                <div class="orgchart" style="margin-top: 50px;">
                    <div class="level">
                        <div class="position director">Community Director<br>Feliks</div>
                    </div>
                    <div class="connection-line"></div>
                    <div class="level">
                        <div class="position senior">Senior Coordinator<br>CodaCulture</div>
                        <div class="position senior">Senior Coordinator<br>Bl1tzer1n</div>
                    </div>
                    <div class="connection-line"></div>
                    <div class="level">
                        <div class="position coordinator">Coordinator<br>Abdullah</div>
                        <div class="position coordinator">Coordinator<br>Nick</div>
                        <div class="position coordinator">Tr. M Person</div>
                        <div class="position coordinator">Coordinator<br>2hn</div>
                        <div class="position coordinator">Coordinator<br>K3bhi</div>
                    </div>
                </div>
            </div>
    
            <!-- Slide 5: Key Responsibilities -->
            <div class="slide">
                <h2>Senior Coordinator Responsibilities</h2>
                <h3>📋 Core Duties (Section 4.2)</h3>
                <ul>
                    <li><strong>Community Engagement:</strong> Serve as public representatives of fx-Studios</li>
                    <li><strong>Platform Management:</strong> Engage community across all official platforms</li>
                    <li><strong>Brand Representation:</strong> Maintain studio's image and voice</li>
                    <li><strong>Feedback Collection:</strong> Gather and relay community feedback to leadership</li>
                    <li><strong>Recruitment Leadership:</strong> Lead hiring campaigns with Board collaboration</li>
                    <li><strong>Staff Monitoring:</strong> Monitor staff levels and recruitment needs</li>
                </ul>
                
                <div class="highlight">
                    <h3>👥 Team Leadership Responsibilities</h3>
                    <ul>
                        <li>Train and mentor Coordinators in your team</li>
                        <li>Assign tasks and monitor progress</li>
                        <li>Conduct regular performance evaluations</li>
                        <li>Handle escalations from your team members</li>
                        <li>Ensure professional development of subordinates</li>
                    </ul>
                </div>
            </div>
    
            <!-- Slide 6: Communication & Protocols -->
            <div class="slide">
                <h2>Communication Protocols & Standards</h2>
                <h3>📞 Reporting Structure</h3>
                <ul>
                    <li><strong>Direct Reports:</strong> Report regularly to Community Director (Feliks)</li>
                    <li><strong>Cross-Division:</strong> Coordinate with Studio Administration for new hire onboarding</li>
                    <li><strong>Board Updates:</strong> Provide hiring updates to Board of Directors</li>
                </ul>
    
                <h3>💬 Professional Standards (Section 2.5)</h3>
                <div class="key-points">
                    <h3>⚠️ Mandatory Behaviors</h3>
                    <ul>
                        <li>Maintain highest level of professionalism in all communications</li>
                        <li>Refrain from provocative, escalatory, or sarcastic responses</li>
                        <li>Maintain posture of de-escalation, neutrality, and professionalism</li>
                        <li>Preserve anonymity in official communications unless cleared by Senior Moderator+</li>
                        <li>Never click unsolicited external links - request embedded previews</li>
                    </ul>
                </div>
    
                <h3>📊 Documentation Requirements</h3>
                <ul>
                    <li>All significant activities must be recorded in <strong>Themis</strong></li>
                    <li>Log all interventions and team interactions</li>
                    <li>Maintain confidentiality of all staff communications</li>
                </ul>
            </div>
    
            <!-- Slide 7: Next Steps -->
            <div class="slide">
                <h2>Next Steps & Final Reminders</h2>
                <h3>🚀 Immediate Actions</h3>
                <ul>
                    <li><strong>Meet Your Team:</strong> Schedule initial meetings with your Coordinators</li>
                    <li><strong>Review Themis:</strong> Familiarize yourself with the logging system</li>
                    <li><strong>Establish Routines:</strong> Set up regular check-ins with your team</li>
                    <li><strong>Coordinate with Leadership:</strong> Align with Community Director on priorities</li>
                </ul>
    
                <div class="key-points">
                    <h3>🎯 Success Metrics</h3>
                    <ul>
                        <li>Team productivity and professional development</li>
                        <li>Quality of community engagement and feedback</li>
                        <li>Successful recruitment and onboarding</li>
                        <li>Adherence to fx-Studios standards and protocols</li>
                    </ul>
                </div>
    
                <div class="highlight">
                    <h3>📋 Key Contacts</h3>
                    <ul>
                        <li><strong>Community Director:</strong> Feliks (feliks0187)</li>
                        <li><strong>Executive Director:</strong> fxllenfx</li>
                        <li><strong>Project Director:</strong> Steve (Stevenson)</li>
                    </ul>
                </div>
    
                <div style="text-align: center; margin-top: 60px;">
                    <h2 style="color: #3b82f6; margin-bottom: 20px;">Welcome to Leadership at fx-Studios!</h2>
                    <p style="font-size: 1.4em; color: #6b7280; line-height: 1.8;">
                        Your role as Senior Coordinator is crucial to our success. Lead with excellence, inspire your team, and drive our community forward.
                    </p>
                </div>
            </div>
        </div>
    
        <div class="navigation">
            <button class="nav-btn" id="prevBtn" onclick="changeSlide(-1)">Previous</button>
            <button class="nav-btn" id="nextBtn" onclick="changeSlide(1)">Next</button>
        </div>
    
        <script>
            let currentSlide = 1;
            const totalSlides = 7;
    
            function showSlide(n) {
                const slides = document.querySelectorAll('.slide');
                if (n > totalSlides) currentSlide = 1;
                if (n < 1) currentSlide = totalSlides;
                
                slides.forEach(slide => slide.classList.remove('active'));
                slides[currentSlide - 1].classList.add('active');
                
                document.getElementById('current-slide').textContent = currentSlide;
                document.getElementById('total-slides').textContent = totalSlides;
                
                // Update navigation buttons
                document.getElementById('prevBtn').disabled = currentSlide === 1;
                document.getElementById('nextBtn').disabled = currentSlide === totalSlides;
            }
    
            function changeSlide(n) {
                currentSlide += n;
                showSlide(currentSlide);
            }
    
            // Keyboard navigation
            document.addEventListener('keydown', function(e) {
                if (e.key === 'ArrowLeft') changeSlide(-1);
                if (e.key === 'ArrowRight') changeSlide(1);
            });
    
            // Initialize
            showSlide(currentSlide);
        </script>
    </body>
    </html>'''
    return render_template_string(html_meeting)

@app.route('/admin/dashboard')
@login_required
@staff_required
def admin_dashboard():
    user = session['user']
    staff_rank = user.get('staff_info', {}).get('role', 'Staff')
    rank_color = RANK_COLORS.get(staff_rank, '#a977f8')
    
    # Modern admin dashboard with enhanced design
    html = rf'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Themis Admin Dashboard</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <style>
            :root {{
                --primary-color: #a977f8;
                --primary-rgb: 169, 119, 248;
                --background-dark: #0a0a0a;
                --surface-dark: #141418;
                --surface-light: rgba(255, 255, 255, 0.05);
                --border-color: rgba(169, 119, 248, 0.3);
                --text-primary: #ffffff;
                --text-secondary: #b7b7c9;
                --text-muted: #8b8b99;
                --rank-color: {rank_color};
                --shadow-primary: 0 4px 32px rgba(169, 119, 248, 0.15);
                --shadow-elevated: 0 8px 48px rgba(169, 119, 248, 0.2);
                --backdrop-blur: blur(16px);
            }}
            
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                background: var(--background-dark);
                color: var(--text-primary);
                line-height: 1.6;
                overflow-x: hidden;
                min-height: 100vh;
            }}

            #fluid-canvas {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                z-index: -2;
                opacity: 0.6;
                pointer-events: none;
            }}
            
            .background-pattern {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                pointer-events: none;
                z-index: -1;
                background: 
                    radial-gradient(circle at 20% 30%, rgba(var(--primary-rgb), 0.04) 0%, transparent 50%),
                    radial-gradient(circle at 80% 70%, rgba(var(--primary-rgb), 0.03) 0%, transparent 50%),
                    radial-gradient(circle at 40% 80%, rgba(var(--primary-rgb), 0.02) 0%, transparent 50%);
            }}
            
            .sidebar {{
                position: fixed;
                top: 0;
                left: 0;
                width: 280px;
                height: 100vh;
                background: rgba(20, 20, 24, 0.95);
                backdrop-filter: var(--backdrop-blur);
                border-right: 1px solid var(--border-color);
                display: flex;
                flex-direction: column;
                z-index: 1000;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }}
            
            .sidebar::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: linear-gradient(180deg, 
                    rgba(var(--primary-rgb), 0.02) 0%, 
                    transparent 100%);
                pointer-events: none;
            }}
            
            .logo {{
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 32px 24px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.08);
                position: relative;
            }}
            
            .logo img {{
                width: 42px;
                height: 42px;
                border-radius: 12px;
                filter: drop-shadow(0 4px 16px rgba(var(--primary-rgb), 0.3));
            }}
            
            .logo-text {{
                font-size: 1.75rem;
                font-weight: 800;
                background: linear-gradient(135deg, var(--text-primary) 0%, var(--primary-color) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                letter-spacing: -0.02em;
            }}
            
            .nav-links {{
                flex: 1;
                padding: 24px 16px;
                display: flex;
                flex-direction: column;
                gap: 8px;
            }}
            
            .nav-item {{
                position: relative;
                text-decoration: none;
                color: var(--text-secondary);
                padding: 16px 20px;
                border-radius: 12px;
                font-weight: 500;
                font-size: 0.95rem;
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
                display: flex;
                align-items: center;
                gap: 12px;
                border: 1px solid transparent;
            }}
            
            .nav-item::before {{
                content: '';
                position: absolute;
                left: 0;
                top: 50%;
                transform: translateY(-50%);
                width: 3px;
                height: 0;
                background: var(--primary-color);
                border-radius: 0 2px 2px 0;
                transition: height 0.2s ease;
            }}
            
            .nav-item:hover {{
                background: rgba(var(--primary-rgb), 0.08);
                color: var(--text-primary);
                transform: translateX(4px);
                border-color: rgba(var(--primary-rgb), 0.2);
            }}
            
            .nav-item.active {{
                background: rgba(var(--primary-rgb), 0.12);
                color: var(--primary-color);
                border-color: rgba(var(--primary-rgb), 0.3);
            }}
            
            .nav-item.active::before {{
                height: 24px;
            }}
            
            .nav-icon {{
                width: 20px;
                height: 20px;
                opacity: 0.7;
                transition: opacity 0.2s ease;
            }}
            
            .nav-item:hover .nav-icon,
            .nav-item.active .nav-icon {{
                opacity: 1;
            }}
            
            .main-content {{
                margin-left: 280px;
                padding: 40px;
                min-height: 100vh;
                position: relative;
            }}
            
            .user-info {{
                position: fixed;
                top: 24px;
                right: 40px;
                z-index: 1100;
                display: flex;
                align-items: center;
                gap: 16px;
                background: rgba(255, 255, 255, 0.08);
                backdrop-filter: var(--backdrop-blur);
                border: 1px solid rgba(var(--primary-rgb), 0.3);
                border-radius: 16px;
                padding: 12px 16px;
                box-shadow: var(--shadow-primary);
            }}
            
            .user-avatar {{
                width: 44px;
                height: 44px;
                border-radius: 12px;
                background: var(--primary-color);
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: 700;
                font-size: 1.1rem;
                overflow: hidden;
                border: 2px solid rgba(var(--primary-rgb), 0.3);
            }}
            
            .user-avatar img {{
                width: 100%;
                height: 100%;
                object-fit: cover;
            }}
            
            .user-details {{
                display: flex;
                flex-direction: column;
                gap: 2px;
            }}
            
            .user-name {{
                font-weight: 600;
                font-size: 0.95rem;
                color: var(--rank-color);
            }}
            
            .user-rank {{
                font-size: 0.8rem;
                color: var(--text-muted);
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            
            .logout-btn {{
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(var(--primary-rgb), 0.3);
                color: var(--text-primary);
                padding: 8px 16px;
                border-radius: 8px;
                font-size: 0.85rem;
                font-weight: 500;
                text-decoration: none;
                transition: all 0.2s ease;
                cursor: pointer;
            }}
            
            .logout-btn:hover {{
                background: var(--primary-color);
                color: white;
                transform: translateY(-1px);
                box-shadow: var(--shadow-primary);
            }}
            
            .dashboard-header {{
                margin-bottom: 48px;
                padding-top: 20px;
            }}
            
            .dashboard-title {{
                font-size: clamp(2.5rem, 5vw, 4rem);
                font-weight: 800;
                line-height: 1.1;
                margin-bottom: 16px;
                background: linear-gradient(135deg, var(--text-primary) 0%, var(--text-secondary) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                letter-spacing: -0.02em;
            }}
            
            .username-highlight {{
                background: linear-gradient(135deg, var(--primary-color) 0%, #d946ef 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }}
            
            .dashboard-subtitle {{
                font-size: 1.1rem;
                color: var(--text-secondary);
                max-width: 600px;
                line-height: 1.6;
                font-weight: 400;
            }}
            
            .quick-actions {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
                gap: 24px;
                margin-top: 40px;
            }}
            
            .action-card {{
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid rgba(var(--primary-rgb), 0.2);
                border-radius: 20px;
                padding: 32px;
                text-decoration: none;
                color: inherit;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                position: relative;
                overflow: hidden;
                backdrop-filter: var(--backdrop-blur);
            }}
            
            .action-card::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: linear-gradient(135deg, 
                    rgba(var(--primary-rgb), 0.05) 0%, 
                    transparent 100%);
                opacity: 0;
                transition: opacity 0.3s ease;
            }}
            
            .action-card:hover {{
                transform: translateY(-8px);
                border-color: rgba(var(--primary-rgb), 0.4);
                box-shadow: var(--shadow-elevated);
            }}
            
            .action-card:hover::before {{
                opacity: 1;
            }}
            
            .card-icon {{
                width: 48px;
                height: 48px;
                border-radius: 12px;
                background: linear-gradient(135deg, var(--primary-color) 0%, #d946ef 100%);
                display: flex;
                align-items: center;
                justify-content: center;
                margin-bottom: 20px;
                box-shadow: var(--shadow-primary);
            }}
            
            .card-icon img {{
                width: 28px;
                height: 28px;
                filter: brightness(0) invert(1);
            }}
            
            .card-title {{
                font-size: 1.25rem;
                font-weight: 700;
                margin-bottom: 8px;
                color: var(--text-primary);
            }}
            
            .card-description {{
                color: var(--text-secondary);
                font-size: 0.95rem;
                line-height: 1.5;
            }}
            
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 40px;
            }}
            
            .stat-card {{
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid rgba(var(--primary-rgb), 0.2);
                border-radius: 16px;
                padding: 24px;
                text-align: center;
                backdrop-filter: var(--backdrop-blur);
            }}
            
            .stat-value {{
                font-size: 2rem;
                font-weight: 800;
                color: var(--primary-color);
                margin-bottom: 8px;
            }}
            
            .stat-label {{
                color: var(--text-secondary);
                font-size: 0.9rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            
            @media (max-width: 1024px) {{
                .sidebar {{
                    width: 240px;
                }}
                
                .main-content {{
                    margin-left: 240px;
                    padding: 32px;
                }}
                
                .user-info {{
                    right: 32px;
                }}
            }}
            
            @media (max-width: 768px) {{
                .sidebar {{
                    transform: translateX(-100%);
                    width: 100%;
                    height: auto;
                    position: fixed;
                    bottom: 0;
                    top: auto;
                    flex-direction: row;
                    padding: 16px;
                    border-right: none;
                    border-top: 1px solid var(--border-color);
                    z-index: 2000;
                }}
                
                .logo {{
                    display: none;
                }}
                
                .nav-links {{
                    flex-direction: row;
                    padding: 0;
                    width: 100%;
                    justify-content: space-around;
                }}
                
                .nav-item {{
                    flex: 1;
                    justify-content: center;
                    padding: 12px 8px;
                    font-size: 0.8rem;
                }}
                
                .main-content {{
                    margin-left: 0;
                    padding: 20px 16px 100px 16px;
                }}
                
                .user-info {{
                    position: static;
                    margin: 0 0 16px 0;
                    top: auto;
                    right: auto;
                    left: auto;
                    width: 100%;
                    justify-content: flex-end;
                    border-radius: 12px;
                    padding: 8px 12px;
                    gap: 12px;
                    box-sizing: border-box;
                }}
                
                .user-avatar {{
                    width: 36px;
                    height: 36px;
                }}
                
                .dashboard-title {{
                    font-size: 2rem;
                }}
                
                .quick-actions {{
                    grid-template-columns: 1fr;
                }}
                
                .stats-grid {{
                    grid-template-columns: repeat(2, 1fr);
                }}
            }}
            
            @media (max-width: 480px) {{
                .main-content {{
                    padding: 16px 12px 100px 12px;
                }}
                
                .user-info {{
                    position: static;
                    margin: 0 0 12px 0;
                    width: 100%;
                    padding: 6px 8px;
                    flex-direction: column;
                    align-items: flex-end;
                    gap: 6px;
                }}
                
                .user-details {{
                    display: none;
                }}
                
                .action-card {{
                    padding: 24px;
                }}
                
                .stats-grid {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <canvas id="fluid-canvas"></canvas>
        
        <div class="sidebar">
            <div class="logo">
                <img src="https://cdn.discordapp.com/attachments/1359093144376840212/1391111028552765550/image.png?ex=686caeda&is=686b5d5a&hm=2f7a401945da09ff951d426aaf651ade57dad6b6a52c567713aacf466c214a85&" alt="Themis">
                <div class="logo-text">Themis</div>
            </div>
            <nav class="nav-links">
                <a href="/admin/dashboard" class="nav-item active">
                    <svg class="nav-icon" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"/>
                    </svg>
                    Dashboard
                </a>
                <a href="/admin/cases" class="nav-item">
                    <svg class="nav-icon" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h8a2 2 0 012 2v12a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm3 1h6v4H7V5zm8 8v2h1v-2h-1zm-1-1h1v-2h-1v2zm1-4h-1V6h1v2zM7 8h6v4H7V8z" clip-rule="evenodd"/>
                    </svg>
                    Cases
                </a>
                <a href="/" class="nav-item">
                    <svg class="nav-icon" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M10.707 2.293a1 1 0 00-1.414 0l-7 7a1 1 0 001.414 1.414L4 10.414V17a1 1 0 001 1h2a1 1 0 001-1v-2a1 1 0 011-1h2a1 1 0 011 1v2a1 1 0 001 1h2a1 1 0 001-1v-6.586l.293.293a1 1 0 001.414-1.414l-7-7z"/>
                    </svg>
                    Home
                </a>
            </nav>
        </div>
        
        <div class="user-info">
            <div class="user-avatar">
                {f'<img src="{user.get('avatar_url')}" alt="Avatar">' if user.get('avatar_url') else user.get('username', 'U')[0].upper()}
            </div>
            <div class="user-details">
                <div class="user-name">{user.get('username', 'User')}</div>
                <div class="user-rank">{staff_rank}</div>
            </div>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>
        
        <main class="main-content">
            <div class="dashboard-header">
                <h1 class="dashboard-title">
                    Welcome back, <span class="username-highlight">{user.get('username', 'User')}</span>
                </h1>
                <p class="dashboard-subtitle">
                    Access advanced moderation tools, review cases, and manage your Themis administration system with precision and efficiency.
                </p>
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">24</div>
                    <div class="stat-label">Active Cases</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">142</div>
                    <div class="stat-label">Total Actions</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">98.2%</div>
                    <div class="stat-label">Success Rate</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">5</div>
                    <div class="stat-label">Pending Reviews</div>
                </div>
            </div>
            
            <div class="quick-actions">
                <a href="/admin/cases" class="action-card">
                    <div class="card-icon">
                        <img src="https://cdn.discordapp.com/attachments/1346136182379122798/1391910863832875018/discotools-xyz-icon_4.png?ex=686d9d82&is=686c4c02&hm=9c63e6b8dd489969258c4e84681ea446be3efe786f2fa434c02fd48c064d4948&" alt="Cases">
                    </div>
                    <h3 class="card-title">Manage Cases</h3>
                    <p class="card-description">Review, investigate, and resolve moderation cases across all connected platforms.</p>
                </a>
                
                <a href="/admin/users" class="action-card">
                    <div class="card-icon">
                        <svg width="28" height="28" fill="currentColor" viewBox="0 0 20 20">
                            <path d="M9 6a3 3 0 11-6 0 3 3 0 016 0zM17 6a3 3 0 11-6 0 3 3 0 016 0zM12.93 17c.046-.327.07-.66.07-1a6.97 6.97 0 00-1.5-4.33A5 5 0 0119 16v1h-6.07zM6 11a5 5 0 015 5v1H1v-1a5 5 0 015-5z"/>
                        </svg>
                    </div>
                    <h3 class="card-title">User Management</h3>
                    <p class="card-description">SOON: Manage user accounts, permissions, and staff roles.</p>
                </a>
                
                <a href="/admin/analytics" class="action-card">
                    <div class="card-icon">
                        <svg width="28" height="28" fill="currentColor" viewBox="0 0 20 20">
                            <path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7zM14 4a1 1 0 011-1h2a1 1 0 011 1v12a1 1 0 01-1 1h-2a1 1 0 01-1-1V4z"/>
                        </svg>
                    </div>
                    <h3 class="card-title">Analytics</h3>
                    <p class="card-description">SOON: View detailed analytics, trends, and insights about moderation activities and system performance.</p>
                </a>
            </div>
        </main>
        <script>
            class FluidSimulation {{
                constructor() {{
                    this.canvas = document.getElementById('fluid-canvas');
                    this.gl = this.canvas.getContext('webgl') || this.canvas.getContext('experimental-webgl');
                    
                    if (!this.gl) {{
                        console.warn('WebGL not supported');
                        // Fallback: create a simple CSS animation instead
                        this.createCSSFallback();
                        return;
                    }}
                    
                    console.log('WebGL initialized successfully');
                    
                    this.mouse = {{ x: 0, y: 0, prevX: 0, prevY: 0 }};
                    this.isMouseDown = false;
                    this.time = 0;
                    
                    this.init();
                    this.setupEventListeners();
                    this.animate();
                }}
                
                createCSSFallback() {{
                    this.canvas.style.background = `
                        radial-gradient(circle at 20% 30%, rgba(169, 119, 248, 0.1) 0%, transparent 50%),
                        radial-gradient(circle at 80% 70%, rgba(169, 119, 248, 0.08) 0%, transparent 50%),
                        radial-gradient(circle at 40% 80%, rgba(169, 119, 248, 0.06) 0%, transparent 50%)
                    `;
                    this.canvas.style.animation = 'pulse 4s ease-in-out infinite alternate';
                    
                    // Add CSS animation
                    const style = document.createElement('style');
                    style.textContent = `
                        @keyframes pulse {{
                            0% {{ opacity: 0.3; }}
                            100% {{ opacity: 0.6; }}
                        }}
                    `;
                    document.head.appendChild(style);
                }}
                
                init() {{
                    this.resizeCanvas();
                    
                    // Vertex shader
                    const vertexShader = this.createShader(this.gl.VERTEX_SHADER, `
                        attribute vec2 a_position;
                        void main() {{
                            gl_Position = vec4(a_position, 0.0, 1.0);
                        }}
                    `);
                    
                    // Fragment shader with subtle fluid effect
                    const fragmentShader = this.createShader(this.gl.FRAGMENT_SHADER, `
                        precision mediump float;
                        uniform vec2 u_resolution;
                        uniform float u_time;
                        uniform vec2 u_mouse;
                        uniform float u_mouseIntensity;
                        
                        float noise(vec2 p) {{
                            return fract(sin(dot(p, vec2(12.9898, 78.233))) * 43758.5453);
                        }}
                        
                        float smoothNoise(vec2 p) {{
                            vec2 i = floor(p);
                            vec2 f = fract(p);
                            f = f * f * (3.0 - 2.0 * f);
                            
                            float a = noise(i);
                            float b = noise(i + vec2(1.0, 0.0));
                            float c = noise(i + vec2(0.0, 1.0));
                            float d = noise(i + vec2(1.0, 1.0));
                            
                            return mix(mix(a, b, f.x), mix(c, d, f.x), f.y);
                        }}
                        
                        float fbm(vec2 p) {{
                            float value = 0.0;
                            float amplitude = 0.5;
                            float frequency = 1.0;
                            
                            for(int i = 0; i < 4; i++) {{
                                value += amplitude * smoothNoise(p * frequency);
                                amplitude *= 0.5;
                                frequency *= 2.0;
                            }}
                            
                            return value;
                        }}
                        
                        void main() {{
                            vec2 uv = gl_FragCoord.xy / u_resolution.xy;
                            
                            // Slow-moving fluid distortion
                            vec2 p = uv * 2.0 + u_time * 0.2;
                            float flow = fbm(p + vec2(sin(u_time * 0.5), cos(u_time * 0.3)));
                            
                            // Mouse interaction
                            vec2 mouseUV = u_mouse / u_resolution.xy;
                            float mouseDist = length(uv - mouseUV);
                            float mouseEffect = smoothstep(0.4, 0.0, mouseDist) * u_mouseIntensity;
                            
                            // Base animated pattern
                            float wave = sin(uv.x * 10.0 + u_time) * sin(uv.y * 10.0 + u_time * 0.8) * 0.1;
                            
                            // Combine effects
                            float intensity = (flow * 0.3 + mouseEffect * 0.7 + wave) * 0.5;
                            
                            // Purple tint matching the theme
                            vec3 color = vec3(0.66, 0.47, 0.97) * (intensity + 0.1);
                            
                            gl_FragColor = vec4(color, (intensity + 0.05) * 0.8);
                        }}
                    `);
                    
                    // Create program
                    this.program = this.createProgram(vertexShader, fragmentShader);
                    
                    // Get uniform locations
                    this.uniforms = {{
                        resolution: this.gl.getUniformLocation(this.program, 'u_resolution'),
                        time: this.gl.getUniformLocation(this.program, 'u_time'),
                        mouse: this.gl.getUniformLocation(this.program, 'u_mouse'),
                        mouseIntensity: this.gl.getUniformLocation(this.program, 'u_mouseIntensity')
                    }};
                    
                    // Create buffer
                    const positions = new Float32Array([
                        -1, -1,
                        1, -1,
                        -1,  1,
                        1,  1
                    ]);
                    
                    this.positionBuffer = this.gl.createBuffer();
                    this.gl.bindBuffer(this.gl.ARRAY_BUFFER, this.positionBuffer);
                    this.gl.bufferData(this.gl.ARRAY_BUFFER, positions, this.gl.STATIC_DRAW);
                    
                    // Setup attributes
                    const positionAttribute = this.gl.getAttribLocation(this.program, 'a_position');
                    this.gl.enableVertexAttribArray(positionAttribute);
                    this.gl.vertexAttribPointer(positionAttribute, 2, this.gl.FLOAT, false, 0, 0);
                    
                    // WebGL settings
                    this.gl.enable(this.gl.BLEND);
                    this.gl.blendFunc(this.gl.SRC_ALPHA, this.gl.ONE_MINUS_SRC_ALPHA);
                }}
                
                createShader(type, source) {{
                    const shader = this.gl.createShader(type);
                    this.gl.shaderSource(shader, source);
                    this.gl.compileShader(shader);
                    
                    if (!this.gl.getShaderParameter(shader, this.gl.COMPILE_STATUS)) {{
                        console.error('Shader compilation error:', this.gl.getShaderInfoLog(shader));
                        this.gl.deleteShader(shader);
                        return null;
                    }}
                    
                    return shader;
                }}
                
                createProgram(vertexShader, fragmentShader) {{
                    const program = this.gl.createProgram();
                    this.gl.attachShader(program, vertexShader);
                    this.gl.attachShader(program, fragmentShader);
                    this.gl.linkProgram(program);
                    
                    if (!this.gl.getProgramParameter(program, this.gl.LINK_STATUS)) {{
                        console.error('Program linking error:', this.gl.getProgramInfoLog(program));
                        this.gl.deleteProgram(program);
                        return null;
                    }}
                    
                    return program;
                }}
                
                setupEventListeners() {{
                    window.addEventListener('resize', () => this.resizeCanvas());
                    
                    // Mouse events
                    window.addEventListener('mousemove', (e) => {{
                        this.mouse.prevX = this.mouse.x;
                        this.mouse.prevY = this.mouse.y;
                        this.mouse.x = e.clientX;
                        this.mouse.y = this.canvas.height - e.clientY;
                    }});
                    
                    window.addEventListener('mousedown', () => {{
                        this.isMouseDown = true;
                    }});
                    
                    window.addEventListener('mouseup', () => {{
                        this.isMouseDown = false;
                    }});
                    
                    // Touch events for mobile
                    window.addEventListener('touchmove', (e) => {{
                        e.preventDefault();
                        const touch = e.touches[0];
                        this.mouse.prevX = this.mouse.x;
                        this.mouse.prevY = this.mouse.y;
                        this.mouse.x = touch.clientX;
                        this.mouse.y = this.canvas.height - touch.clientY;
                    }});
                    
                    window.addEventListener('touchstart', () => {{
                        this.isMouseDown = true;
                    }});
                    
                    window.addEventListener('touchend', () => {{
                        this.isMouseDown = false;
                    }});
                }}
                
                resizeCanvas() {{
                    this.canvas.width = window.innerWidth;
                    this.canvas.height = window.innerHeight;
                    this.gl.viewport(0, 0, this.canvas.width, this.canvas.height);
                }}
                
                render() {{
                    this.gl.useProgram(this.program);
                    
                    // Update uniforms
                    this.gl.uniform2f(this.uniforms.resolution, this.canvas.width, this.canvas.height);
                    this.gl.uniform1f(this.uniforms.time, this.time);
                    this.gl.uniform2f(this.uniforms.mouse, this.mouse.x, this.mouse.y);
                    
                    // Mouse intensity based on movement and click
                    const mouseVelocity = Math.sqrt(
                        (this.mouse.x - this.mouse.prevX) ** 2 + 
                        (this.mouse.y - this.mouse.prevY) ** 2
                    );
                    const intensity = Math.min(mouseVelocity * 0.01 + (this.isMouseDown ? 0.5 : 0), 1.0);
                    this.gl.uniform1f(this.uniforms.mouseIntensity, intensity);
                    
                    // Draw
                    this.gl.drawArrays(this.gl.TRIANGLE_STRIP, 0, 4);
                }}
                
                animate() {{
                    this.time += 0.016;
                    this.render();
                    requestAnimationFrame(() => this.animate());
                }}
            }}
            
            // Initialize when page loads
            window.addEventListener('load', () => {{
                new FluidSimulation();
            }});
        </script>
    </body>
    </html>
    '''
    return render_template_string(html)

@app.route('/admin/cases')
@login_required
@require_ranks([
    'Executive Director',
    'Administration Director',
    'Project Director',
    'Community Director',
    'Administrator',
    'Junior Administrator',
    'Senior Moderator',
    'Moderator',
    'Trial Moderator',
])
def admin_cases():
    user = session['user']
    staff_rank = user.get('staff_info', {}).get('role', 'Staff')
    rank_color = RANK_COLORS.get(staff_rank, '#a977f8')
    
    # Fetch cases from the discord table ONLY (no join with users), filter out those without punishment_type
    import ast
    connection = get_db_connection()
    cases = []
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            query = '''
                SELECT reference_id, user_id, punishment_type, reason, appealed, length, evidence
                FROM discord
                WHERE punishment_type IS NOT NULL AND punishment_type != ''
                ORDER BY reference_id DESC
                LIMIT 100
            '''
            cursor.execute(query)
            for row in cursor.fetchall():
                # Parse evidence as list
                evidence_list = []
                if row.get('evidence'):
                    try:
                        if row['evidence'].strip().startswith('['):
                            evidence_list = ast.literal_eval(row['evidence'])
                        else:
                            evidence_list = [url.strip() for url in row['evidence'].split('\n') if url.strip()]
                    except Exception:
                        evidence_list = [url.strip() for url in row['evidence'].split('\n') if url.strip()]
                cases.append({
                    'id': row['reference_id'],
                    'user_id': row['user_id'],
                    'type': row['punishment_type'],
                    'reason': row['reason'],
                    'status': 'Appealed' if row['appealed'] == 1 else 'Active',
                    'length': row['length'] if row['length'] else 'N/A',
                    'evidence_list': evidence_list
                })
            cursor.close()
        except Exception as e:
            print('Error in /admin/cases:', e)
            cases = []
        finally:
            connection.close()
    def render_evidence_block(evidence_list):
        if not evidence_list:
            return '<span style="color:#888">No evidence</span>'
        html = ''
        for url in evidence_list:
            ext = url.split('.')[-1].lower().split('?')[0]
            if ext in ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp']:
                html += f'<img src="{url}" alt="evidence" style="max-width:90px;max-height:70px;margin:2px;border-radius:6px;border:1px solid #333;vertical-align:middle;">'
            elif ext in ['mp4', 'webm', 'ogg', 'mov', 'm4v']:
                html += f'<video src="{url}" controls style="max-width:90px;max-height:70px;margin:2px;border-radius:6px;vertical-align:middle;background:#111;"></video>'
            else:
                html += f'<a href="{url}" target="_blank" style="color:#a977f8;">File</a> '
        return html
    
    # Color coding for punishment types
    PUNISHMENT_COLORS = {
        'ban': '#ef4444',
        'kick': '#f59e42',
        'mute': '#fde047',
        'warn': '#22d3ee',
        'default': '#a0a0a0'
    }
    
    # Expose punishment color mapping to JS for modal
    punishment_colors_js = json.dumps(PUNISHMENT_COLORS)

    # Helper for inline rendering
    def get_type_color(ptype):
        return PUNISHMENT_COLORS.get(ptype.lower(), PUNISHMENT_COLORS['default']) if ptype else PUNISHMENT_COLORS['default']

    # The following HTML contains inline JS that references 'document', which is not a Python variable.
    # noqa: E501, F405, F821  # For linters: ignore long lines and undefined names in inline JS
    # Use a raw string to avoid SyntaxWarning for backslashes in JS/HTML
    html = rf'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Themis Admin Cases</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <style>
            :root {{
                --primary-color: #a977f8;
                --primary-rgb: 169, 119, 248;
                --background-dark: #0a0a0a;
                --surface-dark: #141418;
                --surface-light: rgba(255, 255, 255, 0.05);
                --border-color: rgba(169, 119, 248, 0.3);
                --text-primary: #ffffff;
                --text-secondary: #b7b7c9;
                --text-muted: #8b8b99;
                --rank-color: {rank_color};
                --shadow-primary: 0 4px 32px rgba(169, 119, 248, 0.15);
                --shadow-elevated: 0 8px 48px rgba(169, 119, 248, 0.2);
                --backdrop-blur: blur(16px);
            }}
            
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            
            body {{
                font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                background: var(--background-dark);
                color: var(--text-primary);
                line-height: 1.6;
                overflow-x: hidden;
                min-height: 100vh;
            }}
            
            /* Animated background */
            .background-pattern {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                pointer-events: none;
                z-index: -1;
                background: 
                    radial-gradient(circle at 20% 30%, rgba(var(--primary-rgb), 0.08) 0%, transparent 50%),
                    radial-gradient(circle at 80% 70%, rgba(var(--primary-rgb), 0.06) 0%, transparent 50%),
                    radial-gradient(circle at 40% 80%, rgba(var(--primary-rgb), 0.04) 0%, transparent 50%);
            }}
            
            /* Sidebar */
            .sidebar {{
                position: fixed;
                top: 0;
                left: 0;
                width: 280px;
                height: 100vh;
                background: rgba(20, 20, 24, 0.95);
                backdrop-filter: var(--backdrop-blur);
                border-right: 1px solid var(--border-color);
                display: flex;
                flex-direction: column;
                z-index: 1000;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }}
            
            .sidebar::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: linear-gradient(180deg, 
                    rgba(var(--primary-rgb), 0.02) 0%, 
                    transparent 100%);
                pointer-events: none;
            }}
            
            .logo {{
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 32px 24px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.08);
                position: relative;
            }}
            
            .logo img {{
                width: 42px;
                height: 42px;
                border-radius: 12px;
                filter: drop-shadow(0 4px 16px rgba(var(--primary-rgb), 0.3));
            }}
            
            .logo-text {{
                font-size: 1.75rem;
                font-weight: 800;
                background: linear-gradient(135deg, var(--text-primary) 0%, var(--primary-color) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                letter-spacing: -0.02em;
            }}
            
            .nav-links {{
                flex: 1;
                padding: 24px 16px;
                display: flex;
                flex-direction: column;
                gap: 8px;
            }}
            
            .nav-item {{
                position: relative;
                text-decoration: none;
                color: var(--text-secondary);
                padding: 16px 20px;
                border-radius: 12px;
                font-weight: 500;
                font-size: 0.95rem;
                transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
                display: flex;
                align-items: center;
                gap: 12px;
                border: 1px solid transparent;
            }}
            
            .nav-item::before {{
                content: '';
                position: absolute;
                left: 0;
                top: 50%;
                transform: translateY(-50%);
                width: 3px;
                height: 0;
                background: var(--primary-color);
                border-radius: 0 2px 2px 0;
                transition: height 0.2s ease;
            }}
            
            .nav-item:hover {{
                background: rgba(var(--primary-rgb), 0.08);
                color: var(--text-primary);
                transform: translateX(4px);
                border-color: rgba(var(--primary-rgb), 0.2);
            }}
            
            .nav-item.active {{
                background: rgba(var(--primary-rgb), 0.12);
                color: var(--primary-color);
                border-color: rgba(var(--primary-rgb), 0.3);
            }}
            
            .nav-item.active::before {{
                height: 24px;
            }}
            
            .nav-icon {{
                width: 20px;
                height: 20px;
                opacity: 0.7;
                transition: opacity 0.2s ease;
            }}
            
            .nav-item:hover .nav-icon,
            .nav-item.active .nav-icon {{
                opacity: 1;
            }}
            
            /* Main content */
            .main-content {{
                margin-left: 280px;
                padding: 40px;
                min-height: 100vh;
                position: relative;
            }}
            
            /* User info */
            .user-info {{
                position: fixed;
                top: 24px;
                right: 40px;
                z-index: 1100;
                display: flex;
                align-items: center;
                gap: 16px;
                background: rgba(255, 255, 255, 0.08);
                backdrop-filter: var(--backdrop-blur);
                border: 1px solid rgba(var(--primary-rgb), 0.3);
                border-radius: 16px;
                padding: 12px 16px;
                box-shadow: var(--shadow-primary);
            }}
            
            .user-avatar {{
                width: 44px;
                height: 44px;
                border-radius: 12px;
                background: var(--primary-color);
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: 700;
                font-size: 1.1rem;
                overflow: hidden;
                border: 2px solid rgba(var(--primary-rgb), 0.3);
            }}
            
            .user-avatar img {{
                width: 100%;
                height: 100%;
                object-fit: cover;
            }}
            
            .user-details {{
                display: flex;
                flex-direction: column;
                gap: 2px;
            }}
            
            .user-name {{
                font-weight: 600;
                font-size: 0.95rem;
                color: var(--text-primary);
            }}
            
            .user-rank {{
                font-size: 0.8rem;
                color: var(--rank-color);
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            
            .logout-btn {{
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(var(--primary-rgb), 0.3);
                color: var(--text-primary);
                padding: 8px 16px;
                border-radius: 8px;
                font-size: 0.85rem;
                font-weight: 500;
                text-decoration: none;
                transition: all 0.2s ease;
                cursor: pointer;
            }}
            
            .logout-btn:hover {{
                background: var(--primary-color);
                color: white;
                transform: translateY(-1px);
                box-shadow: var(--shadow-primary);
            }}
            
            /* Cases content */
            .cases-header {{
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 40px;
                padding-top: 20px;
                gap: 24px;
                flex-wrap: wrap;
            }}
            
            .cases-title {{
                font-size: clamp(2.5rem, 5vw, 3.5rem);
                font-weight: 800;
                line-height: 1.1;
                background: linear-gradient(135deg, var(--text-primary) 0%, var(--text-secondary) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                letter-spacing: -0.02em;
            }}
            
            .create-log-btn {{
                background: linear-gradient(135deg, var(--primary-color) 0%, #d946ef 100%);
                color: white;
                border: none;
                border-radius: 12px;
                padding: 14px 24px;
                font-size: 0.95rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s ease;
                box-shadow: var(--shadow-primary);
                display: flex;
                align-items: center;
                gap: 8px;
            }}
            
            .create-log-btn:hover {{
                transform: translateY(-2px);
                box-shadow: var(--shadow-elevated);
            }}
            
            .create-log-btn:active {{
                transform: translateY(0);
            }}
            
            /* Cases table */
            .cases-container {{
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid rgba(var(--primary-rgb), 0.2);
                border-radius: 20px;
                overflow: hidden;
                backdrop-filter: var(--backdrop-blur);
                box-shadow: var(--shadow-primary);
                position: relative;
            }}
            
            .cases-container::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: linear-gradient(135deg, 
                    rgba(var(--primary-rgb), 0.02) 0%, 
                    transparent 100%);
                pointer-events: none;
            }}
            
            .cases-table {{
                width: 100%;
                border-collapse: collapse;
                position: relative;
                z-index: 1;
            }}
            
            .cases-table th {{
                background: rgba(var(--primary-rgb), 0.08);
                color: var(--text-primary);
                padding: 20px 24px;
                text-align: left;
                font-weight: 600;
                font-size: 0.9rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                border-bottom: 1px solid rgba(var(--primary-rgb), 0.15);
            }}
            
            .cases-table td {{
                padding: 20px 24px;
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
                color: var(--text-secondary);
                font-size: 0.95rem;
                vertical-align: middle;
            }}
            
            .cases-table tr:hover {{
                background: rgba(var(--primary-rgb), 0.04);
            }}
            
            .cases-table tr:last-child td {{
                border-bottom: none;
            }}
            
            .type-badge {{
                display: inline-flex;
                align-items: center;
                padding: 6px 14px;
                border-radius: 20px;
                font-weight: 600;
                font-size: 0.8rem;
                color: #000;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            }}
            
            .status-badge {{
                display: inline-flex;
                align-items: center;
                padding: 6px 14px;
                border-radius: 20px;
                font-weight: 600;
                font-size: 0.8rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            
            .status-active {{
                background: rgba(34, 197, 94, 0.2);
                color: #22c55e;
                border: 1px solid rgba(34, 197, 94, 0.3);
            }}
            
            .status-appealed {{
                background: rgba(249, 115, 22, 0.2);
                color: #f97316;
                border: 1px solid rgba(249, 115, 22, 0.3);
            }}
            
            .action-btn {{
                background: rgba(var(--primary-rgb), 0.1);
                color: var(--primary-color);
                border: 1px solid rgba(var(--primary-rgb), 0.3);
                padding: 8px 16px;
                border-radius: 8px;
                font-size: 0.85rem;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.2s ease;
                text-decoration: none;
                display: inline-flex;
                align-items: center;
                gap: 6px;
            }}
            
            .action-btn:hover {{
                background: var(--primary-color);
                color: white;
                transform: translateY(-1px);
                box-shadow: var(--shadow-primary);
            }}
            
            .case-id {{
                font-family: 'Monaco', 'Menlo', monospace;
                font-weight: 600;
                color: var(--text-primary);
            }}
            
            .user-id {{
                font-family: 'Monaco', 'Menlo', monospace;
                color: var(--text-muted);
            }}
            
            .case-reason {{
                max-width: 200px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }}
            
            /* Modal styles */
            .modal {{
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100vw;
                height: 100vh;
                background: rgba(0, 0, 0, 0.8);
                backdrop-filter: blur(8px);
                align-items: center;
                justify-content: center;
                z-index: 2000;
                padding: 20px;
            }}
            
            .modal[aria-modal="true"] {{
                display: flex;
            }}
            
            .modal-content {{
                background: rgba(20, 20, 24, 0.98);
                border: 1px solid rgba(var(--primary-rgb), 0.3);
                border-radius: 20px;
                padding: 32px;
                max-width: 500px;
                width: 100%;
                box-shadow: var(--shadow-elevated);
                position: relative;
                backdrop-filter: var(--backdrop-blur);
            }}
            
            .modal-content::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                background: linear-gradient(135deg, 
                    rgba(var(--primary-rgb), 0.05) 0%, 
                    transparent 100%);
                border-radius: 20px;
                pointer-events: none;
            }}
            
            .close-modal {{
                position: absolute;
                top: 20px;
                right: 24px;
                background: none;
                border: none;
                font-size: 24px;
                color: var(--text-secondary);
                cursor: pointer;
                transition: color 0.2s ease;
                z-index: 1;
            }}
            
            .close-modal:hover {{
                color: var(--text-primary);
            }}
            
            .modal-title {{
                font-size: 1.5rem;
                font-weight: 700;
                margin-bottom: 24px;
                color: var(--text-primary);
                text-align: center;
                position: relative;
                z-index: 1;
            }}
            
            .form-group {{
                margin-bottom: 20px;
                position: relative;
                z-index: 1;
            }}
            
            .form-group label {{
                display: block;
                margin-bottom: 8px;
                color: var(--text-primary);
                font-weight: 500;
                font-size: 0.9rem;
            }}
            
            .form-group input,
            .form-group select,
            .form-group textarea {{
                width: 100%;
                padding: 12px 16px;
                border: 1px solid rgba(var(--primary-rgb), 0.3);
                border-radius: 12px;
                background: rgba(255, 255, 255, 0.05);
                color: var(--text-primary);
                font-size: 0.95rem;
                font-family: inherit;
                transition: all 0.2s ease;
                backdrop-filter: var(--backdrop-blur);
            }}
            
            .form-group input:focus,
            .form-group select:focus,
            .form-group textarea:focus {{
                outline: none;
                border-color: var(--primary-color);
                box-shadow: 0 0 0 3px rgba(var(--primary-rgb), 0.1);
            }}
            
            .form-group textarea {{
                min-height: 80px;
                resize: vertical;
            }}
            
            .submit-btn {{
                width: 100%;
                background: linear-gradient(135deg, var(--primary-color) 0%, #d946ef 100%);
                color: white;
                border: none;
                border-radius: 12px;
                padding: 14px 24px;
                font-size: 1rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s ease;
                box-shadow: var(--shadow-primary);
                position: relative;
                z-index: 1;
            }}
            
            .submit-btn:hover {{
                transform: translateY(-2px);
                box-shadow: var(--shadow-elevated);
            }}
            
            .submit-btn:active {{
                transform: translateY(0);
            }}
            
            /* Responsive design */
            @media (max-width: 1024px) {{
                .sidebar {{
                    width: 240px;
                }}
                
                .main-content {{
                    margin-left: 240px;
                    padding: 32px;
                }}
                
                .user-info {{
                    right: 32px;
                }}
            }}
            
            @media (max-width: 768px) {{
                .sidebar {{
                    transform: translateX(-100%);
                    width: 100%;
                    height: auto;
                    position: fixed;
                    bottom: 0;
                    top: auto;
                    flex-direction: row;
                    padding: 16px;
                    border-right: none;
                    border-top: 1px solid var(--border-color);
                    z-index: 2000;
                }}
                
                .logo {{
                    display: none;
                }}
                
                .nav-links {{
                    flex-direction: row;
                    padding: 0;
                    width: 100%;
                    justify-content: space-around;
                }}
                
                .nav-item {{
                    flex: 1;
                    justify-content: center;
                    padding: 12px 8px;
                    font-size: 0.8rem;
                }}
                
                .main-content {{
                    margin-left: 0;
                    padding: 20px 16px 100px 16px;
                }}
                
                .user-info {{
                    top: 16px;
                    right: 16px;
                    padding: 8px 12px;
                    gap: 12px;
                }}
                
                .user-avatar {{
                    width: 36px;
                    height: 36px;
                }}
                
                .cases-title {{
                    font-size: 2rem;
                }}
                
                .cases-header {{
                    flex-direction: column;
                    align-items: flex-start;
                    gap: 16px;
                }}
                
                .cases-table {{
                    font-size: 0.85rem;
                }}
                
                .cases-table th,
                .cases-table td {{
                    padding: 12px 16px;
                }}
                
                .case-reason {{
                    max-width: 150px;
                }}
            }}
            
            @media (max-width: 480px) {{
                .main-content {{
                    padding: 16px 12px 100px 12px;
                }}
                
                .user-info {{
                    top: 12px;
                    right: 12px;
                    padding: 6px 8px;
                }}
                
                .user-details {{
                    display: none;
                }}
                
                .cases-table th,
                .cases-table td {{
                    padding: 8px 12px;
                }}
                
                .case-reason {{
                    max-width: 100px;
                }}
                
                .modal-content {{
                    padding: 24px;
                    margin: 20px;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="background-pattern"></div>
        
        <div class="sidebar">
            <div class="logo">
                <img src="https://cdn.discordapp.com/attachments/1359093144376840212/1391111028552765550/image.png?ex=686caeda&is=686b5d5a&hm=2f7a401945da09ff951d426aaf651ade57dad6b6a52c567713aacf466c214a85&" alt="Themis">
                <div class="logo-text">Themis</div>
            </div>
            <nav class="nav-links">
                <a href="/admin/dashboard" class="nav-item">
                    <svg class="nav-icon" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M3 4a1 1 0 011-1h12a1 1 0 011 1v2a1 1 0 01-1 1H4a1 1 0 01-1-1V4zM3 10a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H4a1 1 0 01-1-1v-6zM14 9a1 1 0 00-1 1v6a1 1 0 001 1h2a1 1 0 001-1v-6a1 1 0 00-1-1h-2z"/>
                    </svg>
                    Dashboard
                </a>
                <a href="/admin/cases" class="nav-item active">
                    <svg class="nav-icon" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h8a2 2 0 012 2v12a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm3 1h6v4H7V5zm8 8v2h1v-2h-1zm-1-1h1v-2h-1v2zm1-4h-1V6h1v2zM7 8h6v4H7V8z" clip-rule="evenodd"/>
                    </svg>
                    Cases
                </a>
                <a href="/" class="nav-item">
                    <svg class="nav-icon" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M10.707 2.293a1 1 0 00-1.414 0l-7 7a1 1 0 001.414 1.414L4 10.414V17a1 1 0 001 1h2a1 1 0 001-1v-2a1 1 0 011-1h2a1 1 0 011 1v2a1 1 0 001 1h2a1 1 0 001-1v-6.586l.293.293a1 1 0 001.414-1.414l-7-7z"/>
                    </svg>
                    Home
                </a>
            </nav>
        </div>
        
        <div class="user-info">
            <div class="user-avatar">
                {f'<img src="{user.get('avatar_url')}" alt="Avatar">' if user.get('avatar_url') else user.get('username', 'U')[0].upper()}
            </div>
            <div class="user-details">
                <div class="user-name">{user.get('username', 'User')}</div>
                <div class="user-rank">{staff_rank}</div>
            </div>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>
        
        <main class="main-content">
            <div class="cases-header">
                <h1 class="cases-title">Cases</h1>
                <button class="create-log-btn" onclick="openModlogModal()">
                    <svg width="16" height="16" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd"/>
                    </svg>
                    Create Moderation Log
                </button>
            </div>
            
            <div class="cases-container">
                <table class="cases-table">
                    <thead>
                        <tr>
    <th>Case ID</th>
    <th>User ID</th>
    <th>Type</th>
    <th>Reason</th>
    <th>Status</th>
    <th>Length</th>
    <th>Evidence</th>
    <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(f'''
                        <tr>
                            <td><span class="case-id">#{c["id"]}</span></td>
                            <td><span class="user-id">{c["user_id"]}</span></td>
                            <td><span class="type-badge" style="background-color: {get_type_color(c['type'])}">{c["type"].title()}</span></td>
                            <td><span class="case-reason" title="{c['reason'] or 'No reason provided'}">{c["reason"] or 'No reason provided'}</span></td>
                            <td><span class="status-badge {'status-appealed' if c['status'] == 'Appealed' else 'status-active'}">{c["status"]}</span></td>
                            <td>{c["length"]}</td>
                            <td>{render_evidence_block(c.get('evidence_list', []))}</td>
                            <td>
                                <button class="action-btn" onclick="viewCase('{c['id']}', '{c['user_id']}', '{c['type']}', '{c['reason'] or 'No reason provided'}', '{c['status']}', '{c['length']}')">
                                    <svg width="14" height="14" fill="currentColor" viewBox="0 0 20 20">
                                        <path d="M10 12a2 2 0 100-4 2 2 0 000 4z"/>
                                        <path fill-rule="evenodd" d="M.458 10C1.732 5.943 5.522 3 10 3s8.268 2.943 9.542 7c-1.274 4.057-5.064 7-9.542 7S1.732 14.057.458 10zM14 10a4 4 0 11-8 0 4 4 0 018 0z" clip-rule="evenodd"/>
                                    </svg>
                                    View
                                </button>
                            </td>
                        </tr>
                        ''' for c in cases) if cases else '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 40px;">No cases found</td></tr>'}
                    </tbody>
                </table>
            </div>
        </main>
        
        <!-- Create Modlog Modal -->
        <div id="modlogModal" class="modal" role="dialog" aria-modal="false" aria-labelledby="modlogModalTitle">
            <div class="modal-content">
                <button class="close-modal" onclick="closeModlogModal()" aria-label="Close modal">&times;</button>
                <h2 id="modlogModalTitle" class="modal-title">Create Moderation Log</h2>
                <form id="modlogForm">
                    <div class="form-group">
                        <label for="userId">User ID</label>
                        <input type="text" id="userId" name="userId" required placeholder="Enter Discord User ID">
                    </div>
                    <div class="form-group">
                        <label for="punishmentType">Punishment Type</label>
                        <select id="punishmentType" name="punishmentType" required>
                            <option value="">Select punishment type</option>
                            <option value="warn">Warning</option>
                            <option value="mute">Mute</option>
                            <option value="kick">Kick</option>
                            <option value="ban">Ban</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="reason">Reason</label>
                        <textarea id="reason" name="reason" required placeholder="Enter reason for punishment"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="length">Length (optional)</label>
                        <input type="text" id="length" name="length" placeholder="e.g., 1d, 1h, permanent">
                    </div>
                    <button type="submit" class="submit-btn">Create Log Entry</button>
                </form>
            </div>
        </div>
        
        <!-- View Case Modal -->
        <div id="viewCaseModal" class="modal" role="dialog" aria-modal="false" aria-labelledby="viewCaseModalTitle">
            <div class="modal-content">
                <button class="close-modal" onclick="closeViewCaseModal()" aria-label="Close modal">&times;</button>
                <h2 id="viewCaseModalTitle" class="modal-title">Case Details</h2>
                <div id="caseDetails">
                    <!-- Case details will be populated here -->
                </div>
            </div>
        </div>
        
        <script>
            const punishmentColors = {punishment_colors_js};
            
            function openModlogModal() {{
                const modal = document.getElementById('modlogModal');
                modal.style.display = 'flex';
                modal.setAttribute('aria-modal', 'true');
                document.body.style.overflow = 'hidden';
            }}

            function closeModlogModal() {{
                const modal = document.getElementById('modlogModal');
                modal.style.display = 'none';
                modal.setAttribute('aria-modal', 'false');
                document.body.style.overflow = 'auto';
                document.getElementById('modlogForm').reset();
            }}

            function viewCase(caseId, userId, type, reason, status, length) {{
                const modal = document.getElementById('viewCaseModal');
                const detailsContainer = document.getElementById('caseDetails');
                detailsContainer.innerHTML = '<div style="text-align:center;padding:30px;">Loading...</div>';
                modal.style.display = 'flex';
                modal.setAttribute('aria-modal', 'true');
                document.body.style.overflow = 'hidden';

                // Fetch latest case info from backend
                fetch('/api/case/discord/' + caseId)
                    .then(res => res.json())
                    .then(data => {{
                        if (data.error) {{
                            detailsContainer.innerHTML = '<div style="color:red;">' + data.error + '</div>';
                            return;
                        }}
                        const typeColor = punishmentColors[(data.punishment_type || '').toLowerCase()] || punishmentColors['default'];
                        // Evidence rendering: show images and videos inline, others as links
                        let evidenceHtml = '';
                        if (data.evidence && Array.isArray(data.evidence) && data.evidence.length) {{
                            evidenceHtml = '<div class="form-group"><label>Evidence</label><div style="display:flex;flex-direction:column;gap:12px;">' +
                                data.evidence.map(function(url) {{
                                    const ext = url.split('.').pop().toLowerCase().split('?')[0];
                                    if (["jpg","jpeg","png","gif","webp","bmp"].includes(ext)) {{
                                        return '<a href="' + url + '" target="_blank"><img src="' + url + '" alt="evidence" style="max-width:100%;max-height:220px;border-radius:8px;box-shadow:0 2px 8px #0002;"></a>';
                                    }} else if (["mp4","webm","ogg","mov","m4v"].includes(ext)) {{
                                        return '<video controls style="max-width:100%;max-height:220px;border-radius:8px;box-shadow:0 2px 8px #0002;"><source src="' + url + '"></video>';
                                    }} else {{
                                        return '<a href="' + url + '" target="_blank">' + url + '</a>';
                                    }}
                                }}).join('') + '</div></div>';
                        }}
                        detailsContainer.innerHTML = `
                            <div style="display: flex; flex-direction: column; gap: 20px;">
                                <div class="form-group">
                                    <label>Case ID</label>
                                    <div style="font-family: 'Monaco', 'Menlo', monospace; font-weight: 600; color: var(--text-primary);">#${{data.reference_id}}</div>
                                </div>
                                <div class="form-group">
                                    <label>User ID</label>
                                    <div style="font-family: 'Monaco', 'Menlo', monospace; color: var(--text-muted);">${{data.user_id}}</div>
                                </div>
                                <div class="form-group">
                                    <label>Punishment Type</label>
                                    <div><span class="type-badge" style="background-color: ${{typeColor}}">${{(data.punishment_type || '').charAt(0).toUpperCase() + (data.punishment_type || '').slice(1)}}</span></div>
                                </div>
                                <div class="form-group">
                                    <label>Reason</label>
                                    <div style="color: var(--text-secondary);">${{data.reason}}</div>
                                </div>
                                <div class="form-group">
                                    <label>Status</label>
                                    <div><span class="status-badge ${{data.appealed === 1 ? 'status-appealed' : 'status-active'}}">${{data.appealed === 1 ? 'Appealed' : 'Active'}}</span></div>
                                </div>
                                <div class="form-group">
                                    <label>Length</label>
                                    <div style="color: var(--text-secondary);">${{data.length || 'N/A'}}</div>
                                </div>
                                ${{data.discord_username ? `<div class="form-group"><label>Discord Username</label><div>${{data.discord_username}}</div></div>` : ''}}
                                ${{data.roblox_username ? `<div class="form-group"><label>Roblox Username</label><div>${{data.roblox_username}}</div></div>` : ''}}
                                ${{evidenceHtml}}
                            </div>
                        `;
                    }})
                    .catch(err => {{
                        detailsContainer.innerHTML = '<div style="color:red;">Error loading case details.</div>';
                    }});
            }}

            function closeViewCaseModal() {{
                const modal = document.getElementById('viewCaseModal');
                modal.style.display = 'none';
                modal.setAttribute('aria-modal', 'false');
                document.body.style.overflow = 'auto';
            }}
            
            // Handle form submission
            document.getElementById('modlogForm').addEventListener('submit', function(e) {{
                e.preventDefault();
                
                const formData = new FormData(this);
                const data = Object.fromEntries(formData);
                
                // Send to server
                fetch('/admin/create-modlog', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify(data)
                }})
                .then(response => response.json())
                .then(result => {{
                    if (result.success) {{
                        closeModlogModal();
                        // Refresh the page to show new case
                        window.location.reload();
                    }} else {{
                        alert('Error creating modlog: ' + result.message);
                    }}
                }})
                .catch(error => {{
                    console.error('Error:', error);
                    alert('Error creating modlog. Please try again.');
                }});
            }});
            
            // Close modals when clicking outside
            document.getElementById('modlogModal').addEventListener('click', function(e) {{
                if (e.target === this) {{
                    closeModlogModal();
                }}
            }});
            
            document.getElementById('viewCaseModal').addEventListener('click', function(e) {{
                if (e.target === this) {{
                    closeViewCaseModal();
                }}
            }});
            
            // Close modals with Escape key
            document.addEventListener('keydown', function(e) {{
                if (e.key === 'Escape') {{
                    closeModlogModal();
                    closeViewCaseModal();
                }}
            }});
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(html)

@app.route('/admin/create-modlog', methods=['POST'])
@login_required
@staff_required
def create_modlog():
    """
    Create a moderation log entry in the discord table (as a new case).
    Accepts: userId, punishmentType, reason, length (from frontend form)
    """
    user = session.get('user', {})
    data = request.get_json()
    user_id = data.get('userId')
    punishment_type = data.get('punishmentType')
    reason = data.get('reason')
    length = data.get('length')
    if not all([user_id, punishment_type, reason]):
        return jsonify({'success': False, 'message': 'Missing required fields'}), 400
    try:
        connection = get_db_connection()
        if connection is None:
            return jsonify({'success': False, 'message': 'DB connection error'}), 500
        cursor = connection.cursor()
        # Insert new case into discord table
        insert_query = """
            INSERT INTO discord (user_id, punishment_type, reason, length, appealed)
            VALUES (%s, %s, %s, %s, 0)
        """
        cursor.execute(insert_query, (user_id, punishment_type, reason, length))
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({'success': True, 'message': 'Moderation log created'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/update-modlog/<int:reference_id>', methods=['PUT'])
@login_required
@staff_required
def update_modlog(reference_id):
    """
    Update an existing moderation log entry with evidence and moderator notes.
    Accepts: evidence, moderatorNote (from request body)
    """
    user = session.get('user', {})
    data = request.get_json()
    
    evidence = data.get('evidence')
    moderator_note = data.get('moderatorNote')
    
    if not evidence and not moderator_note:
        return jsonify({'success': False, 'message': 'No update data provided'}), 400
    
    try:
        connection = get_db_connection()
        if connection is None:
            return jsonify({'success': False, 'message': 'DB connection error'}), 500
        
        cursor = connection.cursor()
        
        # First check if the modlog entry exists
        check_query = "SELECT reference_id FROM discord WHERE reference_id = %s"
        cursor.execute(check_query, (reference_id,))
        
        if not cursor.fetchone():
            cursor.close()
            connection.close()
            return jsonify({'success': False, 'message': 'Moderation log entry not found'}), 404
        
        # Build dynamic update query based on provided fields
        update_fields = []
        update_values = []
        
        if evidence:
            update_fields.append("evidence = %s")
            update_values.append(evidence)
        
        if moderator_note:
            update_fields.append("moderator_note = %s")
            update_values.append(moderator_note)
        
        # Add the reference_id at the end for the WHERE clause
        update_values.append(reference_id)
        
        update_query = f"""
            UPDATE discord 
            SET {', '.join(update_fields)}
            WHERE reference_id = %s
        """
        
        cursor.execute(update_query, update_values)
        connection.commit()
        
        cursor.close()
        connection.close()
        
        return jsonify({
            'success': True, 
            'message': 'Moderation log updated successfully',
            'updated_fields': {
                'evidence': evidence is not None,
                'moderator_note': moderator_note is not None
            }
        })
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/case/<project>/<case_id>')
@login_required
@staff_required
def get_case_detail(project, case_id):
    try:
        # Validate project parameter to prevent SQL injection
        if project not in ['discord', 'arenamadness']:
            return jsonify({'error': 'Invalid project'}), 400

        connection = get_db_connection()
        if connection is None:
            return jsonify({'error': 'DB connection error'}), 500

        cursor = connection.cursor(dictionary=True)
        # Get case from main table
        cursor.execute(f"SELECT * FROM {project} WHERE reference_id = %s OR user_id = %s", (case_id, case_id))
        case = cursor.fetchone()
        if not case:
            cursor.close()
            connection.close()
            return jsonify({'error': 'Case not found'}), 404
        # Try to get user info from users table if possible
        discord_username = None
        roblox_user_id = None
        roblox_username = None
        if 'user_id' in case and case['user_id']:
            cursor.execute("SELECT discord_username, roblox_user_id, roblox_username FROM users WHERE discord_user_id = %s", (case['user_id'],))
            user_row = cursor.fetchone()
            if user_row:
                discord_username = user_row.get('discord_username')
                roblox_user_id = user_row.get('roblox_user_id')
                roblox_username = user_row.get('roblox_username')
        cursor.close()
        connection.close()
        # Convert evidence field if it exists
        if case.get('evidence'):
            if isinstance(case['evidence'], str):
                import ast
                try:
                    # Try to parse as list, fallback to splitting by newline
                    evidence_val = case['evidence']
                    if evidence_val.strip().startswith('['):
                        case['evidence'] = ast.literal_eval(evidence_val)
                    else:
                        case['evidence'] = [url.strip() for url in evidence_val.split('\n') if url.strip()]
                except Exception:
                    case['evidence'] = [url.strip() for url in case['evidence'].split('\n') if url.strip()]
        # Add user info to response
        case['discord_username'] = discord_username
        case['roblox_user_id'] = roblox_user_id
        case['roblox_username'] = roblox_username
        return jsonify(case)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/meeting')
@login_required
@staff_required
def meeting():
    html = '''
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Senior Coordinator Onboarding - fx-Studios</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .slide {
            background: white;
            margin: 20px 0;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1);
            display: none;
            animation: slideIn 0.5s ease-out;
        }

        .slide.active {
            display: block;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        h1 {
            color: #4a5568;
            font-size: 2.5em;
            margin-bottom: 20px;
            text-align: center;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }

        h2 {
            color: #2d3748;
            font-size: 2em;
            margin-bottom: 20px;
            text-align: center;
        }

        h3 {
            color: #4a5568;
            font-size: 1.5em;
            margin-bottom: 15px;
            border-left: 4px solid #667eea;
            padding-left: 15px;
        }

        .logo {
            text-align: center;
            margin-bottom: 30px;
        }

        .logo-text {
            font-size: 3em;
            font-weight: bold;
            background: linear-gradient(135deg, #667eea, #764ba2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .orgchart {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 30px;
            margin: 30px 0;
        }

        .level {
            display: flex;
            justify-content: center;
            gap: 40px;
            flex-wrap: wrap;
        }

        .position {
            background: linear-gradient(135deg, #f7fafc, #edf2f7);
            border: 2px solid #667eea;
            border-radius: 10px;
            padding: 15px 25px;
            text-align: center;
            min-width: 180px;
            position: relative;
            transition: all 0.3s ease;
        }

        .position:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.3);
        }

        .position.executive {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border-color: #4c51bf;
        }

        .position.director {
            background: linear-gradient(135deg, #4299e1, #3182ce);
            color: white;
            border-color: #2b6cb0;
        }

        .position.senior {
            background: linear-gradient(135deg, #48bb78, #38a169);
            color: white;
            border-color: #2f855a;
        }

        .position.coordinator {
            background: linear-gradient(135deg, #ed8936, #dd6b20);
            color: white;
            border-color: #c05621;
        }

        .team-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin: 30px 0;
        }

        .team-card {
            background: linear-gradient(135deg, #f7fafc, #edf2f7);
            border: 2px solid #667eea;
            border-radius: 15px;
            padding: 25px;
            transition: transform 0.3s ease;
        }

        .team-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.2);
        }

        .team-title {
            color: #667eea;
            font-size: 1.4em;
            font-weight: bold;
            margin-bottom: 15px;
            text-align: center;
        }

        .member {
            background: white;
            border-radius: 8px;
            padding: 10px 15px;
            margin: 10px 0;
            border-left: 4px solid #667eea;
        }

        .member.senior {
            border-left-color: #48bb78;
            background: linear-gradient(90deg, #f0fff4, #ffffff);
        }

        .member.coordinator {
            border-left-color: #ed8936;
            background: linear-gradient(90deg, #fffaf0, #ffffff);
        }

        .key-points {
            background: linear-gradient(135deg, #fed7d7, #fbb6ce);
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            border-left: 5px solid #e53e3e;
        }

        .key-points h3 {
            color: #742a2a;
            border-left: none;
            padding-left: 0;
        }

        ul {
            padding-left: 20px;
            margin: 15px 0;
        }

        li {
            margin: 8px 0;
            padding-left: 10px;
        }

        .navigation {
            position: fixed;
            bottom: 20px;
            left: 50%;
            transform: translateX(-50%);
            display: flex;
            gap: 10px;
            z-index: 1000;
        }

        .nav-btn {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 25px;
            cursor: pointer;
            font-size: 14px;
            transition: all 0.3s ease;
        }

        .nav-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }

        .nav-btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .slide-counter {
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(255, 255, 255, 0.9);
            padding: 10px 15px;
            border-radius: 20px;
            font-weight: bold;
            z-index: 1000;
        }

        .highlight {
            background: linear-gradient(135deg, #fef5e7, #fed7aa);
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            border-left: 4px solid #f6ad55;
        }

        .connection-line {
            width: 2px;
            height: 20px;
            background: #667eea;
            margin: 0 auto;
        }

        @media (max-width: 768px) {
            .team-grid {
                grid-template-columns: 1fr;
            }
            
            .level {
                flex-direction: column;
                align-items: center;
            }
            
            .slide {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="slide-counter">
            <span id="current-slide">1</span> / <span id="total-slides">7</span>
        </div>

        <!-- Slide 1: Welcome -->
        <div class="slide active">
            <div class="logo">
                <div class="logo-text">fx-Studios</div>
            </div>
            <h1>Senior Coordinator Onboarding</h1>
            <div style="text-align: center; margin: 40px 0;">
                <h2 style="color: #667eea; margin-bottom: 20px;">Welcome to Leadership</h2>
                <p style="font-size: 1.2em; color: #4a5568; max-width: 600px; margin: 0 auto;">
                    This presentation will guide you through your responsibilities as Senior Coordinators 
                    and introduce you to your team structure within fx-Studios.
                </p>
            </div>
            <div class="highlight">
                <h3>Document Version: V1.0</h3>
                <p><strong>Last Updated:</strong> 06/07/2025</p>
                <p><strong>Maintained By:</strong> Project Director Steve & Executive Director fxllenfx</p>
            </div>
        </div>

        <!-- Slide 2: Organizational Structure -->
        <div class="slide">
            <h2>fx-Studios Organizational Structure</h2>
            <div class="orgchart">
                <div class="level">
                    <div class="position executive">
                        <strong>Executive Director</strong><br>
                        fxllenfx
                    </div>
                </div>
                <div class="connection-line"></div>
                <div class="level">
                    <div class="position director">Administration Director</div>
                    <div class="position director">Project Director<br>Steve</div>
                    <div class="position director">Community Director<br>Feliks</div>
                </div>
                <div class="connection-line"></div>
                <div class="level">
                    <div class="position">Studio Administration</div>
                    <div class="position">Moderation Division</div>
                    <div class="position">Development Team</div>
                    <div class="position" style="background: linear-gradient(135deg, #667eea, #764ba2); color: white;">
                        <strong>Community Coordination</strong><br>
                        <em>Your Division</em>
                    </div>
                </div>
            </div>
        </div>

        <!-- Slide 3: Community Coordination Teams -->
        <div class="slide">
            <h2>Community Coordination Team Structure</h2>
            <div class="team-grid">
                <div class="team-card">
                    <div class="team-title">🛒 Procurement Team</div>
                    <div class="member senior">
                        <strong>Senior Coordinator</strong><br>
                        CodaCulture (UTC+1)
                    </div>
                    <div class="member coordinator">
                        <strong>Coordinator</strong><br>
                        Abdullah (UTC+2)
                    </div>
                    <div class="member coordinator">
                        <strong>Coordinator</strong><br>
                        Nick (UTC+0)
                    </div>
                    <div class="member coordinator">
                        <strong>Trainee Moderator</strong><br>
                        Person (UTC+2)
                    </div>
                </div>
                <div class="team-card">
                    <div class="team-title">🎯 Campaigns & Ideas Team</div>
                    <div class="member senior">
                        <strong>Senior Coordinator</strong><br>
                        Bl1tzer1n (UTC+2)
                    </div>
                    <div class="member coordinator">
                        <strong>Coordinator</strong><br>
                        2hn (EST)
                    </div>
                    <div class="member coordinator">
                        <strong>Coordinator</strong><br>
                        K3bhi (UTC-4)
                    </div>
                </div>
            </div>
        </div>

        <!-- Slide 4: Senior Coordinator Hierarchy -->
        <div class="slide">
            <h2>Leadership Hierarchy & Training Responsibilities</h2>
            <div class="key-points">
                <h3>🎖️ Critical Leadership Structure</h3>
                <ul>
                    <li><strong>Senior Coordinators</strong> are responsible for training and developing Coordinators</li>
                    <li><strong>Coordinators report directly to Senior Coordinators</strong> within their teams</li>
                    <li>Senior Coordinators must mentor, guide, and evaluate Coordinator performance</li>
                    <li>All escalations from Coordinators go through Senior Coordinators first</li>
                </ul>
            </div>
            <div class="orgchart" style="margin-top: 30px;">
                <div class="level">
                    <div class="position director">Community Director<br>Feliks</div>
                </div>
                <div class="connection-line"></div>
                <div class="level">
                    <div class="position senior">Senior Coordinator<br>CodaCulture</div>
                    <div class="position senior">Senior Coordinator<br>Bl1tzer1n</div>
                </div>
                <div class="connection-line"></div>
                <div class="level">
                    <div class="position coordinator">Coordinator<br>Abdullah</div>
                    <div class="position coordinator">Coordinator<br>Nick</div>
                    <div class="position coordinator">Tr. M Person</div>
                    <div class="position coordinator">Coordinator<br>2hn</div>
                    <div class="position coordinator">Coordinator<br>K3bhi</div>
                </div>
            </div>
        </div>

        <!-- Slide 5: Key Responsibilities -->
        <div class="slide">
            <h2>Senior Coordinator Responsibilities</h2>
            <h3>📋 Core Duties (Section 4.2)</h3>
            <ul>
                <li><strong>Community Engagement:</strong> Serve as public representatives of fx-Studios</li>
                <li><strong>Platform Management:</strong> Engage community across all official platforms</li>
                <li><strong>Brand Representation:</strong> Maintain studio's image and voice</li>
                <li><strong>Feedback Collection:</strong> Gather and relay community feedback to leadership</li>
                <li><strong>Recruitment Leadership:</strong> Lead hiring campaigns with Board collaboration</li>
                <li><strong>Staff Monitoring:</strong> Monitor staff levels and recruitment needs</li>
            </ul>
            
            <div class="highlight">
                <h3>👥 Team Leadership Responsibilities</h3>
                <ul>
                    <li>Train and mentor Coordinators in your team</li>
                    <li>Assign tasks and monitor progress</li>
                    <li>Conduct regular performance evaluations</li>
                    <li>Handle escalations from your team members</li>
                    <li>Ensure professional development of subordinates</li>
                </ul>
            </div>
        </div>

        <!-- Slide 6: Communication & Protocols -->
        <div class="slide">
            <h2>Communication Protocols & Standards</h2>
            <h3>📞 Reporting Structure</h3>
            <ul>
                <li><strong>Direct Reports:</strong> Report regularly to Community Director (Feliks)</li>
                <li><strong>Cross-Division:</strong> Coordinate with Studio Administration for new hire onboarding</li>
                <li><strong>Board Updates:</strong> Provide hiring updates to Board of Directors</li>
            </ul>

            <h3>💬 Professional Standards (Section 2.5)</h3>
            <div class="key-points">
                <h3>⚠️ Mandatory Behaviors</h3>
                <ul>
                    <li>Maintain highest level of professionalism in all communications</li>
                    <li>Refrain from provocative, escalatory, or sarcastic responses</li>
                    <li>Maintain posture of de-escalation, neutrality, and professionalism</li>
                    <li>Preserve anonymity in official communications unless cleared by Senior Moderator+</li>
                    <li>Never click unsolicited external links - request embedded previews</li>
                </ul>
            </div>

            <h3>📊 Documentation Requirements</h3>
            <ul>
                <li>All significant activities must be recorded in <strong>Themis</strong></li>
                <li>Log all interventions and team interactions</li>
                <li>Maintain confidentiality of all staff communications</li>
            </ul>
        </div>

        <!-- Slide 7: Next Steps -->
        <div class="slide">
            <h2>Next Steps & Final Reminders</h2>
            <h3>🚀 Immediate Actions</h3>
            <ul>
                <li><strong>Meet Your Team:</strong> Schedule initial meetings with your Coordinators</li>
                <li><strong>Review Themis:</strong> Familiarize yourself with the logging system</li>
                <li><strong>Establish Routines:</strong> Set up regular check-ins with your team</li>
                <li><strong>Coordinate with Leadership:</strong> Align with Community Director on priorities</li>
            </ul>

            <div class="key-points">
                <h3>🎯 Success Metrics</h3>
                <ul>
                    <li>Team productivity and professional development</li>
                    <li>Quality of community engagement and feedback</li>
                    <li>Successful recruitment and onboarding</li>
                    <li>Adherence to fx-Studios standards and protocols</li>
                </ul>
            </div>

            <div class="highlight">
                <h3>📋 Key Contacts</h3>
                <ul>
                    <li><strong>Community Director:</strong> Feliks (feliks0187)</li>
                    <li><strong>Executive Director:</strong> fxllenfx</li>
                    <li><strong>Project Director:</strong> Steve (Stevenson)</li>
                </ul>
            </div>

            <div style="text-align: center; margin-top: 40px;">
                <h2 style="color: #667eea;">Welcome to Leadership at fx-Studios!</h2>
                <p style="font-size: 1.2em; color: #4a5568;">
                    Your role as Senior Coordinator is crucial to our success. Lead with excellence.
                </p>
            </div>
        </div>
    </div>

    <div class="navigation">
        <button class="nav-btn" id="prevBtn" onclick="changeSlide(-1)">Previous</button>
        <button class="nav-btn" id="nextBtn" onclick="changeSlide(1)">Next</button>
    </div>

    <script>
        let currentSlide = 1;
        const totalSlides = 7;

        function showSlide(n) {
            const slides = document.querySelectorAll('.slide');
            if (n > totalSlides) currentSlide = 1;
            if (n < 1) currentSlide = totalSlides;
            
            slides.forEach(slide => slide.classList.remove('active'));
            slides[currentSlide - 1].classList.add('active');
            
            document.getElementById('current-slide').textContent = currentSlide;
            document.getElementById('total-slides').textContent = totalSlides;
            
            // Update navigation buttons
            document.getElementById('prevBtn').disabled = currentSlide === 1;
            document.getElementById('nextBtn').disabled = currentSlide === totalSlides;
        }

        function changeSlide(n) {
            currentSlide += n;
            showSlide(currentSlide);
        }

        // Keyboard navigation
        document.addEventListener('keydown', function(e) {
            if (e.key === 'ArrowLeft') changeSlide(-1);
            if (e.key === 'ArrowRight') changeSlide(1);
        });

        // Initialize
        showSlide(currentSlide);
    </script>
</body>
</html>
'''
    return render_template_string(html)

if __name__ == '__main__':
    app.run(debug=False)
