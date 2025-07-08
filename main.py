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
        # Optionally: Save file_url to your DB here
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

@app.route('/admin/dashboard')
@login_required
@staff_required
def admin_dashboard():
    user = session['user']
    staff_rank = user.get('staff_info', {}).get('role', 'Staff')
    rank_color = RANK_COLORS.get(staff_rank, '#a977f8')
    # Use a raw string for HTML/JS and match the new sidebar/user info layout
    html = rf'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Themis Admin Dashboard</title>
        <style>
            /* --- Mobile/Responsive Polish --- */
            @media (max-width: 900px) {{
                .main-content {{ margin-left: 0 !important; padding: 1.5rem 0.5rem 5rem 0.5rem !important; }}
                .sidebar {{ width: 100vw !important; height: 60px !important; flex-direction: row !important; top: unset !important; bottom: 0 !important; left: 0 !important; border-right: none !important; border-top: 1.5px solid #a977f8 !important; box-shadow: 0 -2px 16px #a977f81a !important; z-index: 2000 !important; }}
                .sidebar .logo {{ display: none !important; }}
                .sidebar .nav-links {{ flex-direction: row !important; gap: 0.5rem !important; margin: 0 !important; width: 100% !important; justify-content: space-around !important; align-items: center !important; }}
                .sidebar .admin-btn {{ margin: 0 !important; padding: 0.7rem 0.9rem !important; font-size: 0.98rem !important; border-radius: 8px !important; }}
                .user-info-box {{ right: 1rem !important; top: 0.7rem !important; padding: 0.5rem 0.8rem !important; }}
            }}
            @media (max-width: 600px) {{
                .main-content {{ padding: 0.7rem 0.1rem 5rem 0.1rem !important; }}
                .cases-title, .dashboard-title {{ font-size: 1.3rem !important; }}
                .cases-header {{ flex-direction: column !important; align-items: flex-start !important; gap: 0.7rem !important; }}
                .cases-table th, .cases-table td {{ padding: 0.5rem !important; font-size: 0.92rem !important; }}
                .cases-table th {{ font-size: 0.8rem !important; }}
                .user-info-box {{ top: 0.3rem !important; right: 0.3rem !important; padding: 0.3rem 0.5rem !important; }}
                .user-avatar {{ width: 28px !important; height: 28px !important; font-size: 13px !important; }}
                .user-details .user-name {{ font-size: 0.98rem !important; }}
                .user-details .user-rank {{ font-size: 10px !important; }}
                .logout-btn {{ padding: 0.3rem 0.7rem !important; font-size: 0.85rem !important; }}
                .modal-content {{ padding: 1.2rem 0.5rem 1rem 0.5rem !important; min-width: 90vw !important; }}
            }}
            @media (max-width: 400px) {{
                .main-content {{ padding: 0.2rem 0 5rem 0 !important; }}
                .cases-table th, .cases-table td {{ padding: 0.25rem !important; font-size: 0.85rem !important; }}
                .modal-content {{ padding: 0.5rem 0.1rem 0.5rem 0.1rem !important; min-width: 98vw !important; }}
            }}
            body {{ font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.5; color: #fff; background: #0a0a0a; overflow-x: hidden; }}
            .sidebar {{ position: fixed; top: 0; left: 0; width: 220px; height: 100vh; background: rgba(20,20,30,0.92); border-right: 1.5px solid #a977f8; display: flex; flex-direction: column; z-index: 1000; box-shadow: 2px 0 16px #a977f81a; transition: all 0.25s; }}
            .sidebar .logo {{ font-size: 1.7rem; font-weight: 800; color: #fff; display: flex; align-items: center; gap: 0.85rem; letter-spacing: -0.03em; padding: 2.2rem 1.5rem 1.2rem 1.5rem; text-shadow: 0 2px 16px #a977f84d; }}
            .sidebar .logo img {{ width: 36px; height: 36px; border-radius: 10px; box-shadow: 0 2px 12px #a977f84d; }}
            .sidebar .nav-links {{ display: flex; flex-direction: column; gap: 0.7rem; margin-top: 2rem; }}
            .sidebar .admin-btn {{ background: rgba(255,255,255,0.08); color: #fff; padding: 0.8rem 1.3rem; border: 1.5px solid rgba(255,255,255,0.13); border-radius: 10px; text-decoration: none; transition: all 0.22s cubic-bezier(.4,0,.2,1); font-weight: 600; font-size: 1.07rem; margin: 0 1.2rem; display: flex; align-items: center; gap: 0.8rem; cursor: pointer; box-shadow: 0 2px 8px #a977f81a; letter-spacing: 0.01em; }}
            .sidebar .admin-btn.active, .sidebar .admin-btn:hover {{ background: rgba(169,119,248,0.18); border-color: #a977f8; color: #fff; transform: translateY(-2px) scale(1.03); box-shadow: 0 4px 24px #a977f84d; }}
            .main-content {{ margin-left: 220px; max-width: 1200px; padding: 3.5rem 2.5rem 2.5rem 2.5rem; min-height: 100vh; background: radial-gradient(ellipse 80% 50% at 50% 40%, rgba(169, 119, 248, 0.04) 0%, transparent 60%); }}
            .user-info-box {{ position: fixed; top: 1.7rem; right: 2.7rem; z-index: 1100; display: flex; align-items: center; gap: 1.1rem; background: rgba(255,255,255,0.10); border: 1.7px solid #a977f8; border-radius: 10px; box-shadow: 0 0 18px #a977f84d; padding: 0.7rem 1.4rem 0.7rem 1rem; backdrop-filter: blur(12px); }}
            .user-avatar {{ width: 40px; height: 40px; border-radius: 50%; background: #a977f8; display: flex; align-items: center; justify-content: center; font-size: 18px; font-weight: 800; overflow: hidden; box-shadow: 0 2px 8px #a977f84d; }}
            .user-avatar img {{ width: 100%; height: 100%; object-fit: cover; }}
            .user-details {{ display: flex; flex-direction: column; align-items: flex-start; }}
            .user-name {{ font-weight: 700; line-height: 1.2; font-size: 1.13rem; color: {{rank_color}}; letter-spacing: 0.01em; text-shadow: 0 2px 8px #000a; }}
            .user-rank {{ font-size: 12px; text-transform: capitalize; line-height: 1; font-weight: 600; color: #a0a0a0; letter-spacing: 0.01em; }}
            .logout-btn {{ background: rgba(255,255,255,0.13); color: #fff; border: 1.5px solid #a977f8; border-radius: 7px; padding: 0.45rem 1.1rem; font-size: 1.01rem; font-weight: 600; margin-left: 0.8rem; cursor: pointer; transition: background 0.2s, box-shadow 0.2s; box-shadow: 0 2px 8px #a977f84d; }}
            .logout-btn:hover {{ background: #a977f8; color: #fff; box-shadow: 0 4px 24px #a977f84d; }}
            .dashboard-title {{ 
                font-size: clamp(3.2rem, 8vw, 5.7rem); 
                font-weight: 800; 
                margin-bottom: 1.2rem; 
                letter-spacing: -0.045em; 
                line-height: 1.1; /* Fixed: Changed from 0.93 to 1.1 to prevent clipping */
                background: linear-gradient(135deg, #fff 0%, #a0a0a0 100%); 
                -webkit-background-clip: text; 
                -webkit-text-fill-color: transparent; 
                background-clip: text; 
                text-shadow: 0 2px 24px #a977f84d; 
                padding: 0.1em 0; /* Added padding to ensure characters don't get clipped */
            }}
            .dashboard-title .username-highlight {{ color: {rank_color}; background: none; -webkit-background-clip: unset; -webkit-text-fill-color: {rank_color}; background-clip: unset; font-weight: 800; text-shadow: 0 2px 12px {rank_color}; }}
            .dashboard-subtitle {{ color: #b7b7c9; font-size: 1.18rem; margin-bottom: 2.8rem; max-width: 650px; line-height: 1.7; font-weight: 500; letter-spacing: 0.01em; text-shadow: 0 2px 8px #000a; }}
            .quick-links {{ display: flex; gap: 2.5rem; margin-top: 2.5rem; }}
            .nav-card {{ background: rgba(169, 119, 248, 0.13); border: 1.5px solid #a977f8; border-radius: 16px; padding: 2.3rem 2.2rem 2rem 2.2rem; text-decoration: none; color: inherit; transition: all 0.32s cubic-bezier(.4,0,.2,1); cursor: pointer; display: flex; flex-direction: column; align-items: center; box-shadow: 0 4px 32px #a977f81a, 0 1.5px 0 #a977f8; position: relative; overflow: hidden; }}
            .nav-card:hover {{ background: rgba(169, 119, 248, 0.22); border-color: #a977f8; transform: translateY(-3px) scale(1.04) rotate(-1deg); box-shadow: 0 8px 48px #a977f84d, 0 1.5px 0 #a977f8; }}
            .nav-card .icon-img {{ width: 2.7rem; height: 2.7rem; margin-bottom: 1.2rem; border-radius: 10px; box-shadow: 0 2px 12px #a977f84d; background: #23232b; object-fit: cover; filter: drop-shadow(0 0 12px #a977f8cc); }}
            .nav-card h3 {{ font-size: 1.18rem; font-weight: 700; margin-bottom: 0.5rem; letter-spacing: 0.01em; text-shadow: 0 2px 8px #000a; }}
            .nav-card p {{ color: #b7b7c9; font-size: 1.01rem; font-weight: 500; text-align: center; margin: 0; letter-spacing: 0.01em; text-shadow: 0 2px 8px #000a; }}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="logo">
                <img src="https://i.imgur.com/S3FBo0I.png" alt="Themis">
                Themis
            </div>
            <div class="nav-links">
                <a href="/admin/dashboard" class="admin-btn active">Dashboard</a>
                <a href="/admin/cases" class="admin-btn">Cases</a>
                <a href="/" class="admin-btn">← Home</a>
            </div>
        </div>
        <div class="user-info-box">
            <div class="user-avatar">{f'<img src="{user.get('avatar_url')}" alt="Avatar">' if user.get('avatar_url') else user.get('username', 'U')[0].upper()}</div>
            <div class="user-details">
                <div class="user-name">{user.get('username', 'User')}</div>
                <div class="user-rank">{staff_rank}</div>
            </div>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>
        <div class="main-content">
            <h1 class="dashboard-title">Welcome back, <span class="username-highlight">{user.get('username', 'User')}</span></h1>
            <p class="dashboard-subtitle">Access moderation tools, review cases, and manage your Themis administration system.</p>
            <div class="quick-links">
                <a href="/admin/cases" class="nav-card">
                    <img class="icon-img" src="https://cdn.discordapp.com/attachments/1346136182379122798/1391910863832875018/discotools-xyz-icon_4.png?ex=686d9d82&is=686c4c02&hm=9c63e6b8dd489969258c4e84681ea446be3efe786f2fa434c02fd48c064d4948&" alt="View Cases">
                    <h3>View Cases</h3>
                    <p>Review, manage, and log moderation actions.</p>
                </a>
            </div>
        </div>
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
    connection = get_db_connection()
    cases = []
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            query = '''
                SELECT reference_id, user_id, punishment_type, reason, appealed, length
                FROM discord
                WHERE punishment_type IS NOT NULL AND punishment_type != ''
                ORDER BY reference_id DESC
                LIMIT 100
            '''
            cursor.execute(query)
            for row in cursor.fetchall():
                cases.append({
                    'id': row['reference_id'],
                    'user_id': row['user_id'],
                    'type': row['punishment_type'],
                    'reason': row['reason'],
                    'status': 'Appealed' if row['appealed'] == 1 else 'Active',
                    'length': row['length'] if row['length'] else 'N/A'
                })
            cursor.close()
        except Exception as e:
            print('Error in /admin/cases:', e)
            cases = []
        finally:
            connection.close()
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
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            body {{ font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.5; color: #ffffff; background: #0a0a0a; overflow-x: hidden; }}
            .sidebar {{ position: fixed; top: 0; left: 0; width: 220px; height: 100vh; background: rgba(20,20,30,0.92); border-right: 1.5px solid #a977f8; display: flex; flex-direction: column; z-index: 1000; box-shadow: 2px 0 16px #a977f81a; }}
            .sidebar .logo {{ font-size: 1.5rem; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 0.75rem; letter-spacing: -0.02em; padding: 2rem 1.5rem 1.2rem 1.5rem; }}
            .sidebar .logo img {{ width: 32px; height: 32px; border-radius: 8px; }}
            .sidebar .nav-links {{ display: flex; flex-direction: column; gap: 0.5rem; margin-top: 1.5rem; }}
            .sidebar .admin-btn {{ background: rgba(255,255,255,0.06); color: #fff; padding: 0.7rem 1.2rem; border: 1px solid rgba(255,255,255,0.12); border-radius: 8px; text-decoration: none; transition: all 0.2s; font-weight: 500; font-size: 1rem; margin: 0 1.2rem; display: flex; align-items: center; gap: 0.7rem; cursor: pointer; }}
            .sidebar .admin-btn.active, .sidebar .admin-btn:hover {{ background: rgba(169,119,248,0.13); border-color: #a977f8; color: #fff; }}
            .main-content {{ margin-left: 220px; max-width: 1200px; padding: 2.5rem 2rem 2rem 2rem; min-height: 100vh; transition: all 0.25s; }}
            .user-info-box {{ position: fixed; top: 1.5rem; right: 2.5rem; z-index: 1100; display: flex; align-items: center; gap: 1rem; background: rgba(255,255,255,0.07); border: 1.5px solid #a977f8; border-radius: 8px; box-shadow: 0 0 12px #a977f84d; padding: 0.6rem 1.2rem 0.6rem 0.8rem; }}
            .user-avatar {{ width: 36px; height: 36px; border-radius: 50%; background: #a977f8; display: flex; align-items: center; justify-content: center; font-size: 16px; font-weight: 700; overflow: hidden; }}
            .user-avatar img {{ width: 100%; height: 100%; object-fit: cover; }}
            .user-details {{ display: flex; flex-direction: column; align-items: flex-start; }}
            .user-name {{ color: #fff; font-weight: 600; line-height: 1.2; font-size: 1.08rem; }}
            .user-rank {{ font-size: 12px; text-transform: capitalize; line-height: 1; font-weight: 600; color: {rank_color}; }}
            .logout-btn {{ background: rgba(255,255,255,0.10); color: #fff; border: 1px solid #a977f8; border-radius: 6px; padding: 0.4rem 1rem; font-size: 0.95rem; font-weight: 500; margin-left: 0.7rem; cursor: pointer; transition: background 0.2s; }}
            .logout-btn:hover {{ background: #a977f8; color: #fff; }}
            .cases-header {{ display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem; margin-top: 0.5rem; gap: 1.2rem; flex-wrap: wrap; }}
            .cases-title {{ font-size: 2.5rem; font-weight: 700; letter-spacing: -0.03em; background: linear-gradient(135deg, #fff 0%, #a0a0a0 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }}
            .create-log-btn {{ background: #a977f8; color: #fff; border: none; border-radius: 8px; padding: 0.7rem 1.5rem; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background 0.2s; box-shadow: 0 2px 8px #a977f84d; }}
            .create-log-btn:hover {{ background: #9966e6; }}
            .cases-table {{ background: rgba(169, 119, 248, 0.05); border: 1px solid rgba(169, 119, 248, 0.2); border-radius: 12px; overflow: hidden; margin-bottom: 2rem; box-shadow: 0 2px 8px #a977f81a; }}
            .cases-table table {{ width: 100%; border-collapse: collapse; }}
            .cases-table th, .cases-table td {{ padding: 1rem; text-align: left; border-bottom: 1px solid #23232b; word-break: break-word; }}
            .cases-table th {{ background: rgba(169, 119, 248, 0.10); font-weight: 600; color: #fff; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; }}
            .cases-table td {{ color: #a0a0a0; font-size: 0.98rem; }}
            .type-badge {{ display: inline-block; padding: 0.3em 0.8em; border-radius: 6px; font-weight: 600; font-size: 0.95em; color: #18181b; margin-right: 0.2em; white-space: nowrap; }}
            .action-link {{ color: #a977f8; text-decoration: none; cursor: pointer; font-weight: 500; border-radius: 5px; padding: 0.1em 0.5em; transition: background 0.18s, color 0.18s; outline: none; }}
            .action-link:hover, .action-link:focus {{ color: #fff; background: #a977f8; text-decoration: none; outline: none; }}
            .logout-btn, .logout-btn:visited, .logout-btn:active {{ text-decoration: none !important; }}
            /* Modal Styles */
            .modal {{ display: none; position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(0,0,0,0.7); align-items: center; justify-content: center; z-index: 2000; outline: none; }}
            .modal[aria-modal="true"] {{ display: flex; }}
            .modal-content {{ background: rgba(35,35,43,0.98); border-radius: 16px; padding: 2.5rem 2rem 2rem 2rem; min-width: 340px; max-width: 95vw; box-shadow: 0 8px 32px #a977f826; position: relative; border: 1.5px solid #a977f8; outline: none; transition: all 0.2s; }}
            .close-modal {{ position: absolute; top: 1.2rem; right: 1.5rem; font-size: 2.2rem; color: #a0a0a0; cursor: pointer; font-weight: 700; transition: color 0.2s; background: none; border: none; }}
            .close-modal:hover, .close-modal:focus {{ color: #fff; outline: none; }}
            .modal-title {{ font-size: 1.4rem; font-weight: 700; margin-bottom: 1.5rem; color: #fff; text-align: center; letter-spacing: -0.01em; }}
            .form-group {{ margin-bottom: 1.3rem; }}
            .form-group label {{ display: block; margin-bottom: 0.5rem; color: #fff; font-weight: 500; }}
            .form-group input, .form-group select, .form-group textarea {{ width: 100%; padding: 0.7rem; border-radius: 8px; border: 1px solid #a977f8; background: #18181b; color: #fff; font-size: 1rem; font-family: inherit; transition: border 0.2s; }}
            .form-group input:focus, .form-group select:focus, .form-group textarea:focus {{ border-color: #fff; outline: none; }}
            .form-group textarea {{ min-height: 70px; resize: vertical; }}
            .submit-btn {{ background: linear-gradient(90deg, #a977f8 0%, #7c3aed 100%); color: #fff; border: none; border-radius: 8px; padding: 0.8rem 2rem; font-size: 1.1rem; font-weight: 700; cursor: pointer; transition: background 0.2s; box-shadow: 0 2px 8px #a977f84d; margin-top: 0.5rem; width: 100%; }}
            .submit-btn:hover {{ background: linear-gradient(90deg, #7c3aed 0%, #a977f8 100%); }}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <div class="logo">
                <img src="https://i.imgur.com/S3FBo0I.png" alt="Themis">
                Themis
            </div>
            <div class="nav-links">
                <a href="/admin/dashboard" class="admin-btn">Dashboard</a>
                <a href="/admin/cases" class="admin-btn active">Cases</a>
                <a href="/" class="admin-btn">← Home</a>
            </div>
        </div>
        <div class="user-info-box">
            <div class="user-avatar">{f'<img src="{user.get('avatar_url')}" alt="Avatar">' if user.get('avatar_url') else user.get('username', 'U')[0].upper()}</div>
            <div class="user-details">
                <div class="user-name">{user.get('username', 'User')}</div>
                <div class="user-rank">{staff_rank}</div>
            </div>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>
        <div class="main-content">
            <div class="cases-header">
                <h2 class="cases-title">Cases</h2>
                <button class="create-log-btn" onclick="openModlogModal()"><i class="fa fa-plus"></i> Create Moderation Log</button>
            </div>
            <div class="cases-table">
                <table>
                    <thead>
                        <tr><th>ID</th><th>User ID</th><th>Type</th><th>Reason</th><th>Status</th><th>Length</th><th>Details</th></tr>
                    </thead>
                    <tbody>
                        {''.join(f'<tr><td>{c["id"]}</td><td>{c["user_id"]}</td><td><span class="type-badge" style="background:{get_type_color(c["type"])}">{c["type"] or "-"}</span></td><td>{c["reason"]}</td><td>{c["status"]}</td><td>{c["length"]}</td><td><span class="action-link" tabindex="0" onclick="viewCaseDetail(\'{c["id"]}\')">View</span></td></tr>' for c in cases)}
                    </tbody>
                </table>
            </div>
            <!-- Moderation Log Modal -->
            <div id="modlog-modal" class="modal" role="dialog" aria-modal="true" aria-labelledby="modlog-modal-title" tabindex="-1">
                <div class="modal-content">
                    <button class="close-modal" onclick="closeModlogModal()" aria-label="Close modal">&times;</button>
                    <div class="modal-title" id="modlog-modal-title">Create Moderation Log</div>
                    <form id="modlog-form">
                        <div class="form-group">
                            <label for="modlog-case-id">Case ID (optional, for updating existing case)</label>
                            <input type="text" id="modlog-case-id" name="case_id" placeholder="Enter Case ID or leave blank for new">
                        </div>
                        <div class="form-group">
                            <label for="modlog-type">Type</label>
                            <select id="modlog-type" name="type" required>
                                <option value="ban">Ban</option>
                                <option value="kick">Kick</option>
                                <option value="mute">Mute</option>
                                <option value="warn">Warn</option>
                            </select>
                        </div>
                        <div class="form-group">
                            <label for="modlog-reason">Reason</label>
                            <textarea id="modlog-reason" name="reason" required placeholder="Enter reason for moderation action..."></textarea>
                        </div>
                        <div class="form-group">
                            <label for="modlog-details">Details (optional)</label>
                            <textarea id="modlog-details" name="details" placeholder="Additional details, evidence, etc."></textarea>
                        </div>
                        <button type="submit" class="submit-btn">Submit Moderation Log</button>
                    </form>
                </div>
            </div>
            <script>
                // Accessibility: trap focus in modal
                function trapFocus(modal) {{
                    var focusableEls = modal.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
                    var first = focusableEls[0];
                    var last = focusableEls[focusableEls.length - 1];
                    modal.addEventListener('keydown', function(e) {{
                        if (e.key === 'Tab') {{
                            if (e.shiftKey) {{ if (document.activeElement === first) {{ e.preventDefault(); last.focus(); }} }}
                            else {{ if (document.activeElement === last) {{ e.preventDefault(); first.focus(); }} }}
                        }}
                        if (e.key === 'Escape') {{ closeModlogModal(); }}
                    }});
                }}
                // Expose punishment colors to JS
                const PUNISHMENT_COLORS = {punishment_colors_js};
                function get_type_color(ptype) {{
                    if (!ptype) {{ return PUNISHMENT_COLORS['default']; }}
                    var key = ptype.toLowerCase();
                    return PUNISHMENT_COLORS[key] || PUNISHMENT_COLORS['default'];
                }}
                // The following JS is inside a Python f-string. Linter: ignore 'document' not defined.
                function openModlogModal() {{
                    const modal = document.getElementById('modlog-modal');
                    modal.setAttribute('aria-modal', 'true');
                    modal.style.display = 'flex';
                    document.getElementById('modlog-form').reset();
                    setTimeout(() => {{
                        const firstInput = modal.querySelector('input, select, textarea, button');
                        if (firstInput) firstInput.focus();
                    }}, 100);
                    trapFocus(modal);
                }}
                function closeModlogModal() {{
                    const modal = document.getElementById('modlog-modal');
                    modal.removeAttribute('aria-modal');
                    modal.style.display = 'none';
                }}
                document.getElementById('modlog-form').onsubmit = async function(event) {{
                    event.preventDefault();
                    const caseId = document.getElementById('modlog-case-id').value;
                    const type = document.getElementById('modlog-type').value;
                    const reason = document.getElementById('modlog-reason').value;
                    const details = document.getElementById('modlog-details').value;
                    try {{
                        const resp = await fetch('/api/modlog/create', {{
                            method: 'POST',
                            headers: {{ 'Content-Type': 'application/json' }},
                            body: JSON.stringify({{ case_id: caseId, type, reason, details }})
                        }});
                        const data = await resp.json();
                        closeModlogModal();
                        if (resp.ok) {{
                            alert('Moderation log created!');
                        }} else {{
                            alert('Error: ' + (data.error || 'Failed to create log.'));
                        }}
                    }} catch (err) {{
                        closeModlogModal();
                        alert('Network error.');
                    }}
                }};
                window.onclick = function(event) {{
                    var modal = document.getElementById('modlog-modal');
                    if (event.target == modal) {{
                        closeModlogModal();
                    }}
                }};
                // View case detail (fetches from /api/case/discord/<case_id> and shows a modal with all info)
                function viewCaseDetail(caseId) {{
                    var url = '/api/case/discord/' + caseId;
                    fetch(url)
                        .then(function(res) {{ return res.json(); }})
                        .then(function(data) {{
                            if (data.error) {{
                                alert('Error: ' + data.error);
                                return;
                            }}
                            var html = "<div style='padding:1.5rem 1.2rem 0.5rem 1.2rem;max-width:480px;'>";
                            html += "<h2 style='font-size:1.3rem;font-weight:700;margin-bottom:1rem;'>Case #" + (data.reference_id || '') + "</h2>";
                            html += "<div style='margin-bottom:0.7rem;'><b>Punishment Type:</b> <span style='background:" + get_type_color(data.punishment_type) + ";color:#18181b;padding:0.2em 0.7em;border-radius:6px;font-weight:600;'>" + (data.punishment_type || '-') + "</span></div>";
                            html += "<div style='margin-bottom:0.7rem;'><b>Status:</b> " + (data.appealed == 1 ? 'Appealed' : 'Active') + "</div>";
                            html += "<div style='margin-bottom:0.7rem;'><b>Reason:</b> " + (data.reason || '-') + "</div>";
                            html += "<div style='margin-bottom:0.7rem;'><b>Length:</b> " + (data.length || '-') + "</div>";
                            html += "<div style='margin-bottom:0.7rem;'><b>Moderator Note:</b> " + (data.moderator_note || '-') + "</div>";
                            html += "<div style='margin-bottom:0.7rem;'><b>Discord User ID:</b> " + (data.user_id || '-') + "</div>";
                            html += "<div style='margin-bottom:0.7rem;'><b>Discord Username:</b> " + (data.discord_username || '-') + "</div>";
                            html += "<div style='margin-bottom:0.7rem;'><b>Roblox User ID:</b> " + (data.roblox_user_id || '-') + "</div>";
                            html += "<div style='margin-bottom:0.7rem;'><b>Roblox Username:</b> " + (data.roblox_username || '-') + "</div>";
                            if (data.evidence && Array.isArray(data.evidence) && data.evidence.length > 0) {{
                                html += "<div style='margin-bottom:0.7rem;'><b>Evidence:</b><ul style='margin:0.3em 0 0 1.2em;'>";
                                for (var i = 0; i < data.evidence.length; i++) {{
                                    var url = data.evidence[i];
                                    html += "<li><a href='" + url + "' target='_blank' style='color:#a977f8;'>" + url + "</a></li>";
                                }}
                                html += "</ul></div>";
                            }} else if (data.evidence) {{
                                html += "<div style='margin-bottom:0.7rem;'><b>Evidence:</b> " + data.evidence + "</div>";
                            }}
                            html += "</div>";
                            showCaseDetailModal(html);
                        }})
                        .catch(function() {{ alert('Failed to fetch case details.'); }});
                }}

                // Modal for case details
                function showCaseDetailModal(contentHtml) {{
                    let modal = document.getElementById('case-detail-modal');
                    let modalContent = document.getElementById('case-detail-modal-content');
                    if (!modal) {{
                        modal = document.createElement('div');
                        modal.id = 'case-detail-modal';
                        modal.className = 'modal';
                        modal.innerHTML = `<div class=\"modal-content\" id=\"case-detail-modal-content\"><span class=\"close-modal\" onclick=\"closeCaseDetailModal()\">&times;</span></div>`;
                        document.body.appendChild(modal);
                        modalContent = document.getElementById('case-detail-modal-content');
                    }}
                    modalContent.innerHTML = `<span class=\"close-modal\" onclick=\"closeCaseDetailModal()\">&times;</span>` + contentHtml;
                    modal.style.display = 'flex';
                }}
                function closeCaseDetailModal() {{
                    let modal = document.getElementById('case-detail-modal');
                    if (modal) modal.style.display = 'none';
                }}
            </script>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html)

# Move /api/modlog/create route OUTSIDE the HTML string and function
@app.route('/api/modlog/create', methods=['POST'])
@login_required
@staff_required
def create_modlog():
    """
    Create a moderation log entry in the discord table (as a new case).
    Accepts: case_id (reference_id), type, reason, details (moderator_note)
    """
    user = session.get('user', {})
    data = request.get_json()
    staff_id = user.get('id')
    staff_name = user.get('username', 'Unknown')
    case_id = data.get('case_id')
    log_type = data.get('type')
    reason = data.get('reason')
    details = data.get('details')
    if not all([case_id, log_type, reason]):
        return jsonify({'error': 'Missing required fields'}), 400
    try:
        connection = get_db_connection()
        if connection is None:
            return jsonify({'error': 'DB connection error'}), 500
        cursor = connection.cursor()
        # Check if the case exists
        cursor.execute("SELECT 1 FROM discord WHERE reference_id = %s", (case_id,))
        if not cursor.fetchone():
            cursor.close()
            connection.close()
            return jsonify({'error': 'Case not found'}), 404
        # Update the case in the discord table with the new log info
        update_query = """
            UPDATE discord
            SET punishment_type = %s, reason = %s, moderator_note = %s
            WHERE reference_id = %s
        """
        cursor.execute(update_query, (log_type, reason, details, case_id))
        connection.commit()
        cursor.close()
        connection.close()
        return jsonify({'message': 'Moderation log updated for case'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/case/<project>/<case_id>')
@login_required
@staff_required
def get_case_detail(project, case_id):
    print(f"Called for {case_id}")
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
        # Try to get user info from users table if possible
        discord_username = None
        roblox_user_id = None
        roblox_username = None
        if case and 'user_id' in case:
            # Discord username
            cursor.execute("SELECT discord_username, roblox_user_id, roblox_username FROM users WHERE discord_user_id = %s", (case['user_id'],))
            user_row = cursor.fetchone()
            if user_row:
                discord_username = user_row.get('discord_username')
                roblox_user_id = user_row.get('roblox_user_id')
                roblox_username = user_row.get('roblox_username')
        cursor.close()
        connection.close()
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        # Convert evidence field if it exists
        if case.get('evidence'):
            if isinstance(case['evidence'], str):
                case['evidence'] = [url.strip() for url in case['evidence'].split('\n') if url.strip()]
        # Add user info to response
        case['discord_username'] = discord_username
        case['roblox_user_id'] = roblox_user_id
        case['roblox_username'] = roblox_username
        return jsonify(case)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# For production, use a WSGI server (e.g. gunicorn/uwsgi) instead of Flask's built-in server.
if __name__ == '__main__':
    app.run(debug=False)
