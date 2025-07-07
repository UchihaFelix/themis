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
RANK_COLORS = {
    'Executive Director': '#7c3aed',         # indigo purple
    'Administration Director': '#a11a1a',    # darker-red
    'Project Director': '#1e3a8a',           # dark blue
    'Community Director': '#166534',         # dark green
    'Administrator': '#b91c1c',              # darkish-red
    'Junior Administrator': '#ef4444',       # red
    'Senior Moderator': '#ea580c',           # dark orange
    'Moderator': '#f59e42',                  # orange
    'Trial Moderator': '#fde047',            # yellow
    'Senior Developer': '#1e40af',           # dark blue
    'Developer': '#3b82f6',                  # blue
    'Junior Developer': '#7dd3fc',           # pastel blue
    'Senior Coordinator': '#15803d',         # darkish green
    'Coordinator': '#22d3ee'                 # neon green
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

# For R2 file upload and proxy
import boto3
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from flask import Response

load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "ehwodbwelenwkshyuxisid"

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

from flask import redirect

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
    html = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Themis Admin Dashboard</title>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            body {{ background: #0a0a0a; color: #fff; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }}
            .sidebar {{ position: fixed; top: 0; left: 0; width: 220px; height: 100vh; background: #161b22; border-right: 1px solid #a977f8; display: flex; flex-direction: column; z-index: 100; }}
            .sidebar a {{ color: #fff; text-decoration: none; padding: 1.2rem 2rem; font-size: 1.1rem; border-left: 4px solid transparent; transition: background 0.2s, border-color 0.2s; }}
            .sidebar a.active, .sidebar a:hover {{ background: #23232b; border-left: 4px solid #a977f8; }}
            .main {{ margin-left: 220px; padding: 2rem; }}
            .dashboard-title {{ font-size: 2.5rem; font-weight: 700; margin-bottom: 0.5rem; background: linear-gradient(135deg, #fff 0%, #a0a0a0 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }}
            .dashboard-subtitle {{ color: #a0a0a0; font-size: 1.125rem; margin-bottom: 2rem; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin-bottom: 3rem; }}
            .stat-card {{ background: #18181b; border: 1px solid #23232b; border-radius: 12px; padding: 1.5rem; box-shadow: 0 2px 8px #a977f81a; }}
            .stat-card h3 {{ font-size: 0.875rem; font-weight: 500; color: #a0a0a0; margin-bottom: 0.5rem; text-transform: uppercase; letter-spacing: 0.05em; }}
            .stat-card .value {{ font-size: 2.25rem; font-weight: 700; color: #fff; margin-bottom: 0.5rem; }}
            .quick-links {{ display: flex; gap: 2rem; }}
            .nav-card {{ background: #23232b; border: 1px solid #a977f8; border-radius: 12px; padding: 2rem; text-decoration: none; color: inherit; transition: all 0.3s; cursor: pointer; display: flex; flex-direction: column; align-items: center; }}
            .nav-card:hover {{ background: #a977f81a; border-color: #a977f8; }}
            .nav-card .icon {{ font-size: 2rem; margin-bottom: 1rem; }}
            .user-info {{ display: flex; align-items: center; gap: 12px; background: #23232b; border: 1px solid #a977f8; border-radius: 6px; font-size: 14px; box-shadow: 0 0 8px #a977f84d; padding: 8px 12px; margin-bottom: 2rem; position: relative; }}
            .user-avatar {{ width: 32px; height: 32px; border-radius: 50%; background: #a977f8; display: flex; align-items: center; justify-content: center; font-size: 14px; font-weight: 600; overflow: hidden; }}
            .user-avatar img {{ width: 100%; height: 100%; object-fit: cover; }}
            .user-details {{ display: flex; flex-direction: column; align-items: flex-start; }}
            .user-name {{ color: #fff; font-weight: 600; line-height: 1.2; }}
            .user-rank {{ font-size: 12px; text-transform: capitalize; line-height: 1; font-weight: 600; margin-bottom: 2px; }}
            .fx-employee {{ font-size: 11px; color: #8b949e; opacity: 0.7; font-style: italic; }}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <a href="/admin/dashboard" class="active">Dashboard</a>
            <a href="/admin/cases">Cases</a>
            <a href="/">← Back to Home</a>
        </div>
        <div class="main">
            <div class="user-info">
                <div class="user-avatar">{f'<img src="{user.get('avatar_url')}" alt="Avatar">' if user.get('avatar_url') else user.get('username', 'U')[0].upper()}</div>
                <div class="user-details">
                    <div class="user-name">{user.get('username', 'User')}</div>
                    <div class="user-rank" style="color: {rank_color};">{staff_rank}</div>
                    <div class="fx-employee">fx-Studios Employee</div>
                </div>
            </div>
            <h1 class="dashboard-title">Admin Dashboard</h1>
            <p class="dashboard-subtitle">Monitor and manage your Themis administration system</p>
            <div class="stats-grid">
                <div class="stat-card">
                    <h3>Total Cases</h3>
                    <div class="value">--</div>
                </div>
                <div class="stat-card">
                    <h3>Open Cases</h3>
                    <div class="value">--</div>
                </div>
                <div class="stat-card">
                    <h3>Staff Members</h3>
                    <div class="value">--</div>
                </div>
            </div>
            <div class="quick-links">
                <a href="/admin/cases" class="nav-card">
                    <div class="icon">📂</div>
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
@staff_required
def admin_cases():
    user = session['user']
    staff_rank = user.get('staff_info', {}).get('role', 'Staff')
    rank_color = RANK_COLORS.get(staff_rank, '#a977f8')
    # Fetch cases from the discord table, join users for username
    connection = get_db_connection()
    cases = []
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            query = '''
                SELECT d.reference_id, d.user_id, d.punishment_type, d.reason, d.appealed, d.length, u.discord_username
                FROM discord d
                LEFT JOIN users u ON d.user_id = u.discord_user_id
                ORDER BY d.reference_id DESC
                LIMIT 100
            '''
            cursor.execute(query)
            for row in cursor.fetchall():
                cases.append({
                    'id': row['reference_id'],
                    'user': row['discord_username'] or row['user_id'],
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
    html = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Themis Admin Cases</title>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            body {{ background: #0a0a0a; color: #fff; font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; }}
            .sidebar {{ position: fixed; top: 0; left: 0; width: 220px; height: 100vh; background: #161b22; border-right: 1px solid #a977f8; display: flex; flex-direction: column; z-index: 100; }}
            .sidebar a {{ color: #fff; text-decoration: none; padding: 1.2rem 2rem; font-size: 1.1rem; border-left: 4px solid transparent; transition: background 0.2s, border-color 0.2s; }}
            .sidebar a.active, .sidebar a:hover {{ background: #23232b; border-left: 4px solid #a977f8; }}
            .main {{ margin-left: 220px; padding: 2rem; }}
            .user-info {{ display: flex; align-items: center; gap: 12px; background: #23232b; border: 1px solid #a977f8; border-radius: 6px; font-size: 14px; box-shadow: 0 0 8px #a977f84d; padding: 8px 12px; margin-bottom: 2rem; position: relative; }}
            .user-avatar {{ width: 32px; height: 32px; border-radius: 50%; background: #a977f8; display: flex; align-items: center; justify-content: center; font-size: 14px; font-weight: 600; overflow: hidden; }}
            .user-avatar img {{ width: 100%; height: 100%; object-fit: cover; }}
            .user-details {{ display: flex; flex-direction: column; align-items: flex-start; }}
            .user-name {{ color: #fff; font-weight: 600; line-height: 1.2; }}
            .user-rank {{ font-size: 12px; text-transform: capitalize; line-height: 1; font-weight: 600; margin-bottom: 2px; }}
            .fx-employee {{ font-size: 11px; color: #8b949e; opacity: 0.7; font-style: italic; }}
            .cases-title {{ font-size: 2rem; font-weight: 700; margin-bottom: 2rem; }}
            .cases-table {{ background: #18181b; border: 1px solid #23232b; border-radius: 12px; overflow: hidden; margin-bottom: 2rem; }}
            .cases-table table {{ width: 100%; border-collapse: collapse; }}
            .cases-table th, .cases-table td {{ padding: 1rem; text-align: left; border-bottom: 1px solid #23232b; }}
            .cases-table th {{ background: #23232b; font-weight: 600; color: #fff; font-size: 0.875rem; text-transform: uppercase; letter-spacing: 0.05em; }}
            .cases-table td {{ color: #a0a0a0; font-size: 0.9rem; }}
            .action-btn {{ background: #a977f8; color: #fff; border: none; border-radius: 6px; padding: 0.5rem 1rem; cursor: pointer; font-size: 1rem; transition: background 0.2s; }}
            .action-btn:hover {{ background: #9966e6; }}
            .modal {{ display: none; position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(0,0,0,0.7); align-items: center; justify-content: center; z-index: 2000; }}
            .modal-content {{ background: #18181b; border-radius: 12px; padding: 2rem; min-width: 320px; max-width: 90vw; box-shadow: 0 8px 32px #a977f826; position: relative; }}
            .close-modal {{ position: absolute; top: 1rem; right: 1rem; font-size: 2rem; color: #a0a0a0; cursor: pointer; }}
            .form-group {{ margin-bottom: 1.2rem; }}
            .form-group label {{ display: block; margin-bottom: 0.5rem; color: #fff; }}
            .form-group input, .form-group select, .form-group textarea {{ width: 100%; padding: 0.5rem; border-radius: 6px; border: 1px solid #333; background: #23232b; color: #fff; font-size: 1rem; }}
            .form-group textarea {{ min-height: 60px; }}
        </style>
    </head>
    <body>
        <div class="sidebar">
            <a href="/admin/dashboard">Dashboard</a>
            <a href="/admin/cases" class="active">Cases</a>
            <a href="/">← Back to Home</a>
        </div>
        <div class="main">
            <div class="user-info">
                <div class="user-avatar">{f'<img src="{user.get('avatar_url')}" alt="Avatar">' if user.get('avatar_url') else user.get('username', 'U')[0].upper()}</div>
                <div class="user-details">
                    <div class="user-name">{user.get('username', 'User')}</div>
                    <div class="user-rank" style="color: {rank_color};">{staff_rank}</div>
                    <div class="fx-employee">fx-Studios Employee</div>
                </div>
            </div>
            <h2 class="cases-title">Cases</h2>
            <div class="cases-table">
                <table>
                    <thead>
                        <tr><th>ID</th><th>User</th><th>Type</th><th>Reason</th><th>Status</th><th>Length</th><th>Actions</th></tr>
                    </thead>
                    <tbody>
                        {''.join(f'<tr><td>{c["id"]}</td><td>{c["user"]}</td><td>{c["type"]}</td><td>{c["reason"]}</td><td>{c["status"]}</td><td>{c["length"]}</td><td><button class="action-btn" onclick="openModlogModal({{{{c["id"]}}}})">Create Moderation Log</button></td></tr>' for c in cases)}
                    </tbody>
                </table>
            </div>
            <!-- Moderation Log Modal -->
            <div id="modlog-modal" class="modal">
                <div class="modal-content">
                    <span class="close-modal" onclick="closeModlogModal()">&times;</span>
                    <h2>Create Moderation Log</h2>
                    <form id="modlog-form">
                        <input type="hidden" id="modlog-case-id" name="case_id">
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
                            <textarea id="modlog-reason" name="reason" required></textarea>
                        </div>
                        <div class="form-group">
                            <label for="modlog-details">Details</label>
                            <textarea id="modlog-details" name="details"></textarea>
                        </div>
                        <button type="submit" class="action-btn">Submit Log</button>
                    </form>
                </div>
            </div>
            <script>
                function openModlogModal(caseId) {{
                document.getElementById('modlog-modal').style.display = 'flex';
                document.getElementById('modlog-case-id').value = caseId;
            }}
            function closeModlogModal() {{
                document.getElementById('modlog-modal').style.display = 'none';
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
@app.route('/api/modlog/create', methods=['POST'])
@login_required
@staff_required
def create_modlog():
    """
    Create a moderation log entry in the discord table (as a new case).
    Accepts: case_id (reference_id), type, reason, details (moderator_note)
    """
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
                window.onclick = function(event) {{
                    var modal = document.getElementById('modlog-modal');
                    if (event.target == modal) {{
                        closeModlogModal();
                    }}
                }};
            </script>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html)
    
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
        
        # Use reference_id in the WHERE clause
        cursor.execute(f"SELECT * FROM {project} WHERE reference_id = %s OR user_id = %s", (case_id, case_id))
        case = cursor.fetchone()
        
        cursor.close()
        connection.close()
        
        if not case:
            return jsonify({'error': 'Case not found'}), 404
            
        # Convert datetime to string for JSON serialization
        
        # Handle evidence field if it exists
        if case.get('evidence'):
            # If evidence is stored as a multi-line string, convert to list
            if isinstance(case['evidence'], str):
                case['evidence'] = [url.strip() for url in case['evidence'].split('\n') if url.strip()]
            
        return jsonify(case)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
