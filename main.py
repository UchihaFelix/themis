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
            
            /* Dashboard content */
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
            
            /* Quick actions grid */
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
            
            /* Stats grid */
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
                    top: 12px;
                    right: 12px;
                    padding: 6px 8px;
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
        <div class="background-pattern"></div>
        
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
                fetch(`/api/case/discord/${caseId}`)
                    .then(res => res.json())
                    .then(data => {{
                        if (data.error) {{
                            detailsContainer.innerHTML = `<div style="color:red;">${{data.error}}</div>`;
                            return;
                        }}
                        const typeColor = punishmentColors[(data.punishment_type || '').toLowerCase()] || punishmentColors['default'];
                        // Evidence rendering: show images and videos inline, others as links
                        let evidenceHtml = '';
                        if (data.evidence && Array.isArray(data.evidence) && data.evidence.length) {{
                            evidenceHtml = `<div class="form-group"><label>Evidence</label><div style="display:flex;flex-direction:column;gap:12px;">` +
                                data.evidence.map(function(url) {{
                                    const ext = url.split('.').pop().toLowerCase().split('?')[0];
                                    if (["jpg","jpeg","png","gif","webp","bmp"].includes(ext)) {{
                                        return `<a href="${{url}}" target="_blank"><img src="${{url}}" alt="evidence" style="max-width:100%;max-height:220px;border-radius:8px;box-shadow:0 2px 8px #0002;"></a>`;
                                    }} else if (["mp4","webm","ogg","mov","m4v"].includes(ext)) {{
                                        return `<video controls style="max-width:100%;max-height:220px;border-radius:8px;box-shadow:0 2px 8px #0002;"><source src="${{url}}"></video>`;
                                    }} else {{
                                        return `<a href="${{url}}" target="_blank">${{url}}</a>`;
                                    }}
                                }}).join('') + `</div></div>`;
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
                        detailsContainer.innerHTML = `<div style="color:red;">Error loading case details.</div>`;
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

# Move /api/modlog/create route OUTSIDE the HTML string and function
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

# For production, use a WSGI server (e.g. gunicorn/uwsgi) instead of Flask's built-in server.
if __name__ == '__main__':
    app.run(debug=False)