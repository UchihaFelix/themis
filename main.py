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

# Steve's one commit - cookies, just not as edible.
app.permanent_session_lifetime = timedelta(days=30) # CHANGE IF NEEDED
app.config['SESSION_COOKIE_NAME'] = 'fxs-sites'
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookie over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'     # Adjust as needed

# Discord OAuth2 Configuration
DISCORD_CLIENT_ID = "1389347057432662119"
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
    user = session['user']
    project = request.args.get('project', 'discord')

    def get_cases(proj):
        try:
            connection = get_db_connection()
            if connection is None:
                return []
            cursor = connection.cursor(dictionary=True)
            cursor.execute(f"SELECT * FROM {proj} ORDER BY created_at DESC")
            cases = cursor.fetchall()
            cursor.close()
            connection.close()
            return cases
        except Exception as e:
            print(f"Error fetching cases: {e}")
            return []

    cases = get_cases(project)
    
    # Convert cases to JavaScript-friendly format
    js_cases = []
    
    js_cases.append({
        'case_id': cases['user_id'],
        'type': cases['punishment_type', 'unknown'].lower(),
        'user_id': cases['user_id', 'Unknown'],
        'username': cases['username'],
        'reason': cases['reason', 'No reason provided'],
        'staff_id': cases['staff_id'],
        'date': str(cases['created_at'])[:16] if cases['created_at'] else 'Unknown',
        'appealed': cases['appealed'] == 1,
        'details': cases['details', ''],
        'evidence': evidence,
        'moderator_note': cases.get('moderator_note', '')
    })

    # Get staff rank for display
    staff_rank = user.get('staff_info', {}).get('role', 'Staff')

    html = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Studio Dashboard - Themis</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #21262d;
            --border-primary: #30363d;
            --border-secondary: #21262d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --text-muted: #656d76;
            --accent-purple: #A977F8;
            --accent-purple-muted: #9966E6;
            --accent-purple-bg: rgba(169, 119, 248, 0.15);
            --accent-purple-glow: rgba(169, 119, 248, 0.3);
            --shadow: rgba(0, 0, 0, 0.12);
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
        }}

        /* Header */
        .header {{
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--accent-purple);
            box-shadow: 0 1px 0 var(--accent-purple-glow);
            padding: 16px 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
        }}

        .header-left {{
            display: flex;
            align-items: center;
            gap: 16px;
        }}

        .breadcrumb {{
            color: var(--text-secondary);
            font-size: 14px;
        }}

        .breadcrumb a {{
            color: var(--accent-purple);
            text-decoration: none;
        }}

        .breadcrumb a:hover {{
            text-decoration: underline;
        }}

        .header-right {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}

        .user-info {{
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 8px 12px;
            background: var(--bg-tertiary);
            border: 1px solid var(--accent-purple);
            border-radius: 6px;
            font-size: 14px;
            box-shadow: 0 0 8px var(--accent-purple-glow);
        }}

        .user-avatar {{
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: var(--accent-purple);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 14px;
            font-weight: 600;
            overflow: hidden;
        }}

        .user-avatar img {{
            width: 100%;
            height: 100%;
            object-fit: cover;
        }}

        .user-details {{
            display: flex;
            flex-direction: column;
            align-items: flex-start;
        }}

        .user-name {{
            color: var(--text-primary);
            font-weight: 600;
            line-height: 1.2;
        }}

        .user-rank {{
            color: var(--accent-purple);
            font-size: 12px;
            text-transform: capitalize;
            line-height: 1;
        }}

        .btn {{
            padding: 6px 12px;
            border: 1px solid var(--accent-purple);
            border-radius: 6px;
            background: var(--bg-tertiary);
            color: var(--text-primary);
            text-decoration: none;
            font-size: 14px;
            cursor: pointer;
            transition: all 0.2s;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            box-shadow: 0 0 4px var(--accent-purple-glow);
        }}

        .btn:hover {{
            background: var(--accent-purple-bg);
            border-color: var(--accent-purple-muted);
            box-shadow: 0 0 12px var(--accent-purple-glow);
        }}

        /* Main Layout */
        .container {{
            max-width: 1280px;
            margin: 0 auto;
            padding: 24px;
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 24px;
            min-height: calc(100vh - 76px);
        }}

        /* Sidebar */
        .sidebar {{
            background: var(--bg-secondary);
            border: 1px solid var(--accent-purple);
            border-radius: 6px;
            height: fit-content;
            position: sticky;
            top: 100px;
            box-shadow: 0 0 8px var(--accent-purple-glow);
        }}

        .sidebar-header {{
            padding: 16px;
            border-bottom: 1px solid var(--accent-purple);
            box-shadow: 0 1px 0 var(--accent-purple-glow);
        }}

        .sidebar-title {{
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 4px;
        }}

        .sidebar-subtitle {{
            font-size: 14px;
            color: var(--text-secondary);
        }}

        .sidebar-section {{
            padding: 16px;
            border-bottom: 1px solid var(--accent-purple);
            box-shadow: 0 1px 0 var(--accent-purple-glow);
        }}

        .sidebar-section:last-child {{
            border-bottom: none;
            box-shadow: none;
        }}

        .section-label {{
            font-size: 12px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            margin-bottom: 8px;
            letter-spacing: 0.5px;
        }}

        .project-select {{
            width: 100%;
            padding: 6px 8px;
            background: var(--bg-primary);
            border: 1px solid var(--accent-purple);
            border-radius: 6px;
            color: var(--text-primary);
            font-size: 14px;
            margin-bottom: 12px;
        }}

        .project-select:focus {{
            outline: none;
            border-color: var(--accent-purple-muted);
            box-shadow: 0 0 0 3px var(--accent-purple-bg);
        }}

        .search-box {{
            position: relative;
            margin-bottom: 12px;
        }}

        .search-input {{
            width: 100%;
            padding: 6px 8px 6px 28px;
            background: var(--bg-primary);
            border: 1px solid var(--accent-purple);
            border-radius: 6px;
            color: var(--text-primary);
            font-size: 14px;
        }}

        .search-input:focus {{
            outline: none;
            border-color: var(--accent-purple-muted);
            box-shadow: 0 0 0 3px var(--accent-purple-bg);
        }}

        .search-icon {{
            position: absolute;
            left: 8px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            font-size: 12px;
        }}

        .filter-tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }}

        .filter-tag {{
            padding: 4px 8px;
            background: var(--bg-primary);
            border: 1px solid var(--accent-purple);
            border-radius: 12px;
            color: var(--text-secondary);
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s;
            text-transform: capitalize;
        }}

        .filter-tag:hover {{
            background: var(--bg-tertiary);
            border-color: var(--accent-purple-muted);
        }}

        .filter-tag.active {{
            background: var(--accent-purple-bg);
            border-color: var(--accent-purple);
            color: var(--accent-purple);
            box-shadow: 0 0 4px var(--accent-purple-glow);
        }}

        .cases-list {{
            max-height: 500px;
            overflow-y: auto;
        }}

        .cases-list::-webkit-scrollbar {{
            width: 6px;
        }}

        .cases-list::-webkit-scrollbar-track {{
            background: var(--bg-primary);
        }}

        .cases-list::-webkit-scrollbar-thumb {{
            background: var(--accent-purple);
            border-radius: 3px;
        }}

        .case-item {{
            padding: 12px 16px;
            border-bottom: 1px solid var(--border-secondary);
            cursor: pointer;
            transition: background 0.2s;
        }}

        .case-item:hover {{
            background: var(--bg-primary);
        }}

        .case-item.selected {{
            background: var(--accent-purple-bg);
            border-left: 3px solid var(--accent-purple);
            padding-left: 13px;
            box-shadow: 0 0 8px var(--accent-purple-glow);
        }}

        .case-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }}

        .case-id {{
            font-weight: 600;
            color: var(--text-primary);
            font-size: 14px;
        }}

        .appealed-badge {{
            background: var(--accent-purple);
            color: white;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .case-type {{
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 4px;
        }}

        .case-type-ban {{ background: #da3633; color: white; }}
        .case-type-kick {{ background: #fb8500; color: white; }}
        .case-type-mute {{ background: #7c3aed; color: white; }}
        .case-type-warn {{ background: #fbbf24; color: black; }}
        .case-type-warning {{ background: #fbbf24; color: black; }}

        .case-user {{
            font-size: 12px;
            color: var(--text-secondary);
            margin-bottom: 2px;
        }}

        .case-reason {{
            font-size: 12px;
            color: var(--text-primary);
            line-height: 1.3;
        }}

        .case-meta {{
            display: flex;
            justify-content: space-between;
            font-size: 11px;
            color: var(--text-muted);
            margin-top: 6px;
        }}

        /* Content Area */
        .content {{
            background: var(--bg-secondary);
            border: 1px solid var(--accent-purple);
            border-radius: 6px;
            padding: 24px;
            min-height: 600px;
            box-shadow: 0 0 8px var(--accent-purple-glow);
        }}

        .content-header {{
            margin-bottom: 24px;
            padding-bottom: 16px;
            border-bottom: 1px solid var(--accent-purple);
            box-shadow: 0 1px 0 var(--accent-purple-glow);
        }}

        .content-title {{
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 4px;
        }}

        .content-subtitle {{
            color: var(--text-secondary);
            font-size: 14px;
        }}

        .detail-section {{
            margin-bottom: 20px;
            background: var(--bg-primary);
            border: 1px solid var(--accent-purple);
            border-radius: 6px;
            padding: 16px;
        }}

        .detail-label {{
            font-size: 12px;
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            margin-bottom: 4px;
            letter-spacing: 0.5px;
        }}

        .detail-value {{
            color: var(--text-primary);
            font-size: 14px;
            word-break: break-word;
        }}

        /* Username formatting styles */
        .username-display {{
            font-size: 14px;
        }}

        .username-display .username {{
            font-weight: bold;
            color: var(--text-primary);
        }}

        .username-display .user-id {{
            color: var(--text-muted);
            font-weight: normal;
        }}

        .evidence-gallery {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 12px;
            margin-top: 8px;
        }}

        .evidence-item {{
            position: relative;
            border: 1px solid var(--accent-purple);
            border-radius: 6px;
            overflow: hidden;
            cursor: pointer;
            transition: all 0.2s;
        }}

        .evidence-item:hover {{
            border-color: var(--accent-purple-muted);
            box-shadow: 0 0 8px var(--accent-purple-glow);
        }}

        .evidence-item img {{
            width: 100%;
            height: 150px;
            object-fit: cover;
            display: block;
        }}

        .evidence-overlay {{
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            opacity: 0;
            transition: opacity 0.2s;
        }}

        .evidence-item:hover .evidence-overlay {{
            opacity: 1;
        }}

        .evidence-overlay i {{
            color: white;
            font-size: 24px;
        }}

        .modal {{
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.9);
        }}

        .modal-content {{
            position: relative;
            margin: auto;
            padding: 20px;
            max-width: 90%;
            max-height: 90%;
            top: 50%;
            transform: translateY(-50%);
        }}

        .modal-content img {{
            max-width: 100%;
            max-height: 100%;
            border-radius: 6px;
        }}

        .close {{
            position: absolute;
            top: 15px;
            right: 35px;
            color: #f1f1f1;
            font-size: 40px;
            font-weight: bold;
            cursor: pointer;
        }}

        .close:hover {{
            color: var(--accent-purple);
        }}

        .empty-state {{
            text-align: center;
            color: var(--text-secondary);
            padding: 60px 20px;
        }}

        .empty-state i {{
            font-size: 48px;
            color: var(--text-muted);
            margin-bottom: 16px;
        }}

        @media (max-width: 768px) {{
            .container {{
                grid-template-columns: 1fr;
                gap: 16px;
                padding: 16px;
            }}
            
            .sidebar {{
                position: relative;
                top: 0;
            }}
        }}
    </style>
</head>
<body>
    <header class="header">
        <div class="header-left">
            <div class="breadcrumb">
                <a href="/admin">Dashboard</a> / Cases
            </div>
        </div>
        <div class="header-right">
            <div class="user-info">
                <div class="user-avatar">
                    {f'<img src="{user.get("avatar_url")}" alt="Avatar">' if user.get("avatar_url") else user.get('username', 'U')[0].upper()}
                </div>
                <div class="user-details">
                    <div class="user-name">{user.get('username', 'User')}</div>
                    <div class="user-rank">{staff_rank}</div>
                </div>
            </div>
            <a href="/logout" class="btn">
                <i class="fas fa-sign-out-alt"></i>
                Logout
            </a>
        </div>
    </header>

    <div class="container">
        <aside class="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-title">Case Management</div>
                <div class="sidebar-subtitle">Review and manage user cases</div>
            </div>
            
            <div class="sidebar-section">
                <div class="section-label">Project</div>
                <select class="project-select" id="project-selector">
                    <option value="discord" {'selected' if project == 'discord' else ''}>Discord Bot</option>
                    <option value="roblox" {'selected' if project == 'roblox' else ''}>Roblox Game</option>
                </select>
            </div>

            <div class="sidebar-section">
                <div class="section-label">Search & Filter</div>
                <div class="search-box">
                    <i class="fas fa-search search-icon"></i>
                    <input type="text" class="search-input" id="search-input" placeholder="Search cases...">
                </div>
                <div class="filter-tags">
                    <div class="filter-tag active" data-type="all">All</div>
                    <div class="filter-tag" data-type="ban">Ban</div>
                    <div class="filter-tag" data-type="kick">Kick</div>
                    <div class="filter-tag" data-type="mute">Mute</div>
                    <div class="filter-tag" data-type="warn">Warn</div>
                    <div class="filter-tag" data-type="warning">Warning</div>
                </div>
            </div>

            <div class="sidebar-section">
                <div class="section-label">Cases</div>
                <div class="cases-list" id="cases-list">
                    <!-- Cases will be populated by JavaScript -->
                </div>
            </div>
        </aside>

        <main class="content">
            <div class="content-header">
                <div class="content-title">Case Details</div>
                <div class="content-subtitle">Select a case from the sidebar to view details</div>
            </div>
            
            <div id="case-details">
                <div class="empty-state">
                    <i class="fas fa-folder-open"></i>
                    <div>No case selected</div>
                </div>
            </div>
        </main>
    </div>

    <!-- Evidence Modal -->
    <div id="evidence-modal" class="modal">
        <span class="close">&times;</span>
        <div class="modal-content">
            <img id="modal-image" src="" alt="Evidence">
        </div>
    </div>

    <script>
        let casesData = {json.dumps(js_cases)};
        let filteredCases = casesData;
        let selectedCaseId = null;

        const casesList = document.getElementById('cases-list');
        const caseDetails = document.getElementById('case-details');
        const searchInput = document.getElementById('search-input');
        const filterTags = document.querySelectorAll('.filter-tag');
        const projectSelector = document.getElementById('project-selector');
        const modal = document.getElementById('evidence-modal');
        const modalImg = document.getElementById('modal-image');
        const closeModal = document.querySelector('.close');

        function formatUsername(username, userId) {{
            if (username && username !== 'Unknown User') {{
                return `<span class="username-display"><span class="username">${{username}}</span> <span class="user-id">(${{userId}})</span></span>`;
            }} else {{
                return `<span class="username-display"><span class="user-id">User: ${{userId}}</span></span>`;
            }}
        }}

        function renderCases() {{
            casesList.innerHTML = '';
            
            if (filteredCases.length === 0) {{
                casesList.innerHTML = '<div style="padding: 12px 16px; color: var(--text-muted); text-align: center;">No cases found</div>';
                return;
            }}

            filteredCases.forEach(caseData => {{
                const caseElement = document.createElement('div');
                caseElement.className = 'case-item';
                caseElement.dataset.caseId = caseData.case_id;
                
                if (selectedCaseId === caseData.case_id) {{
                    caseElement.classList.add('selected');
                }}

                const appealedBadge = caseData.appealed ? '<span class="appealed-badge">Appealed</span>' : '';
                const truncatedReason = caseData.reason.length > 60 ? caseData.reason.substring(0, 60) + '...' : caseData.reason;
                const userDisplay = caseData.username !== 'Unknown User' ? 
                    `${{caseData.username}} (${{caseData.user_id}})` : 
                    `User: ${{caseData.user}}`;

                caseElement.innerHTML = `
                    <div class="case-header">
                        <div class="case-id">#${{caseData.case_id}}</div>
                        ${{appealedBadge}}
                    </div>
                    <div class="case-type case-type-${{caseData.type}}">${{caseData.type}}</div>
                    <div class="case-user">${{userDisplay}}</div>
                    <div class="case-reason">${{truncatedReason}}</div>
                    <div class="case-meta">
                        <span>${{caseData.date}}</span>
                        <span>by ${{caseData.staff}}</span>
                    </div>
                `;

                caseElement.addEventListener('click', () => selectCase(caseData.case_id));
                casesList.appendChild(caseElement);
            }});
        }}

        function selectCase(caseId) {{
            selectedCaseId = caseId;
            const caseData = casesData.find(c => c.case_id === caseId);
            
            // Update selected state
            document.querySelectorAll('.case-item').forEach(item => {{
                item.classList.remove('selected');
            }});
            document.querySelector(`[data-case-id="${{caseId}}"]`)?.classList.add('selected');

            if (!caseData) {{
                caseDetails.innerHTML = '<div class="empty-state"><i class="fas fa-exclamation-triangle"></i><div>Case not found</div></div>';
                return;
            }}

            let evidenceHtml = '';
            if (caseData.evidence && caseData.evidence.length > 0) {{
                evidenceHtml = `
                <div class="detail-section">
                    <div class="detail-label">Evidence</div>
                    <div class="evidence-gallery">
                        ${{caseData.evidence.map(url => `
                            <div class="evidence-item" onclick="openModal('${{url}}')">
                                <img src="${{url}}" alt="Evidence" onerror="this.parentElement.innerHTML='<div style=\\'padding: 20px; text-align: center; color: var(--text-muted);\\'>Failed to load image</div>'">
                                <div class="evidence-overlay">
                                    <i class="fas fa-expand"></i>
                                </div>
                            </div>
                        `).join('')}}
                    </div>
                </div>
                `;
            }}

            caseDetails.innerHTML = `
                <div class="content-header">
                    <div class="content-title">Case #${{caseData.case_id}}</div>
                    <div class="content-subtitle">${{caseData.type.charAt(0).toUpperCase() + caseData.type.slice(1)}} case details</div>
                </div>
                
                <div class="detail-section">
                    <div class="detail-label">Case Type</div>
                    <div class="detail-value">
                        <span class="case-type case-type-${{caseData.type}}">${{caseData.type}}</span>
                        ${{caseData.appealed ? '<span class="appealed-badge" style="margin-left: 8px;">Appealed</span>' : ''}}
                    </div>
                </div>

                <div class="detail-section">
                    <div class="detail-label">Target User</div>
                    <div class="detail-value">${{formatUsername(caseData.username, caseData.user_id)}}</div>
                </div>

                <div class="detail-section">
                    <div class="detail-label">Reason</div>
                    <div class="detail-value">${{caseData.reason}}</div>
                </div>

                <div class="detail-section">
                    <div class="detail-label">Staff Member</div>
                    <div class="detail-value">${{caseData.staff}} (ID: ${{caseData.staff_id}})</div>
                </div>

                <div class="detail-section">
                    <div class="detail-label">Date & Time</div>
                    <div class="detail-value">${{caseData.date}}</div>
                </div>

                ${{caseData.moderator_note ? `
                <div class="detail-section">
                    <div class="detail-label">Moderator Notes</div>
                    <div class="detail-value">${{caseData.moderator_note}}</div>
                </div>
                ` : ''}}

                ${{evidenceHtml}}

                ${{caseData.details ? `
                <div class="detail-section">
                    <div class="detail-label">Additional Details</div>
                    <div class="detail-value">${{caseData.details}}</div>
                </div>
                ` : ''}}
            `;
        }}

        function openModal(imageUrl) {{
            modal.style.display = 'block';
            modalImg.src = imageUrl;
        }}

        function applyFilters() {{
            const searchTerm = searchInput.value.toLowerCase();
            const activeFilter = document.querySelector('.filter-tag.active').dataset.type;

            filteredCases = casesData.filter(caseData => {{
                const matchesSearch = !searchTerm || 
                    caseData.case_id.toString().includes(searchTerm) ||
                    caseData.user.toLowerCase().includes(searchTerm) ||
                    caseData.username.toLowerCase().includes(searchTerm) ||
caseData.reason.toLowerCase().includes(searchTerm) ||
                    caseData.staff.toLowerCase().includes(searchTerm);

                const matchesFilter = activeFilter === 'all' || 
                    caseData.type === activeFilter ||
                    (activeFilter === 'warning' && caseData.type === 'warn');

                return matchesSearch && matchesFilter;
            }});

            renderCases();
        }}

        // Event listeners
        searchInput.addEventListener('input', applyFilters);

        filterTags.forEach(tag => {{
            tag.addEventListener('click', () => {{
                filterTags.forEach(t => t.classList.remove('active'));
                tag.classList.add('active');
                applyFilters();
            }});
        }});

        projectSelector.addEventListener('change', () => {{
            window.location.href = `?project=${{projectSelector.value}}`;
        }});

        closeModal.addEventListener('click', () => {{
            modal.style.display = 'none';
        }});

        window.addEventListener('click', (event) => {{
            if (event.target === modal) {{
                modal.style.display = 'none';
            }}
        }});

        // Initialize
        renderCases();
    </script>
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
        if cases['evidence']:
            # If evidence is stored as a multi-line string, convert to list
            if isinstance(case['evidence'], str):
                case['evidence'] = [url.strip() for url in case['evidence'].split('\n') if url.strip()]
            
        return jsonify(case)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
