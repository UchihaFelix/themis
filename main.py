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

    # Build cases HTML with enhanced styling
    cases_html = ""
    for case in cases:
        created = str(case['created_at'])[:16] if case['created_at'] else ''
        appealed_badge = '<span class="appealed-badge">APPEALED</span>' if case.get('appealed') == 1 else ''
        
        # Determine punishment type color
        punishment_color = {
            'ban': '#ef4444',
            'kick': '#f59e0b', 
            'mute': '#8b5cf6',
            'warn': '#10b981'
        }.get(case.get('punishment_type', '').lower(), '#6b7280')
        
        cases_html += f'''
        <div class="case-item" data-id="{case.get('reference_id', case['user_id'])}" data-reference="{case.get('reference_id', case['user_id'])}" data-type="{case.get('punishment_type', '').lower()}">
            <div class="case-header">
                <div class="case-id">#{case.get('reference_id', case['user_id'])}</div>
                {appealed_badge}
            </div>
            <div class="case-body">
                <div class="case-type" style="background-color: {punishment_color}20; color: {punishment_color}; border: 1px solid {punishment_color}40;">
                    {case.get('punishment_type', 'Unknown')}
                </div>
                <div class="case-user">User: {case.get('user_id', 'Unknown')}</div>
                <div class="case-reason">{case.get('reason', 'No reason provided')[:50]}{'...' if len(case.get('reason', '')) > 50 else ''}</div>
            </div>
            <div class="case-footer">
                <div class="case-date">{created}</div>
                <div class="case-staff">by {case.get('staff_id', 'Unknown')}</div>
            </div>
        </div>
        '''

    # Enhanced project selector
    project_selector = f'''
    <div class="project-selector-container">
        <label for="project">Active Project:</label>
        <select name="project" id="project" onchange="changeProject(this.value)">
            <option value="discord" {'selected' if project == 'discord' else ''}>🎮 Discord</option>
            <option value="roblox" {'selected' if project == 'roblox' else ''}>🎯 Roblox</option>
        </select>
    </div>
    '''

    html = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Themis Admin Dashboard</title>
    <link
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"
        rel="stylesheet"
    />
    <style>
        :root {{
            --primary: #6366f1;
            --primary-dark: #4f46e5;
            --secondary: #8b5cf6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --dark: #111827;
            --dark-light: #1f2937;
            --dark-lighter: #374151;
            --text: #f9fafb;
            --text-muted: #9ca3af;
            --border: #374151;
            --card-bg: #1f2937;
            --glass: rgba(31, 41, 55, 0.8);
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'SF Pro Display', -apple-system, BlinkMacSystemFont,
                'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%);
            color: var(--text);
            min-height: 100vh;
            overflow-x: hidden;
        }}

        /* Navigation Header */
        .nav-header {{
            background: var(--glass);
            backdrop-filter: blur(20px);
            border-bottom: 1px solid var(--border);
            padding: 1rem 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
        }}

        .nav-left {{
            display: flex;
            align-items: center;
            gap: 1.5rem;
        }}

        .nav-logo {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.5rem;
            font-weight: 700;
            color: var(--primary);
        }}

        .nav-logo i {{
            font-size: 1.75rem;
        }}

        .breadcrumb {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: var(--text-muted);
            font-size: 0.9rem;
        }}

        .breadcrumb a {{
            color: var(--primary);
            text-decoration: none;
            transition: color 0.2s;
        }}

        .breadcrumb a:hover {{
            color: var(--primary-dark);
        }}

        .nav-right {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}

        .user-info {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.5rem 1rem;
            background: var(--card-bg);
            border-radius: 50px;
            border: 1px solid var(--border);
        }}

        .user-avatar {{
            width: 32px;
            height: 32px;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 0.9rem;
        }}

        .btn {{
            padding: 0.5rem 1rem;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.9rem;
        }}

        .btn-primary {{
            background: var(--primary);
            color: white;
        }}

        .btn-primary:hover {{
            background: var(--primary-dark);
            transform: translateY(-1px);
        }}

        .btn-danger {{
            background: var(--danger);
            color: white;
        }}

        .btn-danger:hover {{
            background: #dc2626;
            transform: translateY(-1px);
        }}

        .btn-ghost {{
            background: transparent;
            color: var(--text-muted);
            border: 1px solid var(--border);
        }}

        .btn-ghost:hover {{
            background: var(--card-bg);
            color: var(--text);
        }}

        /* Main Layout */
        .admin-container {{
            display: flex;
            min-height: calc(100vh - 80px);
            max-width: 1400px;
            margin: 2rem auto;
            gap: 2rem;
            padding: 0 2rem;
        }}

        /* Sidebar */
        .sidebar {{
            width: 400px;
            background: var(--glass);
            backdrop-filter: blur(20px);
            border: 1px solid var(--border);
            border-radius: 16px;
            overflow: hidden;
            height: fit-content;
            position: sticky;
            top: 100px;
        }}

        .sidebar-header {{
            padding: 2rem;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            text-align: center;
        }}

        .sidebar-header h2 {{
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
        }}

        .sidebar-header p {{
            opacity: 0.9;
            font-size: 0.9rem;
        }}

        .project-selector-container {{
            padding: 1.5rem;
            border-bottom: 1px solid var(--border);
        }}

        .project-selector-container label {{
            display: block;
            margin-bottom: 0.75rem;
            font-weight: 600;
            color: var(--primary);
        }}

        .project-selector-container select {{
            width: 100%;
            padding: 0.75rem;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 1rem;
            transition: all 0.2s;
        }}

        .project-selector-container select:focus {{
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
        }}

        .controls {{
            padding: 1.5rem;
            border-bottom: 1px solid var(--border);
        }}

        .search-container {{
            position: relative;
            margin-bottom: 1rem;
        }}

        .search-container input {{
            width: 100%;
            padding: 0.75rem 0.75rem 0.75rem 2.5rem;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 8px;
            color: var(--text);
            font-size: 0.9rem;
            transition: all 0.2s;
        }}

        .search-container input:focus {{
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
        }}

        .search-container i {{
            position: absolute;
            left: 0.75rem;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
        }}

        .filters {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
        }}

        .filter-tag {{
            padding: 0.4rem 0.8rem;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 20px;
            color: var(--text-muted);
            font-size: 0.8rem;
            cursor: pointer;
            transition: all 0.2s;
            text-transform: capitalize;
        }}

        .filter-tag:hover {{
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }}

        .filter-tag.active {{
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }}

        .cases-container {{
            max-height: 60vh;
            overflow-y: auto;
            scrollbar-width: thin;
            scrollbar-color: var(--primary) transparent;
        }}

        .cases-container::-webkit-scrollbar {{
            width: 6px;
        }}

        .cases-container::-webkit-scrollbar-track {{
            background: transparent;
        }}

        .cases-container::-webkit-scrollbar-thumb {{
            background: var(--primary);
            border-radius: 3px;
        }}

        .case-item {{
            margin: 1rem 1.5rem;
            background: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1rem;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}

        .case-item::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: linear-gradient(90deg, var(--primary), var(--secondary));
            transform: scaleX(0);
            transition: transform 0.3s ease;
        }}

        .case-item:hover {{
            background: rgba(99, 102, 241, 0.1);
            border-color: var(--primary);
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(99, 102, 241, 0.2);
        }}

        .case-item:hover::before {{
            transform: scaleX(1);
        }}

        .case-item.selected {{
            background: rgba(99, 102, 241, 0.15);
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.3);
        }}

        .case-item.selected::before {{
            transform: scaleX(1);
        }}

        .case-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }}

        .case-id {{
            font-weight: 700;
            font-size: 1.1rem;
            color: var(--primary);
        }}

        .appealed-badge {{
            background: var(--danger);
            color: white;
            padding: 0.25rem 0.5rem;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: 600;
            text-transform: uppercase;
            animation: pulse 2s infinite;
        }}

        @keyframes pulse {{
            0%, 100% {{ opacity: 1; }}
            50% {{ opacity: 0.7; }}
        }}

        .case-body {{
            margin-bottom: 0.75rem;
        }}

        .case-type {{
            display: inline-block;
            padding: 0.25rem 0.6rem;
            border-radius: 8px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            margin-bottom: 0.5rem;
        }}

        .case-user {{
            font-size: 0.9rem;
            color: var(--text-muted);
            margin-bottom: 0.25rem;
        }}

        .case-reason {{
            font-size: 0.85rem;
            color: var(--text);
            line-height: 1.4;
        }}

        .case-footer {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.8rem;
            color: var(--text-muted);
            padding-top: 0.5rem;
            border-top: 1px solid var(--border);
        }}

        /* Colors by type */
        .case-type-moderation {{
            background: #6b7280;
            color: #d1d5db;
        }}

        .case-type-ban {{
            background: var(--danger);
            color: white;
        }}

        .case-type-warning {{
            background: var(--warning);
            color: #78350f;
        }}

        .case-type-mute {{
            background: var(--secondary);
            color: white;
        }}

        .case-type-kick {{
            background: var(--primary);
            color: white;
        }}

        /* Case Details Section */
        .case-details {{
            flex-grow: 1;
            background: var(--glass);
            backdrop-filter: blur(20px);
            border-radius: 16px;
            padding: 2rem;
            display: flex;
            flex-direction: column;
            gap: 1rem;
            max-height: 60vh;
            overflow-y: auto;
            border: 1px solid var(--border);
        }}

        .case-details h3 {{
            margin-bottom: 1rem;
            font-weight: 700;
            color: var(--primary);
            font-size: 1.4rem;
        }}

        .case-details-section {{
            background: var(--card-bg);
            border-radius: 12px;
            padding: 1rem 1.5rem;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        }}

        .case-details-section h4 {{
            margin-bottom: 0.75rem;
            font-weight: 600;
            color: var(--secondary);
            font-size: 1.1rem;
        }}

        .case-details-section p {{
            font-size: 0.95rem;
            color: var(--text);
            white-space: pre-wrap;
        }}

        .case-details-section a {{
            color: var(--primary);
            text-decoration: none;
        }}

        .case-details-section a:hover {{
            text-decoration: underline;
        }}

        /* Scrollbar for details */
        .case-details::-webkit-scrollbar {{
            width: 8px;
        }}

        .case-details::-webkit-scrollbar-track {{
            background: transparent;
        }}

        .case-details::-webkit-scrollbar-thumb {{
            background: var(--primary);
            border-radius: 4px;
        }}

        /* Responsive */
        @media (max-width: 1150px) {{
            .admin-container {{
                flex-direction: column;
                padding: 1rem;
            }}

            .sidebar {{
                width: 100%;
                position: relative;
                top: auto;
                margin-bottom: 1rem;
                height: auto;
            }}

            .case-details {{
                max-height: none;
                height: auto;
            }}
        }}
    </style>
</head>
<body>
    <header class="nav-header">
        <div class="nav-left">
            <div class="nav-logo">
                <i class="fa-solid fa-gavel"></i>
                Themis Admin
            </div>
            <nav class="breadcrumb" aria-label="Breadcrumb">
                <a href="/admin" class="breadcrumb-home" aria-current="page">
                    <i class="fa-solid fa-house"></i> Admin
                </a>
                <span>&gt;</span>
                <a href="/admin/cases">Cases</a>
            </nav>
        </div>
        <div class="nav-right">
            <div class="user-info" title="{user.get('username')}#{user.get('discriminator')}">
                <div class="user-avatar">{user.get('username')[0].upper()}</div>
                <span>{user.get('username')}</span>
            </div>
            <form method="post" action="/admin/logout">
                <button type="submit" class="btn btn-ghost" aria-label="Logout">
                    <i class="fa-solid fa-right-from-bracket"></i>
                </button>
            </form>
        </div>
    </header>

    <main class="admin-container" role="main" aria-label="Admin Dashboard">
        <aside class="sidebar" role="complementary" aria-label="Project and Case Controls">
            <div class="sidebar-header">
                <h2>Case Manager</h2>
                <p>Manage and review user cases</p>
            </div>
            <div class="project-selector-container">
                <label for="project-select">Select Project</label>
                {project_selector}
            </div>
            <div class="controls">
                <div class="search-container">
                    <i class="fa-solid fa-magnifying-glass"></i>
                    <input
                        type="text"
                        id="search"
                        placeholder="Search cases..."
                        aria-label="Search cases"
                        autocomplete="off"
                    />
                </div>
                <div class="filters" role="group" aria-label="Filter Cases by Type">
                    <span class="filter-tag active" data-type="all" tabindex="0">All</span>
                    <span class="filter-tag" data-type="ban" tabindex="0">Ban</span>
                    <span class="filter-tag" data-type="warning" tabindex="0">Warning</span>
                    <span class="filter-tag" data-type="mute" tabindex="0">Mute</span>
                    <span class="filter-tag" data-type="kick" tabindex="0">Kick</span>
                    <span class="filter-tag" data-type="moderation" tabindex="0">Moderation</span>
                </div>
            </div>
            <div class="cases-container" id="cases-container" tabindex="0" aria-live="polite" aria-atomic="true">
                <!-- Cases will be dynamically inserted here -->
            </div>
        </aside>

        <section class="case-details" id="case-details" aria-live="polite" aria-atomic="true">
            <h3>Select a case to view details</h3>
            <p>No case selected.</p>
        </section>
    </main>

    <script>
        // JavaScript to handle case selection and filters
        let casesData = {cases_json};
        let selectedCaseId = null;

        const casesContainer = document.getElementById('cases-container');
        const caseDetails = document.getElementById('case-details');
        const filters = document.querySelectorAll('.filter-tag');
        const searchInput = document.getElementById('search');

        function renderCases(filterType = 'all', searchTerm = '') {{
            casesContainer.innerHTML = '';
            let filteredCases = casesData;

            if (filterType !== 'all') {{
                filteredCases = filteredCases.filter(c => c.type === filterType);
            }}

            if (searchTerm.trim() !== '') {{
                const lowerTerm = searchTerm.toLowerCase();
                filteredCases = filteredCases.filter(c =>
                    c.case_id.toString().includes(lowerTerm) ||
                    c.user.toLowerCase().includes(lowerTerm) ||
                    c.reason.toLowerCase().includes(lowerTerm)
                );
            }}

            if (filteredCases.length === 0) {{
                casesContainer.innerHTML = '<p style="padding:1rem; color:var(--text-muted);">No cases found.</p>';
                caseDetails.innerHTML = '<h3>No case selected</h3><p>Please select a case from the list.</p>';
                selectedCaseId = null;
                return;
            }}

            for (const c of filteredCases) {{
                const caseDiv = document.createElement('div');
                caseDiv.classList.add('case-item');
                caseDiv.dataset.caseId = c.case_id;
                if (c.case_id === selectedCaseId) {{
                    caseDiv.classList.add('selected');
                }}
                caseDiv.tabIndex = 0;
                caseDiv.setAttribute('role', 'button');
                caseDiv.setAttribute('aria-pressed', c.case_id === selectedCaseId ? 'true' : 'false');

                let appealedBadge = c.appealed ? '<span class="appealed-badge" title="This case has been appealed">Appealed</span>' : '';

                caseDiv.innerHTML = `
                    <div class="case-header">
                        <div class="case-id">#${{c.case_id}}</div>
                        ${{appealedBadge}}
                    </div>
                    <div class="case-body">
                        <div class="case-type case-type-${{c.type}}">${{c.type}}</div>
                        <div class="case-user">User: ${{c.user}}</div>
                        <div class="case-reason">${{c.reason.length > 100 ? c.reason.slice(0, 100) + '...' : c.reason}}</div>
                    </div>
                    <div class="case-footer">
                        <div>Date: ${{c.date}}</div>
                        <div>Staff: ${{c.staff}}</div>
                    </div>
                `;

                caseDiv.addEventListener('click', () => {{
                    selectCase(c.case_id);
                }});
                caseDiv.addEventListener('keypress', e => {{
                    if (e.key === 'Enter' || e.key === ' ') {{
                        e.preventDefault();
                        selectCase(c.case_id);
                    }}
                }});

                casesContainer.appendChild(caseDiv);
            }}
        }}

        function selectCase(caseId) {{
            selectedCaseId = caseId;

            const prevSelected = casesContainer.querySelector('.case-item.selected');
            if (prevSelected) {{
                prevSelected.classList.remove('selected');
                prevSelected.setAttribute('aria-pressed', 'false');
            }}

            const newSelected = casesContainer.querySelector(`.case-item[data-case-id="${{caseId}}"]`);
            if (newSelected) {{
                newSelected.classList.add('selected');
                newSelected.setAttribute('aria-pressed', 'true');
                newSelected.focus();
            }}

            const c = casesData.find(c => c.case_id === caseId);
            if (!c) {{
                caseDetails.innerHTML = '<h3>Case not found</h3>';
                return;
            }}

            caseDetails.innerHTML = `
                <h3>Case #${{c.case_id}}</h3>
                <div class="case-details-section">
                    <h4>Type</h4>
                    <p class="case-type case-type-${{c.type}}">${{c.type}}</p>
                </div>
                <div class="case-details-section">
                    <h4>User</h4>
                    <p>${{c.user}} (ID: ${{c.user_id}})</p>
                </div>
                <div class="case-details-section">
                    <h4>Reason</h4>
                    <p>${{c.reason}}</p>
                </div>
                <div class="case-details-section">
                    <h4>Staff</h4>
                    <p>${{c.staff}} (ID: ${{c.staff_id}})</p>
                </div>
                <div class="case-details-section">
                    <h4>Date</h4>
                    <p>${{c.date}}</p>
                </div>
                <div class="case-details-section">
                    <h4>Additional Details</h4>
                    <p>${{c.details || 'No additional details available.'}}</p>
                </div>
                ${{c.appealed ? '<div class="case-details-section"><h4>Appeal Status</h4><p>This case has been appealed.</p></div>' : ''}}
            `;
        }}

        filters.forEach(filter => {{
            filter.addEventListener('click', () => {{
                filters.forEach(f => f.classList.remove('active'));
                filter.classList.add('active');
                renderCases(filter.dataset.type, searchInput.value);
                selectedCaseId = null;
                caseDetails.innerHTML = '<h3>Select a case to view details</h3><p>No case selected.</p>';
            }});
            filter.addEventListener('keypress', e => {{
                if (e.key === 'Enter' || e.key === ' ') {{
                    e.preventDefault();
                    filter.click();
                }}
            }});
        }});

        searchInput.addEventListener('input', () => {{
            const activeFilter = document.querySelector('.filter-tag.active').dataset.type;
            renderCases(activeFilter, searchInput.value);
            selectedCaseId = null;
            caseDetails.innerHTML = '<h3>Select a case to view details</h3><p>No case selected.</p>';
        }});

        // Initial render
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
        if case.get('evidence'):
            # If evidence is stored as a multi-line string, convert to list
            if isinstance(case['evidence'], str):
                case['evidence'] = [url.strip() for url in case['evidence'].split('\n') if url.strip()]
            
        return jsonify(case)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
