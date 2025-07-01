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

app.permanent_session_lifetime = timedelta(days=30) # CHANGE IF NEEDED

# Initialize Flask app
app = Flask(__name__)
app.secret_key = "ehwodbwelenwkshyuxisid"

# Steve's one commit - cookies, just not as edible.
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
        
        cases_html += f'''
        <div class="case-item" data-id="{case.get('reference_id', case['user_id'])}" data-reference="{case.get('reference_id', case['user_id'])}">
            <div class="case-header">
                <div class="case-id">#{case.get('reference_id', case['user_id'])}</div>
                {appealed_badge}
            </div>
            <div class="case-meta">
                <div class="case-type">{case.get('punishment_type', 'Unknown')}</div>
                <div class="case-date">{created}</div>
            </div>
        </div>
        '''

    # Enhanced project selector
    project_selector = f'''
    <div class="project-selector">
        <label for="project">Project:</label>
        <select name="project" id="project" onchange="changeProject(this.value)">
            <option value="discord" {'selected' if project == 'discord' else ''}>Discord</option>
            <option value="roblox" {'selected' if project == 'roblox' else ''}>Roblox</option>
        </select>
    </div>
    '''

    html = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Themis Admin Panel - Case Management</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}

            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #0a0a0a 0%, #1a1a2e 50%, #16213e 100%);
                color: #ffffff;
                display: flex;
                height: 100vh;
                overflow: hidden;
            }}

            /* Sidebar Styles */
            #sidebar {{
                width: 380px;
                background: rgba(18, 18, 18, 0.95);
                backdrop-filter: blur(10px);
                border-right: 1px solid rgba(169, 119, 248, 0.2);
                display: flex;
                flex-direction: column;
                box-shadow: 2px 0 20px rgba(0, 0, 0, 0.5);
            }}

            .sidebar-header {{
                padding: 2rem 1.5rem 1rem;
                background: linear-gradient(135deg, #a977f8 0%, #5e3ce2 100%);
                border-bottom: 1px solid rgba(169, 119, 248, 0.3);
            }}

            .sidebar-header h1 {{
                font-size: 1.5rem;
                font-weight: 700;
                margin-bottom: 0.5rem;
                text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
            }}

            .sidebar-header .subtitle {{
                opacity: 0.9;
                font-size: 0.9rem;
            }}

            .project-selector {{
                padding: 1.5rem;
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            }}

            .project-selector label {{
                display: block;
                margin-bottom: 0.5rem;
                font-weight: 600;
                color: #a977f8;
            }}

            .project-selector select {{
                width: 100%;
                padding: 0.75rem;
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(169, 119, 248, 0.3);
                border-radius: 8px;
                color: white;
                font-size: 1rem;
                transition: all 0.3s ease;
            }}

            .project-selector select:focus {{
                outline: none;
                border-color: #a977f8;
                box-shadow: 0 0 0 3px rgba(169, 119, 248, 0.2);
            }}

            .search-bar {{
                padding: 0 1.5rem 1rem;
            }}

            .search-bar input {{
                width: 100%;
                padding: 0.75rem;
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 8px;
                color: white;
                font-size: 0.9rem;
                transition: all 0.3s ease;
            }}

            .search-bar input::placeholder {{
                color: rgba(255, 255, 255, 0.5);
            }}

            .search-bar input:focus {{
                outline: none;
                border-color: #a977f8;
                box-shadow: 0 0 0 3px rgba(169, 119, 248, 0.2);
            }}

            .filters {{
                padding: 0 1.5rem 1rem;
                display: flex;
                gap: 0.5rem;
                flex-wrap: wrap;
            }}

            .filter-btn {{
                padding: 0.4rem 0.8rem;
                background: rgba(255, 255, 255, 0.1);
                border: 1px solid rgba(255, 255, 255, 0.2);
                border-radius: 20px;
                color: white;
                font-size: 0.8rem;
                cursor: pointer;
                transition: all 0.3s ease;
            }}

            .filter-btn:hover, .filter-btn.active {{
                background: #a977f8;
                border-color: #a977f8;
            }}

            #caseList {{
                flex: 1;
                overflow-y: auto;
                padding: 0 1.5rem 1.5rem;
            }}

            .case-item {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 1rem;
                margin-bottom: 0.75rem;
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
                background: linear-gradient(90deg, #a977f8, #5e3ce2);
                transform: scaleX(0);
                transition: transform 0.3s ease;
            }}

            .case-item:hover {{
                background: rgba(169, 119, 248, 0.1);
                border-color: rgba(169, 119, 248, 0.3);
                transform: translateY(-2px);
                box-shadow: 0 4px 20px rgba(169, 119, 248, 0.2);
            }}

            .case-item:hover::before {{
                transform: scaleX(1);
            }}

            .case-item.selected {{
                background: rgba(169, 119, 248, 0.2);
                border-color: #a977f8;
                box-shadow: 0 0 0 2px rgba(169, 119, 248, 0.3);
            }}

            .case-item.selected::before {{
                transform: scaleX(1);
            }}

            .case-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 0.5rem;
            }}

            .case-id {{
                font-weight: 700;
                font-size: 1.1rem;
                color: #a977f8;
            }}

            .appealed-badge {{
                background: #e04e4e;
                color: white;
                padding: 0.2rem 0.5rem;
                border-radius: 12px;
                font-size: 0.7rem;
                font-weight: 600;
                text-transform: uppercase;
            }}

            .case-meta {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                font-size: 0.85rem;
                opacity: 0.8;
            }}

            .case-type {{
                background: rgba(255, 255, 255, 0.1);
                padding: 0.2rem 0.6rem;
                border-radius: 8px;
                font-weight: 500;
            }}

            .case-date {{
                color: rgba(255, 255, 255, 0.6);
            }}

            .logout-section {{
                padding: 1.5rem;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
                text-align: center;
            }}

            .logout-btn {{
                color: #e04e4e;
                text-decoration: none;
                font-weight: 600;
                padding: 0.5rem 1rem;
                border: 1px solid #e04e4e;
                border-radius: 8px;
                transition: all 0.3s ease;
                display: inline-block;
            }}

            .logout-btn:hover {{
                background: #e04e4e;
                color: white;
            }}

            /* Main Panel Styles */
            #detailPanel {{
                flex: 1;
                background: rgba(26, 26, 26, 0.95);
                backdrop-filter: blur(10px);
                padding: 2rem;
                overflow-y: auto;
                position: relative;
            }}

            .detail-header {{
                margin-bottom: 2rem;
                padding-bottom: 1rem;
                border-bottom: 2px solid rgba(169, 119, 248, 0.2);
            }}

            .detail-header h2 {{
                color: #a977f8;
                font-size: 2rem;
                font-weight: 700;
                margin-bottom: 0.5rem;
            }}

            .detail-header .case-status {{
                display: flex;
                gap: 1rem;
                align-items: center;
            }}

            .status-badge {{
                padding: 0.5rem 1rem;
                border-radius: 20px;
                font-size: 0.85rem;
                font-weight: 600;
                text-transform: uppercase;
            }}

            .status-badge.appealed {{
                background: rgba(224, 78, 78, 0.2);
                color: #e04e4e;
                border: 1px solid #e04e4e;
            }}

            .status-badge.active {{
                background: rgba(34, 197, 94, 0.2);
                color: #22c55e;
                border: 1px solid #22c55e;
            }}

            .detail-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 1.5rem;
                margin-bottom: 2rem;
            }}

            .detail-card {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 1.5rem;
                transition: all 0.3s ease;
            }}

            .detail-card:hover {{
                background: rgba(255, 255, 255, 0.08);
                border-color: rgba(169, 119, 248, 0.3);
            }}

            .detail-card h3 {{
                color: #a977f8;
                font-size: 1rem;
                font-weight: 600;
                margin-bottom: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}

            .detail-card p {{
                color: rgba(255, 255, 255, 0.9);
                line-height: 1.6;
                word-wrap: break-word;
            }}

            .evidence-list {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 1.5rem;
            }}

            .evidence-list h3 {{
                color: #a977f8;
                margin-bottom: 1rem;
                font-size: 1.1rem;
            }}

            .evidence-item {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                padding: 0.75rem;
                margin-bottom: 0.5rem;
                word-break: break-all;
            }}

            .evidence-item a {{
                color: #a977f8;
                text-decoration: none;
                transition: color 0.3s ease;
            }}

            .evidence-item a:hover {{
                color: #5e3ce2;
                text-decoration: underline;
            }}

            .empty-state {{
                text-align: center;
                padding: 4rem 2rem;
                color: rgba(255, 255, 255, 0.6);
            }}

            .empty-state h3 {{
                font-size: 1.5rem;
                margin-bottom: 1rem;
                color: #a977f8;
            }}

            /* Scrollbar Styling */
            #caseList::-webkit-scrollbar, #detailPanel::-webkit-scrollbar {{
                width: 8px;
            }}

            #caseList::-webkit-scrollbar-track, #detailPanel::-webkit-scrollbar-track {{
                background: rgba(255, 255, 255, 0.05);
                border-radius: 4px;
            }}

            #caseList::-webkit-scrollbar-thumb, #detailPanel::-webkit-scrollbar-thumb {{
                background: rgba(169, 119, 248, 0.5);
                border-radius: 4px;
                transition: background 0.3s ease;
            }}

            #caseList::-webkit-scrollbar-thumb:hover, #detailPanel::-webkit-scrollbar-thumb:hover {{
                background: rgba(169, 119, 248, 0.7);
            }}

            /* Loading Animation */
            .loading {{
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 2rem;
            }}

            .loading::after {{
                content: '';
                width: 20px;
                height: 20px;
                border: 2px solid rgba(169, 119, 248, 0.3);
                border-top: 2px solid #a977f8;
                border-radius: 50%;
                animation: spin 1s linear infinite;
            }}

            @keyframes spin {{
                0% {{ transform: rotate(0deg); }}
                100% {{ transform: rotate(360deg); }}
            }}

            /* Responsive Design */
            @media (max-width: 768px) {{
                body {{
                    flex-direction: column;
                }}

                #sidebar {{
                    width: 100%;
                    height: 50vh;
                }}

                #detailPanel {{
                    height: 50vh;
                }}

                .detail-grid {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <div id="sidebar">
            <div class="sidebar-header">
                <h1>Case Management</h1>
                <div class="subtitle">{project.capitalize()} Cases</div>
            </div>
            
            {project_selector}
            
            <div class="search-bar">
                <input type="text" id="searchInput" placeholder="Search cases..." oninput="filterCases()">
            </div>
            
            <div class="filters">
                <button class="filter-btn active" onclick="filterByType('all')">All</button>
                <button class="filter-btn" onclick="filterByType('ban')">Bans</button>
                <button class="filter-btn" onclick="filterByType('kick')">Kicks</button>
                <button class="filter-btn" onclick="filterByType('mute')">Mutes</button>
                <button class="filter-btn" onclick="filterByType('appealed')">Appealed</button>
            </div>
            
            <div id="caseList">
                {cases_html}
            </div>
            
            <div class="logout-section">
                <a href="/logout" class="logout-btn">Logout</a>
            </div>
        </div>
        
        <div id="detailPanel">
            <div class="empty-state">
                <h3>Select a Case</h3>
                <p>Choose a case from the sidebar to view detailed information including evidence, moderator notes, and case history.</p>
            </div>
        </div>

        <script>
            let selectedCaseId = null;
            let allCases = [];
            const currentProject = '{project}';

            // Store all cases for filtering
            document.querySelectorAll('.case-item').forEach(item => {{
                allCases.push({{
                    element: item,
                    id: item.dataset.id,
                    reference: item.dataset.reference,
                    type: item.querySelector('.case-type').textContent.toLowerCase(),
                    appealed: item.querySelector('.appealed-badge') !== null
                }});
            }});

            function changeProject(project) {{
                window.location.href = `/admin?project=${{project}}`;
            }}

            function filterCases() {{
                const searchTerm = document.getElementById('searchInput').value.toLowerCase();
                allCases.forEach(caseObj => {{
                    const matchesSearch = caseObj.reference.toLowerCase().includes(searchTerm) || 
                                        caseObj.id.toLowerCase().includes(searchTerm);
                    caseObj.element.style.display = matchesSearch ? 'block' : 'none';
                }});
            }}

            function filterByType(type) {{
                // Update filter buttons
                document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
                event.target.classList.add('active');

                allCases.forEach(caseObj => {{
                    let show = false;
                    switch(type) {{
                        case 'all':
                            show = true;
                            break;
                        case 'appealed':
                            show = caseObj.appealed;
                            break;
                        default:
                            show = caseObj.type.includes(type);
                    }}
                    caseObj.element.style.display = show ? 'block' : 'none';
                }});
            }}

            // Case selection handler
            document.getElementById('caseList').addEventListener('click', async (e) => {{
                const caseItem = e.target.closest('.case-item');
                if (!caseItem) return;

                const caseId = caseItem.dataset.reference;
                if (caseId === selectedCaseId) return;

                // Update selection
                document.querySelectorAll('.case-item.selected').forEach(el => el.classList.remove('selected'));
                caseItem.classList.add('selected');
                selectedCaseId = caseId;

                // Show loading state
                document.getElementById('detailPanel').innerHTML = '<div class="loading"></div>';

                try {{
                    const response = await fetch(`/api/case/${{currentProject}}/${{caseId}}`);
                    if (!response.ok) throw new Error('Failed to load case');
                    
                    const caseData = await response.json();
                    if (caseData.error) {{
                        throw new Error(caseData.error);
                    }}

                    displayCaseDetails(caseData);
                }} catch (error) {{
                    document.getElementById('detailPanel').innerHTML = `
                        <div class="empty-state">
                            <h3>Error Loading Case</h3>
                            <p>${{error.message}}</p>
                        </div>
                    `;
                }}
            }});

            function displayCaseDetails(caseData) {{
                const evidenceList = caseData.evidence && caseData.evidence.length > 0 ? 
    caseData.evidence.map(url => 
        `<div class="evidence-item"><a href="${{url.trim()}}" target="_blank">${{url.trim()}}</a></div>`
    ).join('') : '<p>No evidence provided</p>';

                const appealedStatus = caseData.appealed == 1 ? 
                    '<div class="status-badge appealed">Appealed</div>' : 
                    '<div class="status-badge active">Active</div>';

                document.getElementById('detailPanel').innerHTML = `
                    <div class="detail-header">
                        <h2>Case #${{caseData.reference_id || caseData.user_id}}</h2>
                        <div class="case-status">
                            ${{appealedStatus}}
                        </div>
                    </div>

                    <div class="detail-grid">
                        <div class="detail-card">
                            <h3>Case Information</h3>
                            <p><strong>User ID:</strong> ${{caseData.user_id}}</p>
                            <p><strong>Staff ID:</strong> ${{caseData.staff_id}}</p>
                            <p><strong>Created:</strong> ${{caseData.created_at}}</p>
                            <p><strong>Type:</strong> ${{caseData.punishment_type}}</p>
                            <p><strong>Length:</strong> ${{caseData.length || 'Permanent/N/A'}}</p>
                        </div>

                        <div class="detail-card">
                            <h3>Reason</h3>
                            <p>${{caseData.reason || 'No reason provided'}}</p>
                        </div>

                        <div class="detail-card">
                            <h3>Moderator Notes</h3>
                            <p>${{caseData.moderator_note || 'No notes provided'}}</p>
                        </div>
                    </div>

                    <div class="evidence-list">
                        <h3>Evidence</h3>
                        ${{evidenceList}}
                    </div>
                `;
            }}
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
