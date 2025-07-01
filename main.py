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
@app.route('/api/case/<project>/<int:case_id>')
@login_required
@staff_required
def api_case_detail(project, case_id):
    try:
        connection = get_db_connection()
        if connection is None:
            return jsonify({'error': 'DB connection error'}), 500
        cursor = connection.cursor(dictionary=True)
        cursor.execute(f"SELECT * FROM {project}_cases WHERE id = %s", (case_id,))
        case = cursor.fetchone()
        cursor.close()
        connection.close()
        if not case:
            return jsonify({'error': 'Case not found'}), 404
        # Convert datetime to string for JSON serialization
        case['created_at'] = case['created_at'].strftime('%Y-%m-%d %H:%M:%S') if case['created_at'] else ''
        return jsonify(case)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
            cursor.execute(f"SELECT id, reference_id, created_at FROM {proj}_cases ORDER BY created_at DESC")
            cases = cursor.fetchall()
            cursor.close()
            connection.close()
            return cases
        except Exception as e:
            print(f"Error fetching cases: {e}")
            return []

    cases = get_cases(project)

    cases_html = ""
    for case in cases:
        created = case['created_at'].strftime('%Y-%m-%d %H:%M') if case['created_at'] else ''
        cases_html += '''
        <div class="case-item" data-id="{id}">
            <strong>#{ref}</strong><br>
            <small>{created}</small>
        </div>
        '''.format(id=case['id'], ref=case['reference_id'], created=created)

    project_selector = '''
    <form id="projectForm" method="get" action="/admin">
        <label for="project">Select Project:</label><br>
        <select name="project" id="project" onchange="document.getElementById('projectForm').submit()">
            <option value="discord" {discord_selected}>Discord</option>
            <option value="roblox" {roblox_selected}>Roblox</option>
        </select>
    </form>
    '''.format(
        discord_selected='selected' if project == 'discord' else '',
        roblox_selected='selected' if project == 'roblox' else ''
    )

    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Themis Admin Panel - Cases</title>
        <style>
            body {{
                margin: 0; font-family: Arial, sans-serif; background: #0a0a0a; color: white;
                display: flex; height: 100vh; overflow: hidden;
            }}
            #sidebar {{
                width: 320px; background: #121212; padding: 1rem; box-sizing: border-box;
                display: flex; flex-direction: column;
            }}
            #sidebar h2 {{
                margin-top: 0; margin-bottom: 1rem; color: #a977f8;
            }}
            #projectSelector {{
                margin-bottom: 1rem;
            }}
            #caseList {{
                flex-grow: 1; overflow-y: auto; border-top: 1px solid #333; padding-top: 1rem;
            }}
            .case-item {{
                padding: 0.5rem 0.75rem; border-radius: 6px; cursor: pointer;
                border: 1px solid transparent;
                margin-bottom: 0.5rem;
                background: #1a1a1a;
                transition: background 0.2s, border-color 0.2s;
            }}
            .case-item:hover {{
                background: #2d1a5f;
                border-color: #a977f8;
            }}
            .case-item.selected {{
                background: #5e3ce2;
                border-color: #a977f8;
            }}
            #detailPanel {{
                flex-grow: 1; background: #1a1a1a; padding: 1.5rem; overflow-y: auto;
            }}
            #detailPanel h2 {{
                color: #a977f8;
                margin-top: 0;
            }}
            #detailPanel p {{
                margin: 0.25rem 0;
                white-space: pre-wrap;
            }}
            .label {{
                font-weight: bold; color: #999;
            }}
            #logout {{
                margin-top: auto; text-align: center;
            }}
            #logout a {{
                color: #e04e4e; text-decoration: none; font-weight: bold;
            }}
            #logout a:hover {{
                text-decoration: underline;
            }}
            /* Scrollbar styling */
            #caseList::-webkit-scrollbar, #detailPanel::-webkit-scrollbar {{
                width: 8px;
            }}
            #caseList::-webkit-scrollbar-thumb, #detailPanel::-webkit-scrollbar-thumb {{
                background-color: #444; border-radius: 4px;
            }}
        </style>
    </head>
    <body>
        <div id="sidebar">
            <h2>Cases - {project_name}</h2>
            <div id="projectSelector">
                {project_selector}
            </div>
            <div id="caseList">
                {cases_html}
            </div>
            <div id="logout">
                <a href="/logout">Logout</a>
            </div>
        </div>
        <div id="detailPanel">
            <h2>Select a case to view details</h2>
            <p>Case details will appear here when you select a case from the list.</p>
        </div>

        <script>
            const caseList = document.getElementById('caseList');
            const detailPanel = document.getElementById('detailPanel');
            let selectedCaseId = null;

            caseList.addEventListener('click', async e => {{
                const caseItem = e.target.closest('.case-item');
                if (!caseItem) return;
                const caseId = caseItem.dataset.id;
                if (caseId === selectedCaseId) return;

                // Clear previous selection highlight
                document.querySelectorAll('.case-item.selected').forEach(el => el.classList.remove('selected'));
                caseItem.classList.add('selected');
                selectedCaseId = caseId;

                detailPanel.innerHTML = '<p>Loading...</p>';
                try {{
                    const response = await fetch(`/api/case/{project}/` + caseId);
                    if (!response.ok) throw new Error('Failed to load case details');
                    const caseData = await response.json();
                    if (caseData.error) {{
                        detailPanel.innerHTML = `<p style="color: #e04e4e;">Error: ${{caseData.error}}</p>`;
                        return;
                    }}

                    detailPanel.innerHTML = `
                        <h2>Case #${{caseData.reference_id}}</h2>
                        <p><span class="label">Created At:</span> ${{caseData.created_at}}</p>
                        <p><span class="label">User ID:</span> ${{caseData.user_id}}</p>
                        <p><span class="label">Staff ID:</span> ${{caseData.staff_id}}</p>
                        <p><span class="label">Punishment Type:</span> ${{caseData.punishment_type}}</p>
                        <p><span class="label">Length:</span> ${{caseData.length || 'N/A'}}</p>
                        <p><span class="label">Reason:</span> ${{caseData.reason}}</p>
                        <p><span class="label">Appealed:</span> ${{caseData.appealed == 1 ? 'Yes' : 'No'}}</p>
                        <p><span class="label">Evidence:</span><br> ${{caseData.evidence ? caseData.evidence.replace(/\\n/g, '<br>') : 'None'}}</p>
                        <p><span class="label">Moderator Note:</span><br> ${{caseData.moderator_note ? caseData.moderator_note.replace(/\\n/g, '<br>') : 'None'}}</p>
                    `;
                }} catch(err) {{
                    detailPanel.innerHTML = `<p style="color: #e04e4e;">Error loading case details.</p>`;
                }}
            }});
        </script>
    </body>
    </html>
    '''.format(
        project=project,
        project_name=project.capitalize(),
        project_selector=project_selector,
        cases_html=cases_html
    )

    return render_template_string(html)

if __name__ == '__main__':
    app.run(debug=True)
