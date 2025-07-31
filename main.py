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

import boto3 # type: ignore
from werkzeug.utils import secure_filename # type: ignore
from dotenv import load_dotenv # type: ignore
from flask import Response # type: ignore

load_dotenv()

# Secrets
DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = os.getenv('DISCORD_REDIRECT_URI')
DB_CONFIG = {
    'host': os.getenv('DB_HOST'),
    'user': os.getenv('DB_USER'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_DATABASE'),
    'port': int(os.getenv('DB_PORT', 3306))
}
BOT_OWNER_ID = os.getenv("BOT_OWNER_ID")
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
    'Senior Administrator' : 5,
    'Administrator': 6,
    'Junior Administrator': 7,
    'Senior Moderator': 8,
    'Moderator': 9,
    'Trial Moderator': 10,
    'Senior Developer': 11,
    'Developer': 12,
    'Junior Developer': 13,
    'Senior Coordinator': 14,
    'Coordinator': 15
}

# Rank color mapping for user info box
# Set the colours to match staff server role colours for consistency. (can't be bothered changing the colour names)
RANK_COLORS = {
    'Executive Director': "#480091ff",         # indigo purple
    'Administration Director': "#420f0f",    # darker-red
    'Project Director': "#002394B7",           # dark blue
    'Community Director': "#003113",  
    'Senior Administrator' : "#5A0000",       # dark green
    'Administrator': "#9e0000ff",              # darkish-red
    'Junior Administrator': "#ff00007f",       # red
    'Senior Moderator': "#992e22b3",           # dark orange
    'Moderator': "#ff8400c8",                  # orange
    'Trial Moderator': "#f2ffa7b0",            # yellow
    'Senior Developer': "#0003af",           # dark blue
    'Developer': "#3c46ff",                  # blue
    'Junior Developer': '#848cff',           # pastel blue
    'Senior Coordinator': '#006428',         # darkish green
    'Coordinator': "#2ecc71"                 # neon green
}

def create_group(group_name, created_by_discord_id, members):
    """
    Create a new group with members (using staff_members table)
    created_by_discord_id = Discord ID from session
    members = [{'user_id': '660419748894343168', 'role': 'Senior Coordinator'}, ...]
    """
    print(f"=== CREATE_GROUP FUNCTION ===")
    print(f"Group name: {group_name}")
    print(f"Created by Discord ID: {created_by_discord_id} (type: {type(created_by_discord_id)})")
    print(f"Members: {members}")
    
    connection = get_db_connection()
    if not connection:
        print("Error: Could not establish database connection")
        return None
        
    try:
        cursor = connection.cursor()
        
        # Convert Discord ID to integer for database storage
        try:
            creator_id_int = int(created_by_discord_id)
            print(f"Converted creator ID to int: {creator_id_int}")
        except ValueError:
            print(f"Error: Could not convert creator Discord ID to integer: {created_by_discord_id}")
            connection.close()
            return None
        
        # Verify all members exist in staff_members and convert their IDs
        validated_members = []
        for member in members:
            try:
                user_id_int = int(member['user_id'])
                
                # Check if member exists in staff_members table
                cursor.execute("SELECT user_id FROM staff_members WHERE user_id = %s", (user_id_int,))
                member_exists = cursor.fetchone()
                print(f"Member {user_id_int} exists in staff_members: {member_exists is not None}")
                
                if not member_exists:
                    print(f"Error: Member with user_id {user_id_int} not found in staff_members table")
                    connection.close()
                    return None
                
                validated_members.append({
                    'user_id': user_id_int,
                    'role': member['role']
                })
                
            except ValueError:
                print(f"Error: Could not convert member user_id to integer: {member['user_id']}")
                connection.close()
                return None
        
        # Create the group with integer Discord ID
        print("Creating group in coordination_groups table...")
        cursor.execute("""
            INSERT INTO coordination_groups (group_name, created_by)
            VALUES (%s, %s)
        """, (group_name, creator_id_int))
        
        # Get the group ID immediately after insertion
        group_id = cursor.lastrowid
        print(f"Group created with ID: {group_id}")
        
        # Verify the group was created
        if not group_id:
            print("Error: No group ID returned from insertion")
            connection.rollback()
            connection.close()
            return None
        
        # Add members to the group
        print("Adding members to group_members table...")
        for member in validated_members:
            print(f"Adding member: user_id={member['user_id']}, role={member['role']}")
            cursor.execute("""
                INSERT INTO group_members (group_id, user_id, role)
                VALUES (%s, %s, %s)
            """, (group_id, member['user_id'], member['role']))
        
        # Commit all changes
        connection.commit()
        print(f"Successfully created group {group_id} with {len(validated_members)} members")
        connection.close()
        return group_id
        
    except Error as e:
        connection.rollback()
        print(f"Database error creating group: {e}")
        connection.close()
        return None
    except Exception as e:
        connection.rollback()
        print(f"General error creating group: {e}")
        connection.close()
        return None

def get_director_groups(director_discord_id):
    """Get all groups created by a director (using Discord ID)"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("""
                SELECT g.*, 
                    (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count
                FROM coordination_groups g
                WHERE g.created_by = %s AND g.is_active = TRUE
                ORDER BY g.created_at DESC
            """, (director_discord_id,))
            
            groups = cursor.fetchall()
            
            # Get members for each group
            for group in groups:
                cursor.execute("""
                    SELECT gm.*, 
                           gm.user_id as username,
                           gm.user_id as user_id_alias
                    FROM group_members gm
                    WHERE gm.group_id = %s
                    ORDER BY gm.role DESC, gm.user_id
                """, (group['id'],))
                group['members'] = cursor.fetchall()
            
            return groups
        except Error as e:
            print(f"Error fetching groups: {e}")
            return []
        finally:
            cursor.close()
            connection.close()
    return []

def update_coordinator_label(group_id, coordinator_id, label, updated_by):
    """Update a coordinator's role label (by Senior Coordinator)"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            
            # Verify the updater is a Senior Coordinator in the same group
            cursor.execute("""
                SELECT role FROM group_members 
                WHERE group_id = %s AND user_id = %s AND role = 'Senior Coordinator'
            """, (group_id, updated_by))
            
            if cursor.fetchone():
                cursor.execute("""
                    UPDATE group_members 
                    SET role_label = %s 
                    WHERE group_id = %s AND user_id = %s
                """, (label, group_id, coordinator_id))
                connection.commit()
                return True
            return False
        except Error as e:
            print(f"Error updating label: {e}")
            return False
        finally:
            cursor.close()
            connection.close()
    return False


def get_team_members_by_rank_fixed():
    """Get all coordinators and senior coordinators from staff_members table only"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("""
                SELECT 
                    s.user_id as id,
                    s.user_id as username,
                    s.rank as role
                FROM staff_members s
                WHERE s.rank IN ('Senior Coordinator', 'Coordinator')
                ORDER BY 
                    CASE s.rank 
                        WHEN 'Senior Coordinator' THEN 1 
                        WHEN 'Coordinator' THEN 2 
                    END,
                    s.user_id
            """)
            return cursor.fetchall()
        except Error as e:
            print(f"Error fetching team members: {e}")
            return []
        finally:
            cursor.close()
            connection.close()
    return []

def get_coordinator_team(senior_coordinator_id):
    """Get the team members under a Senior Coordinator (using staff_members table)"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            
            # First get the group(s) where this user is a Senior Coordinator
            cursor.execute("""
                SELECT DISTINCT g.id, g.group_name
                FROM coordination_groups g
                JOIN group_members gm ON g.id = gm.group_id
                WHERE gm.user_id = %s AND gm.role = 'Senior Coordinator'
                AND g.is_active = TRUE
            """, (senior_coordinator_id,))
            
            groups = cursor.fetchall()
            
            # Get coordinators in these groups
            coordinators = []
            for group in groups:
                cursor.execute("""
                    SELECT gm.*, 
                           gm.user_id as username,
                           gm.user_id as user_id_alias
                    FROM group_members gm
                    WHERE gm.group_id = %s AND gm.role = 'Coordinator'
                    ORDER BY gm.user_id
                """, (group['id'],))
                
                group_coordinators = cursor.fetchall()
                for coord in group_coordinators:
                    coord['group_name'] = group['group_name']
                    coord['group_id'] = group['id']
                coordinators.extend(group_coordinators)
            
            return coordinators
        except Error as e:
            print(f"Error fetching team: {e}")
            return []
        finally:
            cursor.close()
            connection.close()
    return []

# Updated assignment creation function (without division)
def create_assignment_updated(title, description, group_id, assigned_to, created_by, priority='medium', due_days=7):
    """Create a new assignment (updated without division)"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            due_date = datetime.now() + timedelta(days=due_days)
            
            cursor.execute("""
                INSERT INTO assignments 
                (title, description, group_id, assigned_to, created_by, priority, due_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (title, description, group_id, assigned_to, created_by, priority, due_date))
            
            assignment_id = cursor.lastrowid
            
            # Log the assignment action
            cursor.execute("""
                INSERT INTO assignment_actions (assignment_id, user_id, action_type, action_data)
                VALUES (%s, %s, 'assignment', %s)
            """, (assignment_id, created_by, json.dumps({'assigned_to': assigned_to})))
            
            connection.commit()
            return assignment_id
        except Error as e:
            connection.rollback()
            print(f"Error creating assignment: {e}")
            return None
        finally:
            cursor.close()
            connection.close()
    return None

def update_assignment_status(assignment_id, new_status, user_id):
    """Update assignment status"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            
            # Update status
            update_query = "UPDATE assignments SET status = %s"
            params = [new_status]
            
            if new_status == 'finished':
                update_query += ", finished_at = NOW()"
            elif new_status == 'verified':
                update_query += ", verified_at = NOW(), verified_by = %s"
                params.append(user_id)
            
            update_query += " WHERE id = %s"
            params.append(assignment_id)
            
            cursor.execute(update_query, params)
            
            # Log the action
            cursor.execute("""
                INSERT INTO assignment_actions (assignment_id, user_id, action_type, action_data)
                VALUES (%s, %s, 'status_change', %s)
            """, (assignment_id, user_id, json.dumps({'new_status': new_status})))
            
            connection.commit()
            return True
        except Error as e:
            connection.rollback()
            print(f"Error updating assignment: {e}")
            return False
        finally:
            cursor.close()
            connection.close()
    return False

def send_coordinator_message(sender_id, recipient_id, message, assignment_id=None):
    """Send a message between director and coordinator"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute("""
                INSERT INTO coordination_messages 
                (sender_id, recipient_id, message, assignment_id)
                VALUES (%s, %s, %s, %s)
            """, (sender_id, recipient_id, message, assignment_id))
            connection.commit()
            return cursor.lastrowid
        except Error as e:
            print(f"Error sending message: {e}")
            return None
        finally:
            cursor.close()
            connection.close()
    return None

def get_director_assignments(director_discord_id):
    """Get assignments for director verification (using Discord ID)"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("""
                SELECT a.*, 
                       a.assigned_to as assigned_to_name,
                       g.group_name,
                       CASE 
                           WHEN a.finished_at IS NOT NULL THEN a.finished_at
                           ELSE a.updated_at 
                       END as sort_date
                FROM assignments a
                LEFT JOIN coordination_groups g ON a.group_id = g.id
                WHERE g.created_by = %s AND a.status = 'finished'
                ORDER BY sort_date DESC
                LIMIT 50
            """, (director_discord_id,))
            return cursor.fetchall()
        except Error as e:
            print(f"Error fetching director assignments: {e}")
            return []
        finally:
            cursor.close()
            connection.close()
    return []

def get_executive_overview():
    """Get executive dashboard overview data (updated)"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Get assignment statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END) as verified,
                    SUM(CASE WHEN status = 'finished' THEN 1 ELSE 0 END) as pending_verification,
                    SUM(CASE WHEN status = 'delayed' THEN 1 ELSE 0 END) as delayed,
                    SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_assignments,
                    SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress
                FROM assignments
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            """)
            stats = cursor.fetchone()
            
            # Get team breakdown by rank
            cursor.execute("""
                SELECT 
                    s.rank,
                    COUNT(DISTINCT s.user_id) as member_count
                FROM staff_members s
                WHERE s.rank IN ('Senior Coordinator', 'Coordinator', 'Community Director', 'Project Director')
                GROUP BY s.rank
                ORDER BY 
                    CASE s.rank 
                        WHEN 'Community Director' THEN 1
                        WHEN 'Project Director' THEN 2
                        WHEN 'Senior Coordinator' THEN 3
                        WHEN 'Coordinator' THEN 4
                    END
            """)
            rank_breakdown = cursor.fetchall()
            
            # Get recent assignments with details
            cursor.execute("""
                SELECT 
                    a.*,
                    g.group_name
                FROM assignments a
                LEFT JOIN coordination_groups g ON a.group_id = g.id
                ORDER BY a.updated_at DESC
                LIMIT 50
            """)
            assignments = cursor.fetchall()
            
            return {
                'stats': stats,
                'rank_breakdown': rank_breakdown,
                'assignments': assignments
            }
        except Error as e:
            print(f"Error fetching overview: {e}")
            return None
        finally:
            cursor.close()
            connection.close()
    return None

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


# API
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

def format_time_ago(timestamp):
    if isinstance(timestamp, str):
        timestamp = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        
    now = datetime.now()
    diff = now - timestamp
        
    if diff.days > 7:
        return timestamp.strftime('%B %d, %Y')
    elif diff.days > 0:
        return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif diff.seconds > 60:
        minutes = diff.seconds // 60
        return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
    else:
        return "Just now"

def format_time_until(timestamp):
    if isinstance(timestamp, str):
        timestamp = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
        
    now = datetime.now()
    diff = timestamp - now
        
    if diff.days < 0:
        return f"{abs(diff.days)} day{'s' if abs(diff.days) > 1 else ''} overdue"
    elif diff.days > 0:
        return f"{diff.days} day{'s' if diff.days > 1 else ''}"
    elif diff.seconds > 3600:
        hours = diff.seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''}"
    else:
        return "Today"
    
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
            
            return redirect(url_for('admin_dashboard'))
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


@app.route('/admin/dashboard')
@login_required
@staff_required
def admin_dashboard():
    user = session['user']
    staff_rank = user.get('staff_info', {}).get('role', 'Staff')
    rank_color = RANK_COLORS.get(staff_rank, '#a977f8')
    
    # Define which panels each rank can access
    rank_panels = {
        'Executive Director': ['cases', 'coordination_executive', 'analytics', 'user_management'],
        'Administration Director': ['cases', 'coordination_director', 'coordination_executive', 'analytics', 'user_management'],
        'Project Director': ['cases', 'coordination_director', 'analytics'],
        'Community Director': ['cases', 'coordination_director', 'analytics'],
        'Administrator': ['cases'],
        'Junior Administrator': ['cases'],
        'Senior Moderator': ['cases'],
        'Moderator': ['cases'],
        'Trial Moderator': ['cases'],
        'Senior Coordinator': ['coordination_senior'],
        'Coordinator': ['coordination_basic'],
        'Senior Developer': ['cases'],
        'Developer': ['cases'],
        'Junior Developer': ['cases']
    }
    
    # Get available panels for current user
    available_panels = rank_panels.get(staff_rank, ['cases'])
    
    # Generate panel cards based on available access
    def generate_panel_card(panel_id, title, description, icon, url):
        if panel_id in available_panels:
            return f'''
            <a href="{url}" class="action-card">
                <div class="card-icon">
                    {icon}
                </div>
                <h3 class="card-title">{title}</h3>
                <p class="card-description">{description}</p>
            </a>
            '''
        return ''
    
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
                --rank-color: #a977f8;
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
            
            /* Background pattern matching cases site */
            .background-pattern {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                pointer-events: none;
                z-index: -1;
                background: 
                    radial-gradient(ellipse 80% 50% at 50% 40%, rgba(var(--primary-rgb), 0.04) 0%, transparent 60%),
                    radial-gradient(circle at 20% 30%, rgba(var(--primary-rgb), 0.08) 0%, transparent 50%),
                    radial-gradient(circle at 80% 70%, rgba(var(--primary-rgb), 0.06) 0%, transparent 50%);
            }}
            
            /* Header matching cases site */
            header {{
                position: fixed;
                top: 0;
                width: 100%;
                background: rgba(10, 10, 10, 0.8);
                backdrop-filter: blur(20px);
                z-index: 1000;
                border-bottom: 1px solid var(--border-color);
            }}
    
            nav {{
                max-width: 1400px;
                margin: 0 auto;
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 1rem 2rem;
            }}
    
            .logo {{
                font-size: 1.5rem;
                font-weight: 600;
                color: #ffffff;
                display: flex;
                align-items: center;
                gap: 0.75rem;
                letter-spacing: -0.02em;
            }}
    
            .logo img {{
                width: 28px;
                height: 28px;
                border-radius: 6px;
            }}
    
            .nav-links {{
                display: flex;
                align-items: center;
                gap: 1rem;
            }}
    
            .nav-link {{
                background: rgba(255, 255, 255, 0.06);
                color: #ffffff;
                padding: 0.5rem 1rem;
                border: 1px solid rgba(255, 255, 255, 0.12);
                border-radius: 6px;
                text-decoration: none;
                transition: all 0.2s ease;
                font-weight: 500;
                font-size: 0.875rem;
                cursor: pointer;
            }}
    
            .nav-link:hover {{
                background: rgba(169, 119, 248, 0.1);
                border-color: rgba(169, 119, 248, 0.4);
                transform: translateY(-1px);
            }}
    
            .nav-link.active {{
                background: rgba(169, 119, 248, 0.2);
                border-color: rgba(169, 119, 248, 0.5);
            }}
    
            .user-profile {{
                display: flex;
                align-items: center;
                gap: 0.5rem;
                background: rgba(255, 255, 255, 0.06);
                padding: 0.5rem 1rem;
                border: 1px solid rgba(255, 255, 255, 0.12);
                border-radius: 6px;
                color: var(--rank-color);
                font-weight: 500;
                font-size: 0.875rem;
            }}
    
            .user-avatar {{
                width: 20px;
                height: 20px;
                border-radius: 50%;
                background: var(--rank-color);
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: 700;
                font-size: 0.75rem;
                overflow: hidden;
            }}
    
            .user-avatar img {{
                width: 100%;
                height: 100%;
                object-fit: cover;
            }}
            
            /* Main content */
            .main-content {{
                margin-top: 80px;
                min-height: calc(100vh - 80px);
                padding: 2rem;
            }}
    
            .container {{
                max-width: 1400px;
                margin: 0 auto;
            }}
            
            /* Dashboard content */
            .dashboard-header {{
                margin-bottom: 3rem;
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
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }}
    
            .stat-card:hover {{
                transform: translateY(-4px);
                border-color: rgba(var(--primary-rgb), 0.4);
                box-shadow: var(--shadow-primary);
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
            
            .card-icon svg {{
                width: 28px;
                height: 28px;
                color: white;
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
            
            /* Responsive design */
            @media (max-width: 1024px) {{
                .main-content {{
                    padding: 1.5rem;
                }}
            }}
            
            @media (max-width: 768px) {{
                nav {{
                    padding: 1rem;
                    flex-direction: column;
                    gap: 1rem;
                }}
    
                .main-content {{
                    padding: 1rem;
                    margin-top: 120px;
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
    
                .nav-links {{
                    flex-wrap: wrap;
                    justify-content: center;
                }}
            }}
            
            @media (max-width: 480px) {{
                .main-content {{
                    padding: 0.75rem;
                }}
                
                .action-card {{
                    padding: 24px;
                }}
                
                .stats-grid {{
                    grid-template-columns: 1fr;
                }}
            }}
    
            /* Animations */
            .main-content {{
                animation: fadeInUp 0.8s ease-out;
            }}
    
            @keyframes fadeInUp {{
                from {{
                    opacity: 0;
                    transform: translateY(20px);
                }}
                to {{
                    opacity: 1;
                    transform: translateY(0);
                }}
            }}
        </style>
    </head>
    <body>
        <div class="background-pattern"></div>
        
        <!-- Header matching cases site -->
        <header>
            <nav>
                <div class="logo">
                    <img src="https://cdn.discordapp.com/attachments/1359093144376840212/1391111028552765550/image.png?ex=686caeda&is=686b5d5a&hm=2f7a401945da09ff951d426aaf651ade57dad6b6a52c567713aacf466c214a85&" alt="Themis">
                    Themis
                </div>
    
                <div class="nav-links">
                    <a href="/admin/dashboard" class="nav-link active">Dashboard</a>
                    <a href="/admin/cases" class="nav-link">Cases</a>
                    <a href="/admin/coordination" class="nav-link">Coordination</a>
                    <a href="/" class="nav-link">Home</a>
                    
                    <div class="user-profile">
                        <div class="user-avatar">U</div>
                        <span>User</span>
                    </div>
                    
                    <a href="/logout" class="nav-link">Logout</a>
                </div>
            </nav>
        </header>
        
        <main class="main-content">
            <div class="container">
                <div class="dashboard-header">
                    <h1 class="dashboard-title">
                        Welcome back, <span class="username-highlight">User</span>
                    </h1>
                    <p class="dashboard-subtitle">
                        We sure hope you're ready for all the bugs which are about to bless your eyes!
                    </p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-value">18</div>
                        <div class="stat-label">Staff Accounts</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">72</div>
                        <div class="stat-label">Total Actions</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">0.0%</div>
                        <div class="stat-label">Code Integrity</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-value">100.0%</div>
                        <div class="stat-label">Built on Hopes & Dreams</div>
                    </div>
                </div>
                
                <div class="quick-actions">
                    <a href="/admin/cases" class="action-card">
                        <div class="card-icon">
                            <svg width="28" height="28" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h8a2 2 0 012 2v12a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm3 1h6v4H7V5zm8 8v2h1v-2h-1zm-1-1h1v-2h-1v2zm1-4h-1V6h1v2zM7 8h6v4H7V8z" clip-rule="evenodd"/>
                            </svg>
                        </div>
                        <div class="card-title">View Cases</div>
                        <div class="card-description">View a list of cases taken from our discord punishments table</div>
                    </a>
                    
                    <a href="/admin/coordination/executive" class="action-card">
                        <div class="card-icon">
                            <svg width="28" height="28" fill="currentColor" viewBox="0 0 20 20">
                                <path d="M2 11a1 1 0 011-1h2a1 1 0 011 1v5a1 1 0 01-1 1H3a1 1 0 01-1-1v-5zM8 7a1 1 0 011-1h2a1 1 0 011 1v9a1 1 0 01-1 1H9a1 1 0 01-1-1V7zM14 4a1 1 0 011-1h2a1 1 0 011 1v12a1 1 0 01-1 1h-2a1 1 0 01-1-1V4z"/>
                            </svg>
                        </div>
                        <div class="card-title">Executive Overview</div>
                        <div class="card-description">Monitor all divisions and assignments from an executive perspective</div>
                    </a>
                    
                    <a href="/admin/coordination/director" class="action-card">
                        <div class="card-icon">
                            <svg width="28" height="28" fill="currentColor" viewBox="0 0 20 20">
                                <path d="M9 6a3 3 0 11-6 0 3 3 0 016 0zM17 6a3 3 0 11-6 0 3 3 0 016 0zM12.93 17c.046-.327.07-.66.07-1a6.97 6.97 0 00-1.5-4.33A5 5 0 0119 16v1h-6.07zM6 11a5 5 0 015 5v1H1v-1a5 5 0 015-5z"/>
                            </svg>
                        </div>
                        <div class="card-title">Director Panel</div>
                        <div class="card-description">Manage your coordination teams and manage assignments</div>
                    </a>
                    
                    <a href="/admin/coordination/senior" class="action-card">
                        <div class="card-icon">
                            <svg width="28" height="28" fill="currentColor" viewBox="0 0 20 20">
                                <path d="M13 6a3 3 0 11-6 0 3 3 0 016 0zM18 8a2 2 0 11-4 0 2 2 0 014 0zM14 15a4 4 0 00-8 0v3h8v-3z"/>
                            </svg>
                        </div>
                        <div class="card-title">Senior Coordinator</div>
                        <div class="card-description">Manage your coordinator team, handle and review incoming assignments</div>
                    </a>
                    
                    <a href="/admin/coordination/coordinator" class="action-card">
                        <div class="card-icon">
                            <svg width="28" height="28" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-6-3a2 2 0 11-4 0 2 2 0 014 0zm-2 4a5 5 0 00-4.546 2.916A5.986 5.986 0 0010 16a5.986 5.986 0 004.546-2.084A5 5 0 0010 11z" clip-rule="evenodd"/>
                            </svg>
                        </div>
                        <div class="card-title">Coordinator Panel</div>
                        <div class="card-description">View your assignments and communicate with your Senior Coordinators</div>
                    </a>
                </div>
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
                html += f'<img src="{url}" alt="evidence" style="max-width:60px;max-height:45px;margin:2px;border-radius:4px;border:1px solid #333;vertical-align:middle;">'
            elif ext in ['mp4', 'webm', 'ogg', 'mov', 'm4v']:
                html += f'<video src="{url}" controls style="max-width:60px;max-height:45px;margin:2px;border-radius:4px;vertical-align:middle;background:#111;"></video>'
            else:
                html += f'<a href="{url}" target="_blank" style="color:#a977f8;font-size:0.8rem;">File</a> '
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

    # Generate table rows
    table_rows = ""
    if cases:
        for c in cases:
            reason_text = c['reason'] or 'No reason provided'
            if len(reason_text) > 50:
                reason_text = reason_text[:50] + '...'
            status_class = 'status-appealed' if c['status'] == 'Appealed' else 'status-active'
            table_rows += f'''
                        <tr class="case-row" onclick="viewCase('{c['id']}', '{c['user_id']}', '{c['type']}', '{c['reason'] or 'No reason provided'}', '{c['status']}', '{c['length']}')">
                            <td><span class="case-id">#{c["id"]}</span></td>
                            <td><span class="user-id">{c["user_id"]}</span></td>
                            <td><span class="type-badge" style="background-color: {get_type_color(c['type'])}">{c["type"].title()}</span></td>
                            <td><span class="case-reason" title="{c['reason'] or 'No reason provided'}">{reason_text}</span></td>
                            <td><span class="status-badge {status_class}">{c["status"]}</span></td>
                            <td><span class="case-length">{c["length"]}</span></td>
                            <td class="evidence-cell">{render_evidence_block(c.get('evidence_list', []))}</td>
                        </tr>'''
    else:
        table_rows = '<tr><td colspan="7" class="empty-row">No cases found</td></tr>'

    html = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Themis - Case Management</title>
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
                --success-color: #22c55e;
                --warning-color: #f59e0b;
                --error-color: #ef4444;
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
            
            /* Background pattern matching index.html */
            .background-pattern {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                pointer-events: none;
                z-index: -1;
                background: 
                    radial-gradient(ellipse 80% 50% at 50% 40%, rgba(var(--primary-rgb), 0.04) 0%, transparent 60%),
                    radial-gradient(circle at 20% 30%, rgba(var(--primary-rgb), 0.08) 0%, transparent 50%),
                    radial-gradient(circle at 80% 70%, rgba(var(--primary-rgb), 0.06) 0%, transparent 50%);
            }}
            
            /* Header matching index.html */
            header {{
                position: fixed;
                top: 0;
                width: 100%;
                background: rgba(10, 10, 10, 0.8);
                backdrop-filter: blur(20px);
                z-index: 1000;
                border-bottom: 1px solid var(--border-color);
            }}

            nav {{
                max-width: 1400px;
                margin: 0 auto;
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 1rem 2rem;
            }}

            .logo {{
                font-size: 1.5rem;
                font-weight: 600;
                color: #ffffff;
                display: flex;
                align-items: center;
                gap: 0.75rem;
                letter-spacing: -0.02em;
            }}

            .logo img {{
                width: 28px;
                height: 28px;
                border-radius: 6px;
            }}

            .nav-links {{
                display: flex;
                align-items: center;
                gap: 1rem;
            }}

            .nav-link {{
                background: rgba(255, 255, 255, 0.06);
                color: #ffffff;
                padding: 0.5rem 1rem;
                border: 1px solid rgba(255, 255, 255, 0.12);
                border-radius: 6px;
                text-decoration: none;
                transition: all 0.2s ease;
                font-weight: 500;
                font-size: 0.875rem;
                cursor: pointer;
            }}

            .nav-link:hover {{
                background: rgba(169, 119, 248, 0.1);
                border-color: rgba(169, 119, 248, 0.4);
                transform: translateY(-1px);
            }}

            .nav-link.active {{
                background: rgba(169, 119, 248, 0.2);
                border-color: rgba(169, 119, 248, 0.5);
            }}

            .user-profile {{
                display: flex;
                align-items: center;
                gap: 0.5rem;
                background: rgba(255, 255, 255, 0.06);
                padding: 0.5rem 1rem;
                border: 1px solid rgba(255, 255, 255, 0.12);
                border-radius: 6px;
                color: var(--rank-color);
                font-weight: 500;
                font-size: 0.875rem;
            }}

            .user-avatar {{
                width: 20px;
                height: 20px;
                border-radius: 50%;
                background: var(--rank-color);
            }}
            
            /* Main content */
            .main-content {{
                margin-top: 80px;
                min-height: calc(100vh - 80px);
                padding: 2rem;
            }}

            .container {{
                max-width: 1400px;
                margin: 0 auto;
            }}
            
            /* Cases header */
            .cases-header {{
                display: flex;
                align-items: center;
                justify-content: space-between;
                margin-bottom: 3rem;
                gap: 24px;
                flex-wrap: wrap;
            }}
            
            .cases-title {{
                font-size: clamp(2.5rem, 5vw, 3.5rem);
                font-weight: 700;
                line-height: 1.1;
                background: linear-gradient(135deg, var(--text-primary) 0%, var(--text-secondary) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                letter-spacing: -0.02em;
            }}

            .cases-subtitle {{
                color: var(--text-secondary);
                font-size: 1.125rem;
                margin-top: 0.5rem;
            }}
            
            .create-log-btn {{
                background: rgba(255, 255, 255, 0.08);
                color: #ffffff;
                border: 1px solid rgba(255, 255, 255, 0.15);
                border-radius: 8px;
                padding: 0.75rem 1.5rem;
                font-size: 0.9rem;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.3s ease;
                display: inline-flex;
                align-items: center;
                gap: 8px;
                backdrop-filter: blur(10px);
            }}
            
            .create-log-btn:hover {{
                background: rgba(255, 255, 255, 0.12);
                border-color: var(--border-color);
                transform: translateY(-2px);
                box-shadow: var(--shadow-primary);
            }}
            
            /* Cases table container */
            .cases-container {{
                background: rgba(255, 255, 255, 0.03);
                border: 1px solid rgba(255, 255, 255, 0.08);
                border-radius: 12px;
                overflow: hidden;
                backdrop-filter: blur(10px);
                box-shadow: var(--shadow-primary);
            }}
            
            .cases-table {{
                width: 100%;
                border-collapse: collapse;
                font-size: 0.9rem;
            }}
            
            .cases-table th {{
                background: rgba(255, 255, 255, 0.02);
                color: var(--text-primary);
                padding: 1rem;
                text-align: left;
                font-weight: 600;
                font-size: 0.875rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
                position: sticky;
                top: 0;
                z-index: 10;
            }}
            
            .cases-table td {{
                padding: 1rem;
                border-bottom: 1px solid rgba(255, 255, 255, 0.05);
                color: var(--text-secondary);
                vertical-align: middle;
            }}
            
            .case-row {{
                transition: all 0.2s ease;
                cursor: pointer;
            }}
            
            .case-row:hover {{
                background: rgba(var(--primary-rgb), 0.04);
                transform: translateX(2px);
            }}
            
            .case-row:last-child td {{
                border-bottom: none;
            }}
            
            .case-id {{
                font-family: 'Monaco', 'Menlo', monospace;
                font-weight: 600;
                color: var(--primary-color);
                font-size: 0.9rem;
            }}
            
            .user-id {{
                font-family: 'Monaco', 'Menlo', monospace;
                color: var(--text-muted);
                font-size: 0.85rem;
            }}
            
            .type-badge {{
                display: inline-flex;
                align-items: center;
                padding: 4px 12px;
                border-radius: 16px;
                font-weight: 600;
                font-size: 0.75rem;
                color: #000;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            }}
            
            .case-reason {{
                max-width: 200px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
                line-height: 1.4;
            }}

            .case-length {{
                font-size: 0.85rem;
                color: var(--text-muted);
            }}
            
            .status-badge {{
                display: inline-flex;
                align-items: center;
                padding: 4px 12px;
                border-radius: 16px;
                font-weight: 600;
                font-size: 0.75rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            
            .status-active {{
                background: rgba(34, 197, 94, 0.2);
                color: var(--success-color);
                border: 1px solid rgba(34, 197, 94, 0.3);
            }}
            
            .status-appealed {{
                background: rgba(249, 115, 22, 0.2);
                color: var(--warning-color);
                border: 1px solid rgba(249, 115, 22, 0.3);
            }}

            .evidence-cell {{
                max-width: 120px;
                overflow: hidden;
            }}

            .empty-row {{
                text-align: center;
                color: var(--text-muted);
                padding: 3rem !important;
                font-style: italic;
            }}
            
            /* Modal styles matching index.html */
            .modal {{
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100vw;
                height: 100vh;
                background: rgba(0, 0, 0, 0.8);
                backdrop-filter: blur(10px);
                align-items: center;
                justify-content: center;
                z-index: 2000;
                opacity: 0;
                transition: opacity 0.3s ease;
                padding: 2rem;
            }}
            
            .modal.active {{
                display: flex;
                opacity: 1;
            }}
            
            .modal-content {{
                background: rgba(15, 15, 15, 0.95);
                border: 1px solid var(--border-color);
                border-radius: 12px;
                padding: 2rem;
                max-width: 500px;
                width: 100%;
                backdrop-filter: blur(20px);
                transform: translateY(20px);
                transition: transform 0.3s ease;
                max-height: 90vh;
                overflow-y: auto;
            }}
            
            .modal.active .modal-content {{
                transform: translateY(0);
            }}
            
            .close-modal {{
                position: absolute;
                top: 1rem;
                right: 1rem;
                background: none;
                border: none;
                color: var(--text-secondary);
                font-size: 1.5rem;
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
                margin-bottom: 1.5rem;
                color: var(--text-primary);
                text-align: center;
            }}
            
            .form-group {{
                margin-bottom: 1.5rem;
            }}
            
            .form-group label {{
                display: block;
                margin-bottom: 0.5rem;
                color: var(--text-primary);
                font-weight: 500;
                font-size: 0.9rem;
            }}
            
            .form-group input,
            .form-group select,
            .form-group textarea {{
                width: 100%;
                padding: 0.75rem 1rem;
                border: 1px solid rgba(255, 255, 255, 0.12);
                border-radius: 8px;
                background: rgba(255, 255, 255, 0.05);
                color: var(--text-primary);
                font-size: 0.9rem;
                font-family: inherit;
                transition: all 0.2s ease;
                backdrop-filter: blur(10px);
            }}
            
            .form-group input:focus,
            .form-group select:focus,
            .form-group textarea:focus {{
                outline: none;
                border-color: var(--primary-color);
                background: rgba(255, 255, 255, 0.08);
                box-shadow: 0 0 0 3px rgba(var(--primary-rgb), 0.1);
            }}
            
            .form-group textarea {{
                min-height: 80px;
                resize: vertical;
            }}
            
            .submit-btn {{
                width: 100%;
                background: rgba(255, 255, 255, 0.08);
                color: #ffffff;
                border: 1px solid rgba(255, 255, 255, 0.15);
                border-radius: 8px;
                padding: 0.75rem 1.5rem;
                font-size: 1rem;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.3s ease;
                backdrop-filter: blur(10px);
            }}
            
            .submit-btn:hover {{
                background: rgba(255, 255, 255, 0.12);
                border-color: var(--border-color);
                transform: translateY(-2px);
                box-shadow: var(--shadow-primary);
            }}

            /* Case details modal specific styles */
            .case-details {{
                display: flex;
                flex-direction: column;
                gap: 1rem;
            }}

            .detail-group {{
                display: flex;
                flex-direction: column;
                gap: 0.5rem;
            }}

            .detail-label {{
                font-weight: 600;
                color: var(--text-secondary);
                font-size: 0.85rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}

            .detail-value {{
                color: var(--text-primary);
                font-size: 0.95rem;
                line-height: 1.4;
            }}

            .evidence-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(120px, 1fr));
                gap: 0.75rem;
                margin-top: 0.5rem;
            }}

            .evidence-item {{
                border-radius: 8px;
                overflow: hidden;
                border: 1px solid rgba(255, 255, 255, 0.1);
                transition: all 0.2s ease;
            }}

            .evidence-item:hover {{
                border-color: var(--primary-color);
                transform: scale(1.02);
            }}

            .evidence-item img,
            .evidence-item video {{
                width: 100%;
                height: 80px;
                object-fit: cover;
                display: block;
            }}

            .evidence-item a {{
                display: block;
                padding: 1rem;
                text-align: center;
                color: var(--primary-color);
                text-decoration: none;
                background: rgba(255, 255, 255, 0.05);
                height: 80px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 0.85rem;
            }}

            .evidence-item a:hover {{
                background: rgba(var(--primary-rgb), 0.1);
            }}
            
            /* Responsive design */
            @media (max-width: 1024px) {{
                .main-content {{
                    padding: 1.5rem;
                }}
                
                .cases-header {{
                    flex-direction: column;
                    align-items: flex-start;
                    gap: 1rem;
                }}
                
                .cases-table {{
                    font-size: 0.85rem;
                }}
                
                .cases-table th,
                .cases-table td {{
                    padding: 0.75rem;
                }}
                
                .case-reason {{
                    max-width: 150px;
                }}
            }}
            
            @media (max-width: 768px) {{
                nav {{
                    padding: 1rem;
                    flex-direction: column;
                    gap: 1rem;
                }}

                .main-content {{
                    padding: 1rem;
                    margin-top: 120px;
                }}
                
                .cases-title {{
                    font-size: 2rem;
                }}
                
                .cases-table {{
                    font-size: 0.8rem;
                }}
                
                .cases-table th,
                .cases-table td {{
                    padding: 0.5rem;
                }}
                
                .case-reason {{
                    max-width: 100px;
                }}

                .evidence-cell {{
                    max-width: 80px;
                }}
                
                .modal {{
                    padding: 1rem;
                }}
                
                .modal-content {{
                    padding: 1.5rem;
                }}

                .nav-links {{
                    flex-wrap: wrap;
                    justify-content: center;
                }}
            }}

            @media (max-width: 480px) {{
                .main-content {{
                    padding: 0.75rem;
                }}
                
                .cases-table {{
                    font-size: 0.75rem;
                }}
                
                .type-badge,
                .status-badge {{
                    font-size: 0.7rem;
                    padding: 2px 8px;
                }}

                .evidence-grid {{
                    grid-template-columns: 1fr 1fr;
                }}
            }}

            /* Smooth scrolling */
            html {{
                scroll-behavior: smooth;
            }}

            /* Animations matching index.html */
            .main-content {{
                animation: fadeInUp 0.8s ease-out;
            }}

            @keyframes fadeInUp {{
                from {{
                    opacity: 0;
                    transform: translateY(20px);
                }}
                to {{
                    opacity: 1;
                    transform: translateY(0);
                }}
            }}

            .hidden {{
                display: none !important;
            }}

            /* Loading */
            .loading {{
                opacity: 0.6;
                pointer-events: none;
            }}
        </style>
    </head>
    <body>
        <div class="background-pattern"></div>
        
        <!-- Header matching index.html -->
        <header>
            <nav>
                <div class="logo">
                    <img src="https://cdn.discordapp.com/attachments/1359093144376840212/1391111028552765550/image.png?ex=686caeda&is=686b5d5a&hm=2f7a401945da09ff951d426aaf651ade57dad6b6a52c567713aacf466c214a85&" alt="Themis">
                    Themis
                </div>

                <div class="nav-links">
                    <a href="/admin/dashboard" class="nav-link">Dashboard</a>
                    <a href="/admin/cases" class="nav-link active">Cases</a>
                    <a href="/admin/coordination" class="nav-link">Coordination</a>
                    <a href="/" class="nav-link">Home</a>
                    
                    <div class="user-profile">
                        {f'<img src="{user.get("avatar_url")}" alt="Avatar" class="user-avatar">' if user.get("avatar_url") else f'<div class="user-avatar">{user.get("username", "U")[0].upper()}</div>'}
                        <span>{user.get('username', 'User')}</span>
                    </div>
                    
                    <a href="/logout" class="nav-link">Logout</a>
                </div>
            </nav>
        </header>
        
        <main class="main-content">
            <div class="container">
                <div class="cases-header">
                    <div>
                        <h1 class="cases-title">Case Management</h1>
                        <p class="cases-subtitle">Monitor and manage all moderation cases across your platforms</p>
                    </div>
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
                            </tr>
                        </thead>
                        <tbody>
                            {table_rows}
                        </tbody>
                    </table>
                </div>
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
                <div id="caseDetails" class="case-details">
                    <!-- Case details will be populated here -->
                </div>
            </div>
        </div>
        
        <script>
            const punishmentColors = {punishment_colors_js};
            
            function openModlogModal() {{
                const modal = document.getElementById('modlogModal');
                modal.classList.add('active');
                modal.setAttribute('aria-modal', 'true');
                document.body.style.overflow = 'hidden';
            }}

            function closeModlogModal() {{
                const modal = document.getElementById('modlogModal');
                modal.classList.remove('active');
                modal.setAttribute('aria-modal', 'false');
                document.body.style.overflow = 'auto';
                document.getElementById('modlogForm').reset();
            }}

            function viewCase(caseId, userId, type, reason, status, length) {{
                const modal = document.getElementById('viewCaseModal');
                const detailsContainer = document.getElementById('caseDetails');
                detailsContainer.innerHTML = '<div style="text-align:center;padding:2rem;color:var(--text-muted);">Loading case details...</div>';
                modal.classList.add('active');
                modal.setAttribute('aria-modal', 'true');
                document.body.style.overflow = 'hidden';

                // Fetch latest case info from backend
                fetch('/api/case/discord/' + caseId)
                    .then(res => res.json())
                    .then(data => {{
                        if (data.error) {{
                            detailsContainer.innerHTML = '<div style="color:var(--error-color);text-align:center;padding:2rem;">' + data.error + '</div>';
                            return;
                        }}
                        const typeColor = punishmentColors[(data.punishment_type || '').toLowerCase()] || punishmentColors['default'];
                        
                        // Evidence rendering: show images and videos inline, others as links
                        let evidenceHtml = '';
                        if (data.evidence && Array.isArray(data.evidence) && data.evidence.length) {{
                            evidenceHtml = `
                                <div class="detail-group">
                                    <div class="detail-label">Evidence</div>
                                    <div class="evidence-grid">
                                        ${{data.evidence.map(function(url) {{
                                            const ext = url.split('.').pop().toLowerCase().split('?')[0];
                                            if (["jpg","jpeg","png","gif","webp","bmp"].includes(ext)) {{
                                                return '<div class="evidence-item"><a href="' + url + '" target="_blank"><img src="' + url + '" alt="evidence"></a></div>';
                                            }} else if (["mp4","webm","ogg","mov","m4v"].includes(ext)) {{
                                                return '<div class="evidence-item"><video controls><source src="' + url + '"></video></div>';
                                            }} else {{
                                                return '<div class="evidence-item"><a href="' + url + '" target="_blank">📄 File</a></div>';
                                            }}
                                        }}).join('')}}
                                    </div>
                                </div>
                            `;
                        }}
                        
                        detailsContainer.innerHTML = `
                            <div class="detail-group">
                                <div class="detail-label">Case ID</div>
                                <div class="detail-value case-id">#${{data.reference_id}}</div>
                            </div>
                            
                            <div class="detail-group">
                                <div class="detail-label">User ID</div>
                                <div class="detail-value user-id">${{data.user_id}}</div>
                            </div>
                            
                            <div class="detail-group">
                                <div class="detail-label">Punishment Type</div>
                                <div class="detail-value">
                                    <span class="type-badge" style="background-color: ${{typeColor}}">
                                        ${{(data.punishment_type || '').charAt(0).toUpperCase() + (data.punishment_type || '').slice(1)}}
                                    </span>
                                </div>
                            </div>
                            
                            <div class="detail-group">
                                <div class="detail-label">Reason</div>
                                <div class="detail-value">${{data.reason || 'No reason provided'}}</div>
                            </div>
                            
                            <div class="detail-group">
                                <div class="detail-label">Status</div>
                                <div class="detail-value">
                                    <span class="status-badge ${{data.appealed === 1 ? 'status-appealed' : 'status-active'}}">
                                        ${{data.appealed === 1 ? 'Appealed' : 'Active'}}
                                    </span>
                                </div>
                            </div>
                            
                            <div class="detail-group">
                                <div class="detail-label">Length</div>
                                <div class="detail-value">${{data.length || 'N/A'}}</div>
                            </div>
                            
                            ${{data.discord_username ? `
                                <div class="detail-group">
                                    <div class="detail-label">Discord Username</div>
                                    <div class="detail-value">${{data.discord_username}}</div>
                                </div>
                            ` : ''}}
                            
                            ${{data.roblox_username ? `
                                <div class="detail-group">
                                    <div class="detail-label">Roblox Username</div>
                                    <div class="detail-value">${{data.roblox_username}}</div>
                                </div>
                            ` : ''}}
                            
                            ${{evidenceHtml}}
                        `;
                    }})
                    .catch(err => {{
                        detailsContainer.innerHTML = '<div style="color:var(--error-color);text-align:center;padding:2rem;">Error loading case details. Please try again.</div>';
                        console.error('Error loading case details:', err);
                    }});
            }}

            function closeViewCaseModal() {{
                const modal = document.getElementById('viewCaseModal');
                modal.classList.remove('active');
                modal.setAttribute('aria-modal', 'false');
                document.body.style.overflow = 'auto';
            }}
            
            // Handle form submission
            document.getElementById('modlogForm').addEventListener('submit', function(e) {{
                e.preventDefault();
                
                const formData = new FormData(this);
                const data = Object.fromEntries(formData);
                
                // Show loading state
                const submitBtn = this.querySelector('.submit-btn');
                const originalText = submitBtn.textContent;
                submitBtn.textContent = 'Creating...';
                submitBtn.disabled = true;
                
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
                        // Show success message
                        showNotification('Moderation log created successfully!', 'success');
                        // Refresh the page to show new case
                        setTimeout(() => window.location.reload(), 1000);
                    }} else {{
                        showNotification('Error creating modlog: ' + (result.message || 'Unknown error'), 'error');
                    }}
                }})
                .catch(error => {{
                    console.error('Error:', error);
                    showNotification('Error creating modlog. Please try again.', 'error');
                }})
                .finally(() => {{
                    // Reset button state
                    submitBtn.textContent = originalText;
                    submitBtn.disabled = false;
                }});
            }});
            
            // Show notification function
            function showNotification(message, type = 'info') {{
                // Create notification element
                const notification = document.createElement('div');
                notification.style.cssText = `
                    position: fixed;
                    top: 2rem;
                    right: 2rem;
                    background: ${{type === 'success' ? 'rgba(34, 197, 94, 0.9)' : type === 'error' ? 'rgba(239, 68, 68, 0.9)' : 'rgba(96, 165, 250, 0.9)'}};
                    color: white;
                    padding: 1rem 1.5rem;
                    border-radius: 8px;
                    font-weight: 500;
                    font-size: 0.9rem;
                    z-index: 3000;
                    backdrop-filter: blur(10px);
                    border: 1px solid ${{type === 'success' ? 'rgba(34, 197, 94, 0.3)' : type === 'error' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(96, 165, 250, 0.3)'}};
                    transform: translateX(100%);
                    transition: transform 0.3s ease;
                    max-width: 400px;
                `;
                notification.textContent = message;
                
                document.body.appendChild(notification);
                
                // Animate in
                setTimeout(() => {{
                    notification.style.transform = 'translateX(0)';
                }}, 100);
                
                // Remove after delay
                setTimeout(() => {{
                    notification.style.transform = 'translateX(100%)';
                    setTimeout(() => {{
                        if (notification.parentNode) {{
                            notification.parentNode.removeChild(notification);
                        }}
                    }}, 300);
                }}, 4000);
            }}
            
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

            // Initialize page
            document.addEventListener('DOMContentLoaded', function() {{
                console.log('Cases page loaded successfully');
            }});
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(html)

@app.route('/admin/coordination')
@login_required
@staff_required
def coordination_main():
    """
    Main coordination route that redirects users to their appropriate panel
    based on their rank
    """
    user = session['user']
    staff_rank = user.get('staff_info', {}).get('role', 'Staff')
    
    if staff_rank in ['Executive Director', 'Administration Director']:
        return redirect(url_for('executive_director_panel'))
    elif staff_rank in ['Community Director', 'Project Director']:
        return redirect(url_for('director_panel'))
    elif staff_rank == 'Senior Coordinator':
        return redirect(url_for('senior_coordinator_panel'))
    elif staff_rank == 'Coordinator':
        return redirect(url_for('coordinator_panel'))
    else:
        # Access Denied
        return render_template_string('''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Access Denied - Themis</title>
            <style>
                body {
                    font-family: 'Inter', sans-serif;
                    background: #0a0a0a;
                    color: #ffffff;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    min-height: 100vh;
                    margin: 0;
                }
                .access-denied {
                    text-align: center;
                    background: rgba(255, 255, 255, 0.04);
                    border: 1px solid rgba(169, 119, 248, 0.3);
                    border-radius: 20px;
                    padding: 40px;
                    max-width: 500px;
                    backdrop-filter: blur(16px);
                }
                .access-denied h1 {
                    font-size: 2rem;
                    margin-bottom: 16px;
                    color: #a977f8;
                }
                .access-denied p {
                    color: #b7b7c9;
                    margin-bottom: 24px;
                    line-height: 1.6;
                }
                .back-btn {
                    background: #a977f8;
                    color: white;
                    padding: 12px 24px;
                    border: none;
                    border-radius: 8px;
                    text-decoration: none;
                    display: inline-block;
                    transition: all 0.2s ease;
                }
                .back-btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 8px 25px rgba(169, 119, 248, 0.3);
                }
            </style>
        </head>
        <body>
            <div class="access-denied">
                <h1>Access Denied</h1>
                <p>The coordination system is only available to Directors and Coordinators. Your current rank ({{ staff_rank }}) does not have access to these features.</p>
                <a href="/admin/dashboard" class="back-btn">Return to Dashboard</a>
            </div>
        </body>
        </html>
        ''', staff_rank=staff_rank), 403

@app.route('/admin/coordination/director/create-group', methods=['POST'])
@login_required
@require_ranks(['Community Director', 'Project Director', 'Executive Director', 'Administration Director'])
def director_create_group():
    user = session['user']
    
    data = request.get_json()
    group_name = data.get('group_name')
    members = data.get('members', [])
    
    # Debug logging
    print(f"=== CREATE GROUP DEBUG ===")
    print(f"User session: {user}")
    print(f"Discord ID from session: {user['id']} (type: {type(user['id'])})")
    print(f"Group name: {group_name}")
    print(f"Members: {members}")
    
    # Check if the Discord ID exists in staff_members table
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Check if user exists in staff_members table
            cursor.execute("SELECT * FROM staff_members WHERE user_id = %s", (str(user['id']),))
            staff_record = cursor.fetchone()
            print(f"Staff record found: {staff_record}")
            
            # Also try checking with different data types
            cursor.execute("SELECT * FROM staff_members WHERE user_id = %s", (user['id'],))
            staff_record_raw = cursor.fetchone()
            print(f"Staff record (raw): {staff_record_raw}")
            
            # Check what's actually in the staff_members table
            cursor.execute("SELECT user_id FROM staff_members LIMIT 5")
            sample_users = cursor.fetchall()
            print(f"Sample user_ids in staff_members: {sample_users}")
            
            cursor.close()
            connection.close()
            
        except Exception as e:
            print(f"Debug query error: {e}")
            if cursor:
                cursor.close()
            connection.close()
    
    if group_name and members:
        # Pass the Discord user ID, not the session user ID
        discord_user_id = user['id']  # This is the Discord ID from session
        print(f"Calling create_group with discord_id: {discord_user_id}")
        
        group_id = create_group(group_name, discord_user_id, members)
        print(f"create_group returned: {group_id}")
        
        if group_id:
            return jsonify({'success': True, 'group_id': group_id})
        
        # More specific error message
        return jsonify({
            'success': False, 
            'error': f'Failed to create group. Discord ID {discord_user_id} may not exist in staff_members table or group creation failed.'
        }), 400
    
    return jsonify({'success': False, 'error': 'Invalid data - missing group name or members'}), 400

@app.route('/admin/coordination/director/create-assignment', methods=['POST'])
@login_required
@require_ranks(['Community Director', 'Project Director', 'Executive Director', 'Administration Director'])
def director_create_assignment():
    user = session['user']
    
    data = request.get_json()
    title = data.get('title')
    description = data.get('description')
    group_id = data.get('group_id')
    assigned_to = data.get('assigned_to')
    priority = data.get('priority', 'medium')
    due_days = data.get('due_days', 7)
    
    if all([title, group_id, assigned_to]):
        assignment_id = create_assignment_updated(
            title, description, group_id, assigned_to, 
            user['id'], priority, due_days
        )
        if assignment_id:
            return jsonify({'success': True, 'assignment_id': assignment_id})
        return jsonify({'success': False, 'error': 'Failed to create assignment'}), 400
    return jsonify({'success': False, 'error': 'Missing required fields'}), 400

@app.route('/admin/coordination/director', methods=['GET'])
@login_required
@require_ranks(['Community Director', 'Project Director', 'Executive Director', 'Administration Director'])
def director_panel():
    user = session['user']
    staff_role = user.get('staff_info', {}).get('role', 'Staff')
    rank_color = RANK_COLORS.get(staff_role, '#a977f8')
    
    # Determine division based on role
    division = 'Community' if staff_role == 'Community Director' else 'Executive'
    


    def get_division_stats(division, director_id):
        """Get statistics for a specific division"""
        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor(dictionary=True)
                
                # Get total groups
                cursor.execute("""
                    SELECT COUNT(*) as total_groups
                    FROM coordination_groups
                    WHERE created_by = %s AND is_active = TRUE
                """, (director_id,))
                stats = cursor.fetchone()
                
                # Get total members across all groups
                cursor.execute("""
                    SELECT COUNT(DISTINCT gm.user_id) as total_members
                    FROM group_members gm
                    JOIN coordination_groups g ON gm.group_id = g.id
                    WHERE g.created_by = %s AND g.is_active = TRUE
                """, (director_id,))
                members = cursor.fetchone()
                stats['total_members'] = members['total_members']
                
                # Get active assignments
                cursor.execute("""
                    SELECT COUNT(*) as active_assignments
                    FROM assignments a
                    JOIN coordination_groups g ON a.group_id = g.id
                    WHERE g.created_by = %s AND a.status IN ('open', 'in_progress')
                """, (director_id,))
                active = cursor.fetchone()
                stats['active_assignments'] = active['active_assignments']
                
                # Calculate completion rate
                cursor.execute("""
                    SELECT 
                        COUNT(CASE WHEN status = 'verified' THEN 1 END) as completed,
                        COUNT(*) as total
                    FROM assignments a
                    JOIN coordination_groups g ON a.group_id = g.id
                    WHERE g.created_by = %s
                """, (director_id,))
                completion = cursor.fetchone()
                
                if completion['total'] > 0:
                    stats['completion_rate'] = int((completion['completed'] / completion['total']) * 100)
                else:
                    stats['completion_rate'] = 0
                
                return stats
            except Error as e:
                print(f"Error fetching division stats: {e}")
                return {'total_groups': 0, 'total_members': 0, 'active_assignments': 0, 'completion_rate': 0}
            finally:
                cursor.close()
                connection.close()
        return {'total_groups': 0, 'total_members': 0, 'active_assignments': 0, 'completion_rate': 0}


    def get_director_groups(director_discord_id):
        """Get all groups created by a director (using Discord ID)"""
        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor(dictionary=True)
                cursor.execute("""
                    SELECT g.*, 
                        (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count
                    FROM coordination_groups g
                    WHERE g.created_by = %s AND g.is_active = TRUE
                    ORDER BY g.created_at DESC
                """, (director_discord_id,))
                
                groups = cursor.fetchall()
                
                # Get members for each group
                for group in groups:
                    cursor.execute("""
                        SELECT gm.*, 
                            gm.user_id as username,
                            gm.user_id as user_id_alias
                        FROM group_members gm
                        WHERE gm.group_id = %s
                        ORDER BY gm.role DESC, gm.user_id
                    """, (group['id'],))
                    group['members'] = cursor.fetchall()
                
                return groups
            except Error as e:
                print(f"Error fetching groups: {e}")
                return []
            finally:
                cursor.close()
                connection.close()
        return []

    # Helper function to generate group options for select dropdown
    def generate_group_options(groups):
        if not groups:
            return '<option value="">No teams available</option>'
        
        html = ''
        for group in groups:
            member_count = len(group.get('members', []))
            html += f'<option value="{group["id"]}">{group["group_name"]} ({member_count} members)</option>'
        
        return html

    # Helper function to generate groups display
    def generate_groups_display(groups):
        if not groups:
            return '''
            <div class="empty-state">
                <svg fill="currentColor" viewBox="0 0 20 20">
                    <path d="M9 6a3 3 0 11-6 0 3 3 0 016 0zM17 6a3 3 0 11-6 0 3 3 0 016 0zM12.93 17c.046-.327.07-.66.07-1a6.97 6.97 0 00-1.5-4.33A5 5 0 0119 16v1h-6.07zM6 11a5 5 0 015 5v1H1v-1a5 5 0 015-5z"/>
                </svg>
                <p>No teams created yet</p>
            </div>
            '''
        
        html = ''
        for group in groups:
            seniors = [m for m in group['members'] if m['role'] == 'Senior Coordinator']
            coordinators = [m for m in group['members'] if m['role'] == 'Coordinator']
            
            # Get assignment stats for this group
            active_count = 0  # You would query this from the database
            completed_count = 0  # You would query this from the database
            
            html += f'''
            <div class="group-card" data-group-id="{group['id']}">
                <div class="group-name">{group['group_name']}</div>
                
                <div class="group-metrics">
                    <div class="group-metric">
                        <div class="metric-value">{len(seniors)}</div>
                        <div class="metric-label">Seniors</div>
                    </div>
                    <div class="group-metric">
                        <div class="metric-value">{len(coordinators)}</div>
                        <div class="metric-label">Coordinators</div>
                    </div>
                    <div class="group-metric">
                        <div class="metric-value">{active_count}</div>
                        <div class="metric-label">Active</div>
                    </div>
                </div>
                
                <div class="group-members-preview">
                    {''.join([f'<div class="member-badge">User {m["user_id"]}</div>' for m in seniors[:2]])}
                    {f'<div class="member-badge">+{len(seniors) - 2} more</div>' if len(seniors) > 2 else ''}
                </div>
            </div>
            '''
        
        return html

    # Helper function to generate pending assignments
    def generate_pending_assignments(assignments):
        if not assignments:
            return '''
            <div class="empty-state">
                <svg fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zM4 6h12v10H4V6z" clip-rule="evenodd"/>
                </svg>
                <p>No assignments pending verification</p>
            </div>
            '''
        
        html = ''
        for assignment in assignments:
            finished_ago = format_time_ago(assignment['finished_at']) if assignment.get('finished_at') else 'Unknown'
            
            html += f'''
            <div class="assignment-item">
                <div class="assignment-header">
                    <div class="assignment-title">{assignment['title']}</div>
                    <div class="assignment-status status-finished">Pending</div>
                </div>
                
                <div class="assignment-details">
                    <span>By: User {assignment['assigned_to']}</span>
                    <span>Team: {assignment.get('group_name', 'Unknown')}</span>
                    <span>Completed: {finished_ago}</span>
                </div>
                
                <div class="assignment-actions">
                    <button class="btn btn-success btn-small" onclick="verifyAssignment({assignment['id']})">
                        <svg width="16" height="16" fill="currentColor" viewBox="0 0 20 20">
                            <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                        </svg>
                        Verify Complete
                    </button>
                    <button class="btn btn-secondary btn-small" onclick="viewAssignmentDetails({assignment['id']})">
                        View Details
                    </button>
                </div>
            </div>
            '''
        return html


    
    # Get data for display
    team_members = get_team_members_by_rank_fixed()
    groups = get_director_groups(user['id'])
    pending_assignments = get_director_assignments(user['id'])
    
    # Get division statistics
    stats = get_division_stats(division, user['id'])
    
    html = rf'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{division} Director Panel - Themis</title>
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
                --success-color: #4ade80;
                --warning-color: #fbbf24;
                --error-color: #f87171;
                --info-color: #60a5fa;
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
                min-height: 100vh;
            }}
            
            /* Background gradient */
            .background-gradient {{
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                pointer-events: none;
                z-index: -1;
                background: 
                    radial-gradient(circle at 20% 30%, rgba(var(--primary-rgb), 0.08) 0%, transparent 50%),
                    radial-gradient(circle at 80% 70%, rgba(var(--primary-rgb), 0.06) 0%, transparent 50%);
            }}
            
            .container {{
                max-width: 1600px;
                margin: 0 auto;
                padding: 40px 20px;
            }}
            
            .header {{
                margin-bottom: 48px;
            }}
            
            .page-title {{
                font-size: 3rem;
                font-weight: 800;
                background: linear-gradient(135deg, var(--text-primary) 0%, var(--primary-color) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 16px;
            }}
            
            .page-subtitle {{
                font-size: 1.1rem;
                color: var(--text-secondary);
            }}
            
            .back-btn {{
                display: inline-flex;
                align-items: center;
                gap: 8px;
                color: var(--text-secondary);
                text-decoration: none;
                margin-bottom: 32px;
                transition: all 0.2s ease;
            }}
            
            .back-btn:hover {{
                color: var(--primary-color);
                transform: translateX(-4px);
            }}
            
            /* Stats Row */
            .stats-row {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 40px;
            }}
            
            .stat-card {{
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 24px;
                backdrop-filter: var(--backdrop-blur);
                position: relative;
                overflow: hidden;
            }}
            
            .stat-card::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 3px;
                background: linear-gradient(90deg, var(--primary-color) 0%, #d946ef 100%);
            }}
            
            .stat-value {{
                font-size: 2rem;
                font-weight: 800;
                color: var(--primary-color);
                margin-bottom: 4px;
            }}
            
            .stat-label {{
                color: var(--text-secondary);
                font-size: 0.875rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            
            /* Main Grid */
            .main-grid {{
                display: grid;
                grid-template-columns: 350px 1fr 380px;
                gap: 32px;
                margin-bottom: 40px;
            }}
            
            .panel {{
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid var(--border-color);
                border-radius: 20px;
                padding: 32px;
                backdrop-filter: var(--backdrop-blur);
            }}
            
            .panel-title {{
                font-size: 1.5rem;
                font-weight: 700;
                margin-bottom: 24px;
                color: var(--text-primary);
            }}
            
            /* Team Building Panel */
            .team-members-list {{
                display: flex;
                flex-direction: column;
                gap: 12px;
                max-height: 400px;
                overflow-y: auto;
                padding-right: 8px;
            }}
            
            .team-members-list::-webkit-scrollbar {{
                width: 6px;
            }}
            
            .team-members-list::-webkit-scrollbar-track {{
                background: rgba(255, 255, 255, 0.05);
                border-radius: 3px;
            }}
            
            .team-members-list::-webkit-scrollbar-thumb {{
                background: rgba(169, 119, 248, 0.3);
                border-radius: 3px;
            }}
            
            .member-item {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 16px;
                display: flex;
                align-items: center;
                gap: 12px;
                transition: all 0.2s ease;
                cursor: pointer;
            }}
            
            .member-item:hover {{
                border-color: var(--primary-color);
                transform: translateX(4px);
            }}
            
            .member-item.selected {{
                background: rgba(var(--primary-rgb), 0.2);
                border-color: var(--primary-color);
            }}
            
            .member-checkbox {{
                width: 20px;
                height: 20px;
                accent-color: var(--primary-color);
            }}
            
            .member-info {{
                flex: 1;
            }}
            
            .member-name {{
                font-weight: 600;
                color: var(--text-primary);
            }}
            
            .member-role {{
                font-size: 0.85rem;
                color: var(--text-secondary);
            }}
            
            .member-role.senior {{
                color: #fbbf24;
            }}
            
            .member-role.coordinator {{
                color: #60a5fa;
            }}
            
            /* Create Group Section */
            .create-group-section {{
                margin-top: 32px;
                padding-top: 32px;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
            }}
            
            .form-group {{
                margin-bottom: 24px;
            }}
            
            .form-label {{
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
                color: var(--text-secondary);
            }}
            
            .form-input, .form-select, .form-textarea {{
                width: 100%;
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                padding: 12px 16px;
                color: var(--text-primary);
                font-size: 1rem;
                transition: all 0.2s ease;
                font-family: inherit;
            }}
            
            .form-input:focus, .form-select:focus, .form-textarea:focus {{
                outline: none;
                border-color: var(--primary-color);
                background: rgba(255, 255, 255, 0.08);
            }}
            
            .form-textarea {{
                min-height: 100px;
                resize: vertical;
            }}
            
            /* Assignment Creation */
            .assignment-form {{
                display: none;
            }}
            
            .assignment-form.active {{
                display: block;
                animation: fadeIn 0.3s ease;
            }}
            
            @keyframes fadeIn {{
                from {{
                    opacity: 0;
                    transform: translateY(10px);
                }}
                to {{
                    opacity: 1;
                    transform: translateY(0);
                }}
            }}
            
            .priority-selector {{
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 12px;
                margin-top: 8px;
            }}
            
            .priority-option {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                padding: 12px;
                text-align: center;
                cursor: pointer;
                transition: all 0.2s ease;
            }}
            
            .priority-option:hover {{
                border-color: var(--primary-color);
            }}
            
            .priority-option.selected {{
                border-color: var(--primary-color);
                background: rgba(var(--primary-rgb), 0.2);
            }}
            
            .priority-option.low {{
                border-color: var(--success-color);
            }}
            
            .priority-option.medium {{
                border-color: var(--warning-color);
            }}
            
            .priority-option.high {{
                border-color: var(--error-color);
            }}
            
            /* Groups Display */
            .groups-display {{
                display: grid;
                gap: 24px;
            }}
            
            .group-card {{
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 24px;
                position: relative;
                cursor: pointer;
                transition: all 0.2s ease;
            }}
            
            .group-card:hover {{
                border-color: var(--primary-color);
                transform: translateY(-2px);
                box-shadow: var(--shadow-primary);
            }}
            
            .group-card.selected {{
                border-color: var(--primary-color);
                background: rgba(var(--primary-rgb), 0.1);
            }}
            
            .group-name {{
                font-size: 1.25rem;
                font-weight: 700;
                margin-bottom: 16px;
                color: var(--primary-color);
            }}
            
            .group-metrics {{
                display: grid;
                grid-template-columns: repeat(3, 1fr);
                gap: 16px;
                margin-bottom: 20px;
            }}
            
            .group-metric {{
                text-align: center;
            }}
            
            .metric-value {{
                font-size: 1.5rem;
                font-weight: 700;
                color: var(--text-primary);
            }}
            
            .metric-label {{
                font-size: 0.75rem;
                color: var(--text-muted);
                text-transform: uppercase;
            }}
            
            .group-members-preview {{
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
            }}
            
            .member-badge {{
                background: rgba(var(--primary-rgb), 0.1);
                border: 1px solid rgba(var(--primary-rgb), 0.3);
                padding: 6px 12px;
                border-radius: 6px;
                font-size: 0.85rem;
                font-weight: 500;
            }}
            
            /* Assignments List */
            .assignments-list {{
                display: grid;
                gap: 16px;
            }}
            
            .assignment-item {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 20px;
                transition: all 0.2s ease;
            }}
            
            .assignment-item:hover {{
                border-color: var(--primary-color);
                transform: translateY(-2px);
            }}
            
            .assignment-header {{
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                margin-bottom: 12px;
            }}
            
            .assignment-title {{
                font-weight: 600;
                font-size: 1.1rem;
                color: var(--text-primary);
            }}
            
            .assignment-status {{
                padding: 6px 12px;
                border-radius: 6px;
                font-size: 0.8rem;
                font-weight: 600;
                text-transform: uppercase;
            }}
            
            .status-finished {{
                background: rgba(251, 191, 36, 0.2);
                color: var(--warning-color);
                border: 1px solid rgba(251, 191, 36, 0.3);
            }}
            
            .assignment-details {{
                display: flex;
                gap: 16px;
                font-size: 0.85rem;
                color: var(--text-secondary);
                margin-bottom: 16px;
            }}
            
            .assignment-actions {{
                display: flex;
                gap: 12px;
            }}
            
            /* Buttons */
            .btn {{
                background: var(--primary-color);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-size: 1rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s ease;
                display: inline-flex;
                align-items: center;
                gap: 8px;
            }}
            
            .btn:hover {{
                transform: translateY(-2px);
                box-shadow: var(--shadow-primary);
            }}
            
            .btn:disabled {{
                opacity: 0.5;
                cursor: not-allowed;
            }}
            
            .btn-secondary {{
                background: rgba(255, 255, 255, 0.08);
                color: var(--text-primary);
                border: 1px solid rgba(255, 255, 255, 0.2);
            }}
            
            .btn-secondary:hover {{
                background: rgba(255, 255, 255, 0.12);
            }}
            
            .btn-success {{
                background: var(--success-color);
                color: black;
            }}
            
            .btn-small {{
                padding: 8px 16px;
                font-size: 0.875rem;
            }}
            
            /* Empty States */
            .empty-state {{
                text-align: center;
                padding: 40px 20px;
                color: var(--text-muted);
            }}
            
            .empty-state svg {{
                width: 48px;
                height: 48px;
                margin-bottom: 16px;
                opacity: 0.3;
            }}
            
            /* Loading */
            .loading {{
                display: none;
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: rgba(0, 0, 0, 0.8);
                padding: 20px;
                border-radius: 8px;
                z-index: 1000;
            }}
            
            .loading.active {{
                display: block;
            }}
            
            /* Responsive */
            @media (max-width: 1200px) {{
                .main-grid {{
                    grid-template-columns: 1fr;
                }}
            }}
            
            @media (max-width: 768px) {{
                .container {{
                    padding: 20px 16px;
                }}
                
                .page-title {{
                    font-size: 2rem;
                }}
                
                .stats-row {{
                    grid-template-columns: 1fr 1fr;
                }}
                
                .priority-selector {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="background-gradient"></div>
        <div class="loading" id="loadingIndicator">
            <div style="color: white;">Processing...</div>
        </div>
        
        <div class="container">
            <a href="/admin/dashboard" class="back-btn">
                <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd"/>
                </svg>
                Back to Dashboard
            </a>
            
            <div class="header">
                <h1 class="page-title">{division} Director Panel</h1>
                <p class="page-subtitle">Build teams, assign tasks, and oversee {division.lower()} operations</p>
            </div>
            
            <!-- Statistics Row -->
            <div class="stats-row">
                <div class="stat-card">
                    <div class="stat-value">{stats.get('total_groups', 0)}</div>
                    <div class="stat-label">Active Teams</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats.get('total_members', 0)}</div>
                    <div class="stat-label">Team Members</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats.get('active_assignments', 0)}</div>
                    <div class="stat-label">Active Tasks</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{stats.get('completion_rate', 0)}%</div>
                    <div class="stat-label">Completion Rate</div>
                </div>
            </div>
            
            <!-- Main Grid -->
            <div class="main-grid">
                <!-- Team Building Panel -->
                <div class="panel">
                    <h2 class="panel-title">Team Builder</h2>
                    
                    <div class="team-members-list">
                        {generate_team_members_html(team_members)}
                    </div>
                    
                    <div class="create-group-section">
                        <h3 style="font-size: 1.1rem; margin-bottom: 16px;">Create New Team</h3>
                        <div class="form-group">
                            <label class="form-label">Team Name</label>
                            <input type="text" class="form-input" id="groupName" placeholder="Enter team name...">
                        </div>
                        <button class="btn" id="createGroupBtn" onclick="createGroup()" disabled>
                            <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd"/>
                            </svg>
                            Create Team
                        </button>
                        <div id="groupError" style="color: var(--error-color); font-size: 0.85rem; margin-top: 8px; display: none;"></div>
                    </div>
                </div>
                
                <!-- Assignment Creation Panel -->
                <div class="panel">
                    <h2 class="panel-title">Create Assignment</h2>
                    
                    <div class="assignment-form active">
                        <div class="form-group">
                            <label class="form-label">Select Team</label>
                            <select class="form-select" id="selectGroup" onchange="updateAssigneeList()">
                                <option value="">Choose a team...</option>
                                {generate_group_options(groups)}
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Assign To</label>
                            <select class="form-select" id="selectAssignee" disabled>
                                <option value="">Select team first...</option>
                            </select>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Task Title</label>
                            <input type="text" class="form-input" id="assignmentTitle" placeholder="Enter task title...">
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Description</label>
                            <textarea class="form-textarea" id="assignmentDescription" placeholder="Provide task details..."></textarea>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Priority</label>
                            <div class="priority-selector">
                                <div class="priority-option low" data-priority="low" onclick="selectPriority('low')">
                                    Low
                                </div>
                                <div class="priority-option medium selected" data-priority="medium" onclick="selectPriority('medium')">
                                    Medium
                                </div>
                                <div class="priority-option high" data-priority="high" onclick="selectPriority('high')">
                                    High
                                </div>
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label class="form-label">Due In (Days)</label>
                            <input type="number" class="form-input" id="dueDays" value="7" min="1" max="30">
                        </div>
                        
                        <button class="btn" onclick="createAssignment()">
                            <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M6 2a1 1 0 00-1 1v1H4a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V6a2 2 0 00-2-2h-1V3a1 1 0 10-2 0v1H7V3a1 1 0 00-1-1zM4 6h12v10H4V6z" clip-rule="evenodd"/>
                            </svg>
                            Create Assignment
                        </button>
                    </div>
                </div>
                
                <!-- Teams & Assignments Panel -->
                <div class="panel">
                    <h2 class="panel-title">Active Teams</h2>
                    
                    <div class="groups-display">
                        {generate_groups_display(groups)}
                    </div>
                    
                    <h3 style="font-size: 1.25rem; margin: 32px 0 16px 0;">Pending Verification</h3>
                    
                    <div class="assignments-list">
                        {generate_pending_assignments(pending_assignments)}
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            let selectedMembers = {{
                senior: [],
                coordinator: []
            }};
            
            let selectedPriority = 'medium';
            let groupsData = {json.dumps([{'id': g['id'], 'name': g['group_name'], 'members': [{'user_id': m['user_id'], 'role': m['role']} for m in g.get('members', [])]} for g in groups])};
            
            function toggleMember(element) {{
                const checkbox = element.querySelector('.member-checkbox');
                checkbox.checked = !checkbox.checked;
                element.classList.toggle('selected', checkbox.checked);
                
                const role = checkbox.dataset.role;
                const userId = checkbox.dataset.userId;
                const name = checkbox.dataset.name;
                
                if (checkbox.checked) {{
                    selectedMembers[role].push({{id: userId, name: name}});
                }} else {{
                    const index = selectedMembers[role].findIndex(m => m.id === userId);
                    if (index > -1) {{
                        selectedMembers[role].splice(index, 1);
                    }}
                }}
                
                validateGroupCreation();
            }}
            
            function validateGroupCreation() {{
                const groupName = document.getElementById('groupName').value.trim();
                const createBtn = document.getElementById('createGroupBtn');
                const errorDiv = document.getElementById('groupError');
                
                const hasSenior = selectedMembers.senior.length >= 1;
                const hasCoordinator = selectedMembers.coordinator.length >= 1;
                const hasName = groupName.length > 0;
                
                if (!hasSenior || !hasCoordinator) {{
                    errorDiv.textContent = 'Select at least 1 Senior Coordinator and 1 Coordinator';
                    errorDiv.style.display = 'block';
                    createBtn.disabled = true;
                }} else if (!hasName) {{
                    errorDiv.textContent = 'Please enter a team name';
                    errorDiv.style.display = 'block';
                    createBtn.disabled = true;
                }} else {{
                    errorDiv.style.display = 'none';
                    createBtn.disabled = false;
                }}
            }}
            
            document.getElementById('groupName').addEventListener('input', validateGroupCreation);
            
            function selectPriority(priority) {{
                document.querySelectorAll('.priority-option').forEach(opt => {{
                    opt.classList.remove('selected');
                }});
                document.querySelector(`.priority-option[data-priority="${{priority}}"]`).classList.add('selected');
                selectedPriority = priority;
            }}
            
            function updateAssigneeList() {{
                const groupId = document.getElementById('selectGroup').value;
                const assigneeSelect = document.getElementById('selectAssignee');
                
                assigneeSelect.innerHTML = '<option value="">Choose assignee...</option>';
                assigneeSelect.disabled = !groupId;
                
                if (groupId) {{
                    const group = groupsData.find(g => g.id == groupId);
                    if (group) {{
                        const seniors = group.members.filter(m => m.role === 'Senior Coordinator');
                        seniors.forEach(member => {{
                            const option = document.createElement('option');
                            option.value = member.user_id;
                            option.textContent = `User ${{member.user_id}} (Senior Coordinator)`;
                            assigneeSelect.appendChild(option);
                        }});
                    }}
                }}
            }}
            
            // Fixed createGroup function - keep IDs as strings (for f-string)
            async function createGroup() {{
                const groupName = document.getElementById('groupName').value.trim();
                const loadingIndicator = document.getElementById('loadingIndicator');
                
                const members = [];
                selectedMembers.senior.forEach(m => {{
                    members.push({{
                        user_id: m.id, // Keep as string, don't use parseInt()
                        role: 'Senior Coordinator'
                    }});
                }});
                selectedMembers.coordinator.forEach(m => {{
                    members.push({{
                        user_id: m.id, // Keep as string, don't use parseInt()
                        role: 'Coordinator'
                    }});
                }});
                
                console.log('Creating group with members:', members); // Debug log
                
                loadingIndicator.classList.add('active');
                
                try {{
                    const response = await fetch('/admin/coordination/director/create-group', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{
                            group_name: groupName,
                            members: members
                        }})
                    }});
                    
                    const data = await response.json();
                    
                    if (data.success) {{
                        alert('Team created successfully!');
                        window.location.reload();
                    }} else {{
                        alert('Error creating team: ' + (data.error || 'Unknown error'));
                    }}
                }} catch (error) {{
                    alert('Error creating team: ' + error.message);
                }} finally {{
                    loadingIndicator.classList.remove('active');
                }}
            }}

            // Also fix the toggleMember function to ensure IDs stay as strings
            function toggleMember(element) {{
                const checkbox = element.querySelector('.member-checkbox');
                checkbox.checked = !checkbox.checked;
                element.classList.toggle('selected', checkbox.checked);
                
                const role = checkbox.dataset.role;
                const userId = checkbox.dataset.userId; // Keep as string
                const name = checkbox.dataset.name;
                
                if (checkbox.checked) {{
                    selectedMembers[role].push({{
                        id: userId, // Keep as string, don't convert to int
                        name: name
                    }});
                }} else {{
                    const index = selectedMembers[role].findIndex(m => m.id === userId);
                    if (index > -1) {{
                        selectedMembers[role].splice(index, 1);
                    }}
                }}
                
                validateGroupCreation();
            }}

            // Also fix the toggleMember function to ensure IDs stay as strings
            function toggleMember(element) {{
                const checkbox = element.querySelector('.member-checkbox');
                checkbox.checked = !checkbox.checked;
                element.classList.toggle('selected', checkbox.checked);
                
                const role = checkbox.dataset.role;
                const userId = checkbox.dataset.userId; // Keep as string
                const name = checkbox.dataset.name;    

                if (checkbox.checked) {{
                    selectedMembers[role].push({{
                        id: userId, // Keep as string, dont convert to int
                        name: name
                    }});
                }} else {{
                    const index = selectedMembers[role].findIndex(m => m.id === userId);
                    if (index > -1) {{
                        selectedMembers[role].splice(index, 1);
                    }}
                }}
                
                validateGroupCreation();
            }}
            
            async function createAssignment() {{
                const groupId = document.getElementById('selectGroup').value;
                const assigneeId = document.getElementById('selectAssignee').value;
                const title = document.getElementById('assignmentTitle').value.trim();
                const description = document.getElementById('assignmentDescription').value.trim();
                const dueDays = document.getElementById('dueDays').value;
                
                if (!groupId || !assigneeId || !title) {{
                    alert('Please fill in all required fields');
                    return;
                }}
                
                const loadingIndicator = document.getElementById('loadingIndicator');
                loadingIndicator.classList.add('active');
                
                try {{
                    const response = await fetch('/admin/coordination/director/create-assignment', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{
                            title: title,
                            description: description,
                            group_id: parseInt(groupId),
                            assigned_to: parseInt(assigneeId),
                            priority: selectedPriority,
                            due_days: parseInt(dueDays)
                        }})
                    }});
                    
                    const data = await response.json();
                    
                    if (data.success) {{
                        alert('Assignment created successfully!');
                        // Clear form
                        document.getElementById('assignmentTitle').value = '';
                        document.getElementById('assignmentDescription').value = '';
                        document.getElementById('selectGroup').value = '';
                        document.getElementById('selectAssignee').value = '';
                        document.getElementById('selectAssignee').disabled = true;
                        document.getElementById('dueDays').value = '7';
                        selectPriority('medium');
                        
                        // Reload to show new assignment
                        setTimeout(() => window.location.reload(), 1000);
                    }} else {{
                        alert('Error creating assignment: ' + (data.error || 'Unknown error'));
                    }}
                }} catch (error) {{
                    alert('Error creating assignment: ' + error.message);
                }} finally {{
                    loadingIndicator.classList.remove('active');
                }}
            }}
            
            async function verifyAssignment(assignmentId) {{
                if (!confirm('Verify this assignment as completed?')) return;
                
                const loadingIndicator = document.getElementById('loadingIndicator');
                loadingIndicator.classList.add('active');
                
                try {{
                    const response = await fetch('/admin/coordination/verify-assignment', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{
                            assignment_id: assignmentId
                        }})
                    }});
                    
                    const data = await response.json();
                    
                    if (data.success) {{
                        alert('Assignment verified successfully!');
                        window.location.reload();
                    }} else {{
                        alert('Error verifying assignment');
                    }}
                }} catch (error) {{
                    alert('Error: ' + error.message);
                }} finally {{
                    loadingIndicator.classList.remove('active');
                }}
            }}
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(html)
            
# Fixed function to get team members (with more flexible requirements)
def get_team_members_by_rank_fixed():
    """Get all coordinators and senior coordinators from staff_members table only"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Get coordinators and senior coordinators from staff_members table only
            cursor.execute("""
                SELECT 
                    s.user_id as id,
                    s.user_id as username,
                    s.rank as role
                FROM staff_members s
                WHERE s.rank IN ('Senior Coordinator', 'Coordinator')
                ORDER BY 
                    CASE s.rank 
                        WHEN 'Senior Coordinator' THEN 1 
                        WHEN 'Coordinator' THEN 2 
                    END,
                    s.user_id
            """)
            
            result = cursor.fetchall()
            
            # If no results, debug by checking all staff ranks
            if not result:
                print("No coordinators found, checking all staff ranks...")
                cursor.execute("""
                    SELECT 
                        s.user_id as id,
                        s.user_id as username,
                        s.rank as role
                    FROM staff_members s
                    ORDER BY s.rank, s.user_id
                    LIMIT 10
                """)
                all_staff = cursor.fetchall()
                print(f"Found {len(all_staff)} total staff members:")
                for staff in all_staff:
                    print(f"  - {staff['username']} ({staff['role']})")
            
            return result
            
        except Error as e:
            print(f"Error fetching team members: {e}")
            return []
        finally:
            cursor.close()
            connection.close()
    return []

# Fixed HTML generation for team members
def generate_team_members_html(members):
    if not members:
        return '''
        <div class="empty-state">
            <svg fill="currentColor" viewBox="0 0 20 20">
                <path d="M9 6a3 3 0 11-6 0 3 3 0 016 0zM17 6a3 3 0 11-6 0 3 3 0 016 0zM12.93 17c.046-.327.07-.66.07-1a6.97 6.97 0 00-1.5-4.33A5 5 0 0119 16v1h-6.07zM6 11a5 5 0 015 5v1H1v-1a5 5 0 015-5z"/>
            </svg>
            <p>No team members found</p>
            <p style="font-size: 0.8rem; margin-top: 8px;">Make sure you have Senior Coordinators and Coordinators in your staff_members table</p>
        </div>
        '''
    
    html = ''
    for member in members:
        role_class = 'senior' if member['role'] == 'Senior Coordinator' else 'coordinator'
        # Use user_id as display name since we don't have usernames
        display_name = f"User {member['id']}"
        html += f'''
        <div class="member-item" onclick="toggleMember(this)">
            <input type="checkbox" class="member-checkbox" data-role="{role_class}" data-user-id="{member['id']}" data-name="{display_name}">
            <div class="member-info">
                <div class="member-name">{display_name}</div>
                <div class="member-role {role_class}">{member['role']}</div>
            </div>
        </div>
        '''
    return html

# Fixed groups HTML generation
def generate_groups_html(groups):
    if not groups:
        return '<p style="text-align: center; color: var(--text-muted);">No groups created yet</p>'
    
    html = ''
    for group in groups:
        seniors = [m for m in group['members'] if m['role'] == 'Senior Coordinator']
        coordinators = [m for m in group['members'] if m['role'] == 'Coordinator']
        
        html += f'''
        <div class="group-card">
            <div class="group-name">{group['group_name']}</div>
            <div class="group-structure">
                <div class="hierarchy-level">
                    <div class="hierarchy-title">Senior Coordinators</div>
                    <div class="hierarchy-members">
                        {''.join([f'<div class="member-badge">User {m["user_id"]}</div>' for m in seniors])}
                    </div>
                </div>
                <div class="hierarchy-level">
                    <div class="hierarchy-title">Coordinators</div>
                    <div class="hierarchy-members">
                        {''.join([f'<div class="member-badge">User {m["user_id"]}{" - " + m["role_label"] if m.get("role_label") else ""}</div>' for m in coordinators])}
                    </div>
                </div>
            </div>
        </div>
        '''
    return html


# Route to verify assignments
@app.route('/admin/coordination/verify-assignment', methods=['POST'])
@login_required
@staff_required
def verify_assignment():
    user = session['user']
    data = request.get_json()
    assignment_id = data.get('assignment_id')
    
    if assignment_id:
        success = update_assignment_status(assignment_id, 'verified', user['id'])
        if success:
            return jsonify({'success': True})
    
    return jsonify({'success': False}), 400

# Senior Coordinator Panel with Backend
@app.route('/admin/coordination/senior', methods=['GET', 'POST'])
@login_required
@staff_required
def senior_coordinator_panel():
    user = session['user']
    staff_role = user.get('staff_info', {}).get('role', 'Staff')
    
    if staff_role not in ['Senior Coordinator', 'Community Director', 'Executive Director', 'Administration Director']:
        return "Access Denied", 403
    
    # Handle label updates
    if request.method == 'POST' and request.path.endswith('/update-label'):
        data = request.get_json()
        group_id = data.get('group_id')
        coordinator_id = data.get('coordinator_id')
        label = data.get('label')
        
        if update_coordinator_label(group_id, coordinator_id, label, user['id']):
            return jsonify({'success': True})
        return jsonify({'success': False}), 400
    
    # Get data
    coordinators = get_coordinator_team(user['id'])
    assignments = get_senior_coordinator_assignments(user['id'])
    
    html = rf'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Senior Coordinator Panel - Themis</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <style>
            /* Include the same base styles as director panel */
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
                --success-color: #4ade80;
                --warning-color: #fbbf24;
                --error-color: #f87171;
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
                min-height: 100vh;
            }}
            
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                padding: 40px 20px;
            }}
            
            .header {{
                margin-bottom: 48px;
            }}
            
            .page-title {{
                font-size: 3rem;
                font-weight: 800;
                background: linear-gradient(135deg, var(--text-primary) 0%, var(--primary-color) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 16px;
            }}
            
            .page-subtitle {{
                font-size: 1.1rem;
                color: var(--text-secondary);
            }}
            
            .panels-grid {{
                display: grid;
                grid-template-columns: 1fr 2fr;
                gap: 32px;
                margin-bottom: 40px;
            }}
            
            .panel {{
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid var(--border-color);
                border-radius: 20px;
                padding: 32px;
                backdrop-filter: var(--backdrop-blur);
            }}
            
            .panel-title {{
                font-size: 1.5rem;
                font-weight: 700;
                margin-bottom: 24px;
                color: var(--text-primary);
            }}
            
            .team-structure {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 16px;
                padding: 24px;
                margin-bottom: 32px;
            }}
            
            .coordinator-list {{
                display: grid;
                gap: 16px;
            }}
            
            .coordinator-card {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 20px;
                cursor: pointer;
                transition: all 0.2s ease;
            }}
            
            .coordinator-card:hover {{
                border-color: var(--primary-color);
                transform: translateY(-2px);
            }}
            
            .coordinator-name {{
                font-weight: 600;
                font-size: 1.1rem;
                margin-bottom: 8px;
            }}
            
            .coordinator-label {{
                font-size: 0.85rem;
                color: var(--text-secondary);
                margin-bottom: 12px;
            }}
            
            .label-input {{
                width: 100%;
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 6px;
                padding: 8px 12px;
                color: var(--text-primary);
                font-size: 0.85rem;
                margin-top: 8px;
            }}
            
            .assignments-section {{
                margin-top: 32px;
            }}
            
            .request-list {{
                display: grid;
                gap: 16px;
            }}
            
            .request-item {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 20px;
                cursor: pointer;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            }}
            
            .request-item:hover {{
                border-color: var(--primary-color);
                transform: translateY(-2px);
                box-shadow: var(--shadow-primary);
            }}
            
            .request-item.active {{
                border-color: var(--primary-color);
                background: rgba(var(--primary-rgb), 0.1);
            }}
            
            .request-title {{
                font-weight: 600;
                font-size: 1.1rem;
                margin-bottom: 8px;
            }}
            
            .request-date {{
                font-size: 0.85rem;
                color: var(--text-muted);
            }}
            
            .request-priority {{
                display: inline-block;
                padding: 4px 12px;
                border-radius: 4px;
                font-size: 0.75rem;
                font-weight: 600;
                margin-top: 8px;
            }}
            
            .priority-high {{
                background: rgba(248, 113, 113, 0.2);
                color: var(--error-color);
            }}
            
            .priority-medium {{
                background: rgba(251, 191, 36, 0.2);
                color: var(--warning-color);
            }}
            
            .priority-low {{
                background: rgba(74, 222, 128, 0.2);
                color: var(--success-color);
            }}
            
            .assignment-detail {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 16px;
                padding: 32px;
                display: none;
            }}
            
            .assignment-detail.active {{
                display: block;
                animation: fadeIn 0.3s ease;
            }}
            
            @keyframes fadeIn {{
                from {{
                    opacity: 0;
                    transform: translateY(10px);
                }}
                to {{
                    opacity: 1;
                    transform: translateY(0);
                }}
            }}
            
            .assignment-header {{
                border-bottom: 1px solid rgba(255, 255, 255, 0.1);
                padding-bottom: 24px;
                margin-bottom: 24px;
            }}
            
            .assignment-title-large {{
                font-size: 1.75rem;
                font-weight: 700;
                margin-bottom: 12px;
            }}
            
            .assignment-meta {{
                display: flex;
                gap: 24px;
                color: var(--text-secondary);
                font-size: 0.9rem;
            }}
            
            .assignment-content {{
                margin-bottom: 32px;
                line-height: 1.8;
                color: var(--text-secondary);
                white-space: pre-wrap;
            }}
            
            .assignment-actions {{
                display: flex;
                gap: 16px;
                padding-top: 24px;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
            }}
            
            .btn {{
                background: var(--primary-color);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-size: 1rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s ease;
                display: inline-flex;
                align-items: center;
                gap: 8px;
            }}
            
            .btn:hover {{
                transform: translateY(-2px);
                box-shadow: var(--shadow-primary);
            }}
            
            .btn-secondary {{
                background: rgba(255, 255, 255, 0.08);
                color: var(--text-primary);
                border: 1px solid rgba(255, 255, 255, 0.2);
            }}
            
            .btn-secondary:hover {{
                background: rgba(255, 255, 255, 0.12);
            }}
            
            .back-btn {{
                display: inline-flex;
                align-items: center;
                gap: 8px;
                color: var(--text-secondary);
                text-decoration: none;
                margin-bottom: 32px;
                transition: all 0.2s ease;
            }}
            
            .back-btn:hover {{
                color: var(--primary-color);
                transform: translateX(-4px);
            }}
            
            .loading {{
                display: none;
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: rgba(0, 0, 0, 0.8);
                padding: 20px;
                border-radius: 8px;
                z-index: 1000;
            }}
            
            .loading.active {{
                display: block;
            }}
            
            @media (max-width: 768px) {{
                .panels-grid {{
                    grid-template-columns: 1fr;
                }}
                
                .container {{
                    padding: 20px 16px;
                }}
                
                .page-title {{
                    font-size: 2rem;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="loading" id="loadingIndicator">
            <div style="color: white;">Processing...</div>
        </div>
        
        <div class="container">
            <a href="/admin/dashboard" class="back-btn">
                <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd"/>
                </svg>
                Back to Dashboard
            </a>
            
            <div class="header">
                <h1 class="page-title">Senior Coordinator Panel</h1>
                <p class="page-subtitle">Manage your team and handle incoming assignments</p>
            </div>
            
            <div class="panels-grid">
                <div class="panel">
                    <h2 class="panel-title">Your Team</h2>
                    
                    {generate_coordinators_html(coordinators)}
                    
                    <div class="assignments-section">
                        <h3 style="font-size: 1.1rem; margin-bottom: 16px;">Incoming Requests</h3>
                        
                        <div class="request-list" id="requestList">
                            {generate_requests_html(assignments)}
                        </div>
                    </div>
                </div>
                
                <div class="panel">
                    <h2 class="panel-title">Assignment Details</h2>
                    
                    <div id="noSelection" style="text-align: center; padding: 60px 20px; color: var(--text-muted);">
                        <svg width="64" height="64" fill="currentColor" viewBox="0 0 20 20" style="opacity: 0.3; margin-bottom: 16px;">
                            <path fill-rule="evenodd" d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z" clip-rule="evenodd"/>
                        </svg>
                        <p>Select an assignment from the list to view details</p>
                    </div>
                    
                    {generate_assignment_details_html(assignments)}
                </div>
            </div>
        </div>
        
        <script>
            function toggleLabelEdit(card) {{
                const label = card.querySelector('.coordinator-label');
                const input = card.querySelector('.label-input');
                
                if (input.style.display === 'none') {{
                    input.value = label.dataset.originalLabel || '';
                    label.style.display = 'none';
                    input.style.display = 'block';
                    input.focus();
                }}
            }}
            
            async function saveLabel(input) {{
                const card = input.closest('.coordinator-card');
                const label = card.querySelector('.coordinator-label');
                const groupId = card.dataset.groupId;
                const coordinatorId = card.dataset.coordinatorId;
                const newLabel = input.value.trim();
                
                if (newLabel && newLabel !== label.dataset.originalLabel) {{
                    const loadingIndicator = document.getElementById('loadingIndicator');
                    loadingIndicator.classList.add('active');
                    
                    try {{
                        const response = await fetch('/admin/coordination/update-label', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json',
                            }},
                            body: JSON.stringify({{
                                group_id: parseInt(groupId),
                                coordinator_id: parseInt(coordinatorId),
                                label: newLabel
                            }})
                        }});
                        
                        const data = await response.json();
                        
                        if (data.success) {{
                            label.textContent = newLabel || 'Click to assign role';
                            label.dataset.originalLabel = newLabel;
                        }} else {{
                            alert('Error updating label');
                        }}
                    }} catch (error) {{
                        alert('Error: ' + error.message);
                    }} finally {{
                        loadingIndicator.classList.remove('active');
                    }}
                }}
                
                label.style.display = 'block';
                input.style.display = 'none';
            }}
            
            function selectRequest(element, assignmentId) {{
                // Update active states
                document.querySelectorAll('.request-item').forEach(item => {{
                    item.classList.remove('active');
                }});
                element.classList.add('active');
                
                // Hide all assignments and no selection message
                document.getElementById('noSelection').style.display = 'none';
                document.querySelectorAll('.assignment-detail').forEach(detail => {{
                    detail.classList.remove('active');
                }});
                
                // Show selected assignment
                setTimeout(() => {{
                    document.getElementById(`assignment${{assignmentId}}`).classList.add('active');
                }}, 100);
                
                // Fade out request list
                const requestList = document.getElementById('requestList');
                requestList.style.opacity = '0.3';
                requestList.style.pointerEvents = 'none';
            }}
            
            async function finishAssignment(assignmentId) {{
                if (confirm('Mark this assignment as finished?')) {{
                    const loadingIndicator = document.getElementById('loadingIndicator');
                    loadingIndicator.classList.add('active');
                    
                    try {{
                        const response = await fetch('/admin/coordination/finish-assignment', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json',
                            }},
                            body: JSON.stringify({{
                                assignment_id: assignmentId
                            }})
                        }});
                        
                        const data = await response.json();
                        
                        if (data.success) {{
                            alert('Assignment marked as finished and sent to Director for verification.');
                            window.location.reload();
                        }} else {{
                            alert('Error finishing assignment');
                        }}
                    }} catch (error) {{
                        alert('Error: ' + error.message);
                    }} finally {{
                        loadingIndicator.classList.remove('active');
                    }}
                }}
            }}
            
            async function contactDirector(assignmentId) {{
                const message = prompt('Enter your message to the Director:');
                if (message) {{
                    const loadingIndicator = document.getElementById('loadingIndicator');
                    loadingIndicator.classList.add('active');
                    
                    try {{
                        const response = await fetch('/admin/coordination/contact-director', {{
                            method: 'POST',
                            headers: {{
                                'Content-Type': 'application/json',
                            }},
                            body: JSON.stringify({{
                                assignment_id: assignmentId,
                                message: message
                            }})
                        }});
                        
                        const data = await response.json();
                        
                        if (data.success) {{
                            alert('Message sent to Director');
                        }} else {{
                            alert('Error sending message');
                        }}
                    }} catch (error) {{
                        alert('Error: ' + error.message);
                    }} finally {{
                        loadingIndicator.classList.remove('active');
                    }}
                }}
            }}
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(html)

# Helper functions for Senior Coordinator panel
def generate_coordinators_html(coordinators):
    if not coordinators:
        return '<p style="text-align: center; color: var(--text-muted);">No team members assigned yet</p>'
    
    # Group coordinators by group
    groups = {}
    for coord in coordinators:
        group_name = coord.get('group_name', 'Unknown Group')
        if group_name not in groups:
            groups[group_name] = []
        groups[group_name].append(coord)
    
    html = ''
    for group_name, members in groups.items():
        html += f'''
        <div class="team-structure">
            <h3 style="font-size: 1.1rem; margin-bottom: 16px; color: var(--primary-color);">{group_name}</h3>
            
            <div class="coordinator-list">
        '''
        
        for member in members:
            label = member.get('role_label', 'Click to assign role')
            html += f'''
            <div class="coordinator-card" onclick="toggleLabelEdit(this)" data-group-id="{member['group_id']}" data-coordinator-id="{member['user_id']}">
                <div class="coordinator-name">{member['username']}</div>
                <div class="coordinator-label" data-original-label="{member.get('role_label', '')}">{label}</div>
                <input type="text" class="label-input" style="display: none;" placeholder="Enter role label..." onblur="saveLabel(this)">
            </div>
            '''
        
        html += '''
            </div>
        </div>
        '''
    
    return html

def generate_requests_html(assignments):
    if not assignments:
        return '<p style="text-align: center; color: var(--text-muted);">No incoming requests at the moment</p>'
    
    html = ''
    for assignment in assignments:
        priority_class = f"priority-{assignment['priority']}"
        created_at = assignment['created_at']
        # Format time ago
        time_ago = format_time_ago(created_at)
        
        html += f'''
        <div class="request-item" onclick="selectRequest(this, {assignment['id']})">
            <div class="request-title">{assignment['title']}</div>
            <div class="request-date">Requested: {time_ago}</div>
            <div class="request-priority {priority_class}">{assignment['priority'].title()} Priority</div>
        </div>
        '''
    
    return html

def generate_assignment_details_html(assignments):
    html = ''
    for assignment in assignments:
        due_date = assignment['due_date']
        time_until_due = format_time_until(due_date)
        
        html += f'''
        <div class="assignment-detail" id="assignment{assignment['id']}">
            <div class="assignment-header">
                <h3 class="assignment-title-large">{assignment['title']}</h3>
                <div class="assignment-meta">
                    <span>From: {assignment['created_by_name']}</span>
                    <span>Priority: {assignment['priority'].title()}</span>
                    <span>Due: {time_until_due}</span>
                </div>
            </div>
            
            <div class="assignment-content">{assignment['description'] or 'No description provided.'}</div>
            
            <div class="assignment-actions">
                <button class="btn" onclick="finishAssignment({assignment['id']})">
                    <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20">
                        <path fill-rule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clip-rule="evenodd"/>
                    </svg>
                    Finish Assignment
                </button>
                <button class="btn btn-secondary" onclick="contactDirector({assignment['id']})">
                    <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20">
                        <path d="M2.003 5.884L10 9.882l7.997-3.998A2 2 0 0016 4H4a2 2 0 00-1.997 1.884z"/>
                        <path d="M18 8.118l-8 4-8-4V14a2 2 0 002 2h12a2 2 0 002-2V8.118z"/>
                    </svg>
                    Contact Director
                </button>
            </div>
        </div>
        '''
    
    return html

def get_senior_coordinator_assignments(user_id):
    """Get assignments for a Senior Coordinator (using staff_members table)"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("""
                SELECT a.*, 
                       a.created_by as created_by_name, 
                       g.group_name
                FROM assignments a
                LEFT JOIN coordination_groups g ON a.group_id = g.id
                WHERE a.assigned_to = %s AND a.status IN ('open', 'in_progress')
                ORDER BY 
                    CASE a.priority 
                        WHEN 'high' THEN 1 
                        WHEN 'medium' THEN 2 
                        WHEN 'low' THEN 3 
                    END,
                    a.created_at DESC
            """, (user_id,))
            return cursor.fetchall()
        except Error as e:
            print(f"Error fetching assignments: {e}")
            return []
        finally:
            cursor.close()
            connection.close()
    return []



# Additional routes for Senior Coordinator actions
@app.route('/admin/coordination/finish-assignment', methods=['POST'])
@login_required
@staff_required
def finish_assignment():
    user = session['user']
    data = request.get_json()
    assignment_id = data.get('assignment_id')
    
    if assignment_id:
        success = update_assignment_status(assignment_id, 'finished', user['id'])
        if success:
            return jsonify({'success': True})
    
    return jsonify({'success': False}), 400

@app.route('/admin/coordination/contact-director', methods=['POST'])
@login_required
@staff_required
def contact_director():
    user = session['user']
    data = request.get_json()
    assignment_id = data.get('assignment_id')
    message = data.get('message')
    
    if assignment_id and message:
        # Get the assignment to find the director
        connection = get_db_connection()
        if connection:
            try:
                cursor = connection.cursor(dictionary=True)
                cursor.execute("""
                    SELECT created_by FROM assignments WHERE id = %s
                """, (assignment_id,))
                assignment = cursor.fetchone()
                
                if assignment:
                    message_id = send_coordinator_message(
                        user['id'], 
                        assignment['created_by'], 
                        message, 
                        assignment_id
                    )
                    if message_id:
                        return jsonify({'success': True})
            finally:
                cursor.close()
                connection.close()
    
    return jsonify({'success': False}), 400

@app.route('/admin/coordination/update-label', methods=['POST'])
@login_required
@staff_required
def update_label():
    user = session['user']
    data = request.get_json()
    group_id = data.get('group_id')
    coordinator_id = data.get('coordinator_id')
    label = data.get('label')
    
    if group_id and coordinator_id and label:
        success = update_coordinator_label(group_id, coordinator_id, label, user['id'])
        if success:
            return jsonify({'success': True})
    
    return jsonify({'success': False}), 400

@app.route('/admin/coordination/coordinator')
@login_required
@require_ranks(['Coordinator', 'Senior Coordinator', 'Community Director', 'Executive Director', 'Administration Director'])
def coordinator_panel():
    user = session['user']
    staff_rank = user.get('staff_info', {}).get('role', 'Staff')
    rank_color = RANK_COLORS.get(staff_rank, '#a977f8')
    user_id = user.get('id')
    
    # Get coordinator's assignments and messages
    connection = get_db_connection()
    assignments = []
    messages = []
    
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Get assignments where this user is assigned
            cursor.execute("""
                SELECT a.*, 
                       u.discord_username as created_by_name, 
                       g.group_name,
                       CASE 
                           WHEN a.due_date < NOW() AND a.status IN ('open', 'in_progress') THEN 'overdue'
                           ELSE a.status 
                       END as display_status
                FROM assignments a
                JOIN users u ON a.created_by = u.discord_user_id
                LEFT JOIN coordination_groups g ON a.group_id = g.id
                WHERE a.assigned_to = %s 
                ORDER BY 
                    CASE a.status 
                        WHEN 'open' THEN 1 
                        WHEN 'in_progress' THEN 2
                        WHEN 'delayed' THEN 3
                        ELSE 4 
                    END,
                    a.due_date ASC
                LIMIT 20
            """, (user_id,))
            assignments = cursor.fetchall()
            
            # Get recent messages
            cursor.execute("""
                SELECT m.*, 
                       u.discord_username as sender_name,
                       a.title as assignment_title
                FROM coordination_messages m
                JOIN users u ON m.sender_id = u.discord_user_id
                LEFT JOIN assignments a ON m.assignment_id = a.id
                WHERE m.recipient_id = %s 
                ORDER BY m.created_at DESC
                LIMIT 10
            """, (user_id,))
            messages = cursor.fetchall()
            
        except Exception as e:
            print(f"Error fetching coordinator data: {e}")
        finally:
            cursor.close()
            connection.close()
    
    html = rf'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Coordinator Panel - Themis</title>
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
                --success-color: #4ade80;
                --warning-color: #fbbf24;
                --error-color: #f87171;
                --info-color: #60a5fa;
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
                min-height: 100vh;
            }}
            
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                padding: 40px 20px;
            }}
            
            .header {{
                margin-bottom: 48px;
            }}
            
            .page-title {{
                font-size: 3rem;
                font-weight: 800;
                background: linear-gradient(135deg, var(--text-primary) 0%, var(--primary-color) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 16px;
            }}
            
            .page-subtitle {{
                font-size: 1.1rem;
                color: var(--text-secondary);
            }}
            
            .back-btn {{
                display: inline-flex;
                align-items: center;
                gap: 8px;
                color: var(--text-secondary);
                text-decoration: none;
                margin-bottom: 32px;
                transition: all 0.2s ease;
            }}
            
            .back-btn:hover {{
                color: var(--primary-color);
                transform: translateX(-4px);
            }}
            
            .panels-grid {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 32px;
                margin-bottom: 40px;
            }}
            
            .panel {{
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid var(--border-color);
                border-radius: 20px;
                padding: 32px;
                backdrop-filter: var(--backdrop-blur);
            }}
            
            .panel-title {{
                font-size: 1.5rem;
                font-weight: 700;
                margin-bottom: 24px;
                color: var(--text-primary);
            }}
            
            .assignment-list {{
                display: flex;
                flex-direction: column;
                gap: 16px;
                max-height: 400px;
                overflow-y: auto;
            }}
            
            .assignment-item {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 20px;
                transition: all 0.2s ease;
                cursor: pointer;
            }}
            
            .assignment-item:hover {{
                border-color: var(--primary-color);
                transform: translateY(-2px);
                box-shadow: var(--shadow-primary);
            }}
            
            .assignment-header {{
                display: flex;
                justify-content: space-between;
                align-items: flex-start;
                margin-bottom: 12px;
            }}
            
            .assignment-title {{
                font-weight: 600;
                font-size: 1.1rem;
                color: var(--text-primary);
                margin-bottom: 4px;
            }}
            
            .assignment-from {{
                font-size: 0.85rem;
                color: var(--text-muted);
            }}
            
            .assignment-status {{
                padding: 6px 12px;
                border-radius: 6px;
                font-size: 0.8rem;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            
            .status-open {{
                background: rgba(96, 165, 250, 0.2);
                color: var(--info-color);
                border: 1px solid rgba(96, 165, 250, 0.3);
            }}
            
            .status-in_progress {{
                background: rgba(251, 191, 36, 0.2);
                color: var(--warning-color);
                border: 1px solid rgba(251, 191, 36, 0.3);
            }}
            
            .status-overdue {{
                background: rgba(248, 113, 113, 0.2);
                color: var(--error-color);
                border: 1px solid rgba(248, 113, 113, 0.3);
            }}
            
            .status-finished {{
                background: rgba(74, 222, 128, 0.2);
                color: var(--success-color);
                border: 1px solid rgba(74, 222, 128, 0.3);
            }}
            
            .assignment-meta {{
                display: flex;
                gap: 16px;
                font-size: 0.85rem;
                color: var(--text-secondary);
                margin-bottom: 12px;
            }}
            
            .assignment-description {{
                font-size: 0.9rem;
                color: var(--text-secondary);
                line-height: 1.5;
                margin-bottom: 16px;
                max-height: 60px;
                overflow: hidden;
                text-overflow: ellipsis;
            }}
            
            .assignment-actions {{
                display: flex;
                gap: 12px;
            }}
            
            .btn {{
                background: var(--primary-color);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 8px 16px;
                font-size: 0.85rem;
                font-weight: 500;
                cursor: pointer;
                transition: all 0.2s ease;
                text-decoration: none;
                display: inline-flex;
                align-items: center;
                gap: 6px;
            }}
            
            .btn:hover {{
                transform: translateY(-1px);
                box-shadow: var(--shadow-primary);
            }}
            
            .btn-secondary {{
                background: rgba(255, 255, 255, 0.08);
                color: var(--text-primary);
                border: 1px solid rgba(255, 255, 255, 0.2);
            }}
            
            .btn-secondary:hover {{
                background: rgba(255, 255, 255, 0.12);
            }}
            
            .btn-success {{
                background: var(--success-color);
                color: black;
            }}
            
            .message-list {{
                display: flex;
                flex-direction: column;
                gap: 12px;
                max-height: 400px;
                overflow-y: auto;
            }}
            
            .message-item {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 16px;
            }}
            
            .message-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 8px;
            }}
            
            .message-from {{
                font-weight: 600;
                color: var(--text-primary);
                font-size: 0.9rem;
            }}
            
            .message-time {{
                font-size: 0.8rem;
                color: var(--text-muted);
            }}
            
            .message-content {{
                font-size: 0.9rem;
                color: var(--text-secondary);
                line-height: 1.4;
            }}
            
            .message-assignment {{
                font-size: 0.8rem;
                color: var(--primary-color);
                margin-top: 4px;
            }}
            
            .empty-state {{
                text-align: center;
                padding: 40px 20px;
                color: var(--text-muted);
            }}
            
            .empty-state svg {{
                width: 48px;
                height: 48px;
                margin-bottom: 16px;
                opacity: 0.3;
            }}
            
            .loading {{
                display: none;
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                background: rgba(0, 0, 0, 0.8);
                padding: 20px;
                border-radius: 8px;
                z-index: 1000;
            }}
            
            .loading.active {{
                display: block;
            }}
            
            @media (max-width: 768px) {{
                .panels-grid {{
                    grid-template-columns: 1fr;
                }}
                
                .container {{
                    padding: 20px 16px;
                }}
                
                .page-title {{
                    font-size: 2rem;
                }}
                
                .assignment-header {{
                    flex-direction: column;
                    align-items: flex-start;
                    gap: 8px;
                }}
                
                .assignment-actions {{
                    flex-wrap: wrap;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="loading" id="loadingIndicator">
            <div style="color: white;">Processing...</div>
        </div>
        
        <div class="container">
            <a href="/admin/dashboard" class="back-btn">
                <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd"/>
                </svg>
                Back to Dashboard
            </a>
            
            <div class="header">
                <h1 class="page-title">Coordinator Panel</h1>
                <p class="page-subtitle">View your assignments and stay updated with messages from supervisors</p>
            </div>
            
            <div class="panels-grid">
                <div class="panel">
                    <h2 class="panel-title">My Assignments</h2>
                    
                    <div class="assignment-list">
                        {generate_coordinator_assignments_html(assignments)}
                    </div>
                </div>
                
                <div class="panel">
                    <h2 class="panel-title">Recent Messages</h2>
                    
                    <div class="message-list">
                        {generate_coordinator_messages_html(messages)}
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            async function updateAssignmentStatus(assignmentId, newStatus) {{
                const loadingIndicator = document.getElementById('loadingIndicator');
                loadingIndicator.classList.add('active');
                
                try {{
                    const response = await fetch('/api/coordinator/assignment/status', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{
                            assignment_id: assignmentId,
                            status: newStatus
                        }})
                    }});
                    
                    const data = await response.json();
                    
                    if (data.success) {{
                        window.location.reload();
                    }} else {{
                        alert('Error updating assignment: ' + (data.error || 'Unknown error'));
                    }}
                }} catch (error) {{
                    alert('Error: ' + error.message);
                }} finally {{
                    loadingIndicator.classList.remove('active');
                }}
            }}
            
            async function sendMessage(assignmentId) {{
                const message = prompt('Enter your message to the supervisor:');
                if (!message) return;
                
                const loadingIndicator = document.getElementById('loadingIndicator');
                loadingIndicator.classList.add('active');
                
                try {{
                    const response = await fetch('/api/coordinator/send-message', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                        }},
                        body: JSON.stringify({{
                            assignment_id: assignmentId,
                            message: message
                        }})
                    }});
                    
                    const data = await response.json();
                    
                    if (data.success) {{
                        alert('Message sent successfully');
                    }} else {{
                        alert('Error sending message');
                    }}
                }} catch (error) {{
                    alert('Error: ' + error.message);
                }} finally {{
                    loadingIndicator.classList.remove('active');
                }}
            }}
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(html)

# Helper function to generate coordinator assignments HTML
def generate_coordinator_assignments_html(assignments):
    if not assignments:
        return '''
        <div class="empty-state">
            <svg fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M4 4a2 2 0 012-2h8a2 2 0 012 2v12a2 2 0 01-2 2H6a2 2 0 01-2-2V4zm3 1h6v4H7V5zm8 8v2h1v-2h-1zm-1-1h1v-2h-1v2zm1-4h-1V6h1v2zM7 8h6v4H7V8z" clip-rule="evenodd"/>
            </svg>
            <p>No assignments available at the moment</p>
        </div>
        '''
    
    html = ''
    for assignment in assignments:
        due_date = assignment.get('due_date')
        time_until_due = format_time_until(due_date) if due_date else 'No due date'
        status_class = f"status-{assignment['display_status']}"
        
        # Determine available actions based on status
        actions = ''
        if assignment['status'] == 'open':
            actions = f'''
            <button class="btn btn-secondary" onclick="updateAssignmentStatus({assignment['id']}, 'in_progress')">
                Start Working
            </button>
            <button class="btn btn-secondary" onclick="sendMessage({assignment['id']})">
                Contact Supervisor
            </button>
            '''
        elif assignment['status'] == 'in_progress':
            actions = f'''
            <button class="btn btn-success" onclick="updateAssignmentStatus({assignment['id']}, 'finished')">
                Mark Complete
            </button>
            <button class="btn btn-secondary" onclick="sendMessage({assignment['id']})">
                Contact Supervisor
            </button>
            '''
        elif assignment['status'] in ['finished', 'verified']:
            actions = f'''
            <button class="btn btn-secondary" onclick="sendMessage({assignment['id']})">
                Contact Supervisor
            </button>
            '''
        
        html += f'''
        <div class="assignment-item">
            <div class="assignment-header">
                <div>
                    <div class="assignment-title">{assignment['title']}</div>
                    <div class="assignment-from">From: {assignment['created_by_name']}</div>
                </div>
                <div class="assignment-status {status_class}">{assignment['display_status'].replace('_', ' ').title()}</div>
            </div>
            
            <div class="assignment-meta">
                <span>Priority: {assignment['priority'].title()}</span>
                <span>Due: {time_until_due}</span>
                {f"<span>Team: {assignment['group_name']}</span>" if assignment.get('group_name') else ''}
            </div>
            
            <div class="assignment-description">{assignment.get('description', 'No description provided.')}</div>
            
            <div class="assignment-actions">
                {actions}
            </div>
        </div>
        '''
    
    return html

# Helper function to generate coordinator messages HTML
def generate_coordinator_messages_html(messages):
    if not messages:
        return '''
        <div class="empty-state">
            <svg fill="currentColor" viewBox="0 0 20 20">
                <path d="M2.003 5.884L10 9.882l7.997-3.998A2 2 0 0016 4H4a2 2 0 00-1.997 1.884z"/>
                <path d="M18 8.118l-8 4-8-4V14a2 2 0 002 2h12a2 2 0 002-2V8.118z"/>
            </svg>
            <p>No messages yet</p>
        </div>
        '''
    
    html = ''
    for message in messages:
        time_ago = format_time_ago(message['created_at'])
        
        html += f'''
        <div class="message-item">
            <div class="message-header">
                <div class="message-from">{message['sender_name']}</div>
                <div class="message-time">{time_ago}</div>
            </div>
            <div class="message-content">{message['message']}</div>
            {f'<div class="message-assignment">Re: {message["assignment_title"]}</div>' if message.get('assignment_title') else ''}
        </div>
        '''
    
    return html

# Executive Director Overview Route
@app.route('/admin/coordination/executive')
@login_required
@staff_required
def executive_director_panel():
    user = session['user']
    staff_role = user.get('staff_info', {}).get('role', 'Staff')
    
    if staff_role not in ['Executive Director', 'Administration Director']:
        return "Access Denied", 403
    
    # Get overview data
    overview_data = get_executive_overview()
    if not overview_data:
        overview_data = {
            'stats': {'total': 0, 'verified': 0, 'pending_verification': 0, 'delayed': 0},
            'divisions': [],
            'assignments': []
        }
    
    stats = overview_data['stats']
    divisions = overview_data['divisions']
    assignments = overview_data['assignments']
    
    html = rf'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Executive Director Overview - Themis</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <style>
            /* Include all the styles from the previous executive panel */
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
                --success-color: #4ade80;
                --warning-color: #fbbf24;
                --error-color: #f87171;
                --info-color: #60a5fa;
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
                min-height: 100vh;
            }}
            
            .container {{
                max-width: 1600px;
                margin: 0 auto;
                padding: 40px 20px;
            }}
            
            .header {{
                margin-bottom: 48px;
            }}
            
            .page-title {{
                font-size: 3.5rem;
                font-weight: 800;
                background: linear-gradient(135deg, var(--text-primary) 0%, var(--primary-color) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 16px;
            }}
            
            .page-subtitle {{
                font-size: 1.2rem;
                color: var(--text-secondary);
            }}
            
            .overview-stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 24px;
                margin-bottom: 48px;
            }}
            
            .stat-card {{
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 24px;
                backdrop-filter: var(--backdrop-blur);
                position: relative;
                overflow: hidden;
            }}
            
            .stat-card::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 4px;
                background: linear-gradient(90deg, var(--primary-color) 0%, #d946ef 100%);
            }}
            
            .stat-value {{
                font-size: 2.5rem;
                font-weight: 800;
                margin-bottom: 8px;
            }}
            
            .stat-label {{
                color: var(--text-secondary);
                font-size: 0.9rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            
            .divisions-overview {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
                gap: 32px;
                margin-bottom: 48px;
            }}
            
            .division-card {{
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid var(--border-color);
                border-radius: 20px;
                padding: 32px;
                backdrop-filter: var(--backdrop-blur);
            }}
            
            .division-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 24px;
            }}
            
            .division-name {{
                font-size: 1.5rem;
                font-weight: 700;
            }}
            
            .division-status {{
                padding: 6px 16px;
                border-radius: 6px;
                font-size: 0.85rem;
                font-weight: 600;
            }}
            
            .status-active {{
                background: rgba(74, 222, 128, 0.2);
                color: var(--success-color);
                border: 1px solid rgba(74, 222, 128, 0.3);
            }}
            
            .division-metrics {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 16px;
            }}
            
            .metric {{
                background: rgba(255, 255, 255, 0.05);
                border-radius: 8px;
                padding: 16px;
            }}
            
            .metric-value {{
                font-size: 1.5rem;
                font-weight: 700;
                color: var(--primary-color);
            }}
            
            .metric-label {{
                font-size: 0.8rem;
                color: var(--text-muted);
                text-transform: uppercase;
            }}
            
            .assignments-overview {{
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid var(--border-color);
                border-radius: 20px;
                padding: 32px;
                backdrop-filter: var(--backdrop-blur);
            }}
            
            .section-title {{
                font-size: 1.75rem;
                font-weight: 700;
                margin-bottom: 24px;
            }}
            
            .assignments-list {{
                display: grid;
                gap: 16px;
            }}
            
            .assignment-row {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 20px;
                display: grid;
                grid-template-columns: 2fr 1fr 1fr 1fr 150px;
                align-items: center;
                gap: 16px;
                transition: all 0.2s ease;
            }}
            
            .assignment-row:hover {{
                border-color: var(--primary-color);
                transform: translateX(4px);
            }}
            
            .assignment-title {{
                font-weight: 600;
            }}
            
            .assignment-division {{
                font-size: 0.85rem;
                color: var(--text-secondary);
            }}
            
            .assignment-assignee {{
                font-size: 0.9rem;
                color: var(--text-secondary);
            }}
            
            .assignment-date {{
                font-size: 0.85rem;
                color: var(--text-muted);
            }}
            
            .status-badge {{
                padding: 6px 16px;
                border-radius: 6px;
                font-size: 0.85rem;
                font-weight: 600;
                text-align: center;
            }}
            
            .status-open {{
                background: rgba(96, 165, 250, 0.2);
                color: var(--info-color);
                border: 1px solid rgba(96, 165, 250, 0.3);
            }}
            
            .status-finished {{
                background: rgba(251, 191, 36, 0.2);
                color: var(--warning-color);
                border: 1px solid rgba(251, 191, 36, 0.3);
            }}
            
            .status-verified {{
                background: rgba(74, 222, 128, 0.2);
                color: var(--success-color);
                border: 1px solid rgba(74, 222, 128, 0.3);
            }}
            
            .status-delayed {{
                background: rgba(248, 113, 113, 0.2);
                color: var(--error-color);
                border: 1px solid rgba(248, 113, 113, 0.3);
            }}
            
            .filters {{
                display: flex;
                gap: 16px;
                margin-bottom: 24px;
                flex-wrap: wrap;
            }}
            
            .filter-btn {{
                background: rgba(255, 255, 255, 0.08);
                border: 1px solid rgba(255, 255, 255, 0.2);
                color: var(--text-primary);
                padding: 8px 16px;
                border-radius: 8px;
                font-size: 0.9rem;
                cursor: pointer;
                transition: all 0.2s ease;
            }}
            
            .filter-btn:hover {{
                background: rgba(255, 255, 255, 0.12);
                border-color: var(--primary-color);
            }}
            
            .filter-btn.active {{
                background: var(--primary-color);
                color: white;
                border-color: var(--primary-color);
            }}
            
            .back-btn {{
                display: inline-flex;
                align-items: center;
                gap: 8px;
                color: var(--text-secondary);
                text-decoration: none;
                margin-bottom: 32px;
                transition: all 0.2s ease;
            }}
            
            .back-btn:hover {{
                color: var(--primary-color);
                transform: translateX(-4px);
            }}
            
            @media (max-width: 1200px) {{
                .assignment-row {{
                    grid-template-columns: 1fr;
                    gap: 12px;
                }}
                
                .assignment-row > div {{
                    display: flex;
                    justify-content: space-between;
                }}
                
                .assignment-row > div::before {{
                    content: attr(data-label);
                    font-weight: 600;
                    color: var(--text-secondary);
                }}
            }}
            
            @media (max-width: 768px) {{
                .container {{
                    padding: 20px 16px;
                }}
                
                .page-title {{
                    font-size: 2.5rem;
                }}
                
                .overview-stats {{
                    grid-template-columns: 1fr 1fr;
                }}
                
                .divisions-overview {{
                    grid-template-columns: 1fr;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/admin/dashboard" class="back-btn">
                <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20">
                    <path fill-rule="evenodd" d="M9.707 16.707a1 1 0 01-1.414 0l-6-6a1 1 0 010-1.414l6-6a1 1 0 011.414 1.414L5.414 9H17a1 1 0 110 2H5.414l4.293 4.293a1 1 0 010 1.414z" clip-rule="evenodd"/>
                </svg>
                Back to Dashboard
            </a>
            
            <div class="header">
                <h1 class="page-title">Executive Overview</h1>
                <p class="page-subtitle">Monitor all divisions, assignments, and organizational performance</p>
            </div>
            
            <div class="overview-stats">
                <div class="stat-card">
                    <div class="stat-value">{stats['total']}</div>
                    <div class="stat-label">Total Assignments</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value">{stats['verified']}</div>
                    <div class="stat-label">Verified Assignments</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value">{stats['pending_verification']}</div>
                    <div class="stat-label">Pending Verification</div>
                </div>
                
                <div class="stat-card">
                    <div class="stat-value">{stats['delayed']}</div>
                    <div class="stat-label">Delayed Assignments</div>
                </div>
            </div>
            
            <div class="divisions-overview">
                {generate_divisions_html(divisions)}
            </div>
            
            <div class="assignments-overview">
                <h2 class="section-title">All Assignments</h2>
                
                <div class="filters">
                    <button class="filter-btn active" onclick="filterAssignments('all')">All</button>
                    <button class="filter-btn" onclick="filterAssignments('verified')">Verified</button>
                    <button class="filter-btn" onclick="filterAssignments('finished')">Awaiting Verification</button>
                    <button class="filter-btn" onclick="filterAssignments('open')">Open</button>
                    <button class="filter-btn" onclick="filterAssignments('delayed')">Delayed</button>
                </div>
                
                <div class="assignments-list" id="assignmentsList">
                    {generate_executive_assignments_html(assignments)}
                </div>
            </div>
        </div>
        
        <script>
            function filterAssignments(status) {{
                // Update active filter button
                document.querySelectorAll('.filter-btn').forEach(btn => {{
                    btn.classList.remove('active');
                }});
                event.target.classList.add('active');
                
                // Filter assignments
                const assignments = document.querySelectorAll('.assignment-row');
                assignments.forEach(assignment => {{
                    if (status === 'all') {{
                        assignment.style.display = 'grid';
                    }} else {{
                        assignment.style.display = assignment.dataset.status === status ? 'grid' : 'none';
                    }}
                }});
            }}
            
            // Auto-refresh every 30 seconds
            setInterval(() => {{
                window.location.reload();
            }}, 30000);
        </script>
    </body>
    </html>
    '''
    
    return render_template_string(html)

def generate_divisions_html(divisions):
    if not divisions:
        return '''
        <div class="division-card">
            <div class="division-header">
                <h3 class="division-name">No Active Divisions</h3>
            </div>
            <p style="color: var(--text-muted);">No division data available</p>
        </div>
        '''
    
    html = ''
    for division in divisions:
        completion_rate = int(division.get('completion_rate', 0))
        html += f'''
        <div class="division-card">
            <div class="division-header">
                <h3 class="division-name">{division['division']}</h3>
                <div class="division-status status-active">Active</div>
            </div>
            <div class="division-metrics">
                <div class="metric">
                    <div class="metric-value">{division['active_assignments']}</div>
                    <div class="metric-label">Active Assignments</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{division['teams']}</div>
                    <div class="metric-label">Teams</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{division['members']}</div>
                    <div class="metric-label">Members</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{completion_rate}%</div>
                    <div class="metric-label">Completion Rate</div>
                </div>
            </div>
        </div>
        '''
    
    return html

def generate_executive_assignments_html(assignments):
    if not assignments:
        return '<p style="text-align: center; color: var(--text-muted);">No assignments to display</p>'
    
    html = ''
    for assignment in assignments:
        status_class = f"status-{assignment['status']}"
        date_info = format_assignment_date(assignment)
        
        html += f'''
        <div class="assignment-row" data-status="{assignment['status']}">
            <div data-label="Assignment">
                <div class="assignment-title">{assignment['title']}</div>
                <div class="assignment-division">{assignment['division']}</div>
            </div>
            <div data-label="Assigned To" class="assignment-assignee">{assignment['assigned_to_name']}</div>
            <div data-label="Team" class="assignment-assignee">{assignment['group_name'] or 'No Team'}</div>
            <div data-label="Date" class="assignment-date">{date_info}</div>
            <div data-label="Status" class="status-badge {status_class}">{format_status(assignment['status'])}</div>
        </div>
        '''
    
    return html

def format_assignment_date(assignment):
    if assignment['status'] == 'verified' and assignment.get('verified_at'):
        return f"Verified {format_time_ago(assignment['verified_at'])}"
    elif assignment['status'] == 'finished' and assignment.get('finished_at'):
        return f"Completed {format_time_ago(assignment['finished_at'])}"
    elif assignment['status'] == 'delayed' and assignment.get('due_date'):
        return f"{format_time_until(assignment['due_date'])}"
    elif assignment.get('due_date'):
        return f"Due {format_time_until(assignment['due_date'])}"
    else:
        return format_time_ago(assignment['created_at'])

def format_status(status):
    status_map = {
        'open': 'Open',
        'in_progress': 'In Progress',
        'finished': 'Awaiting Verification',
        'verified': 'Verified',
        'delayed': 'Delayed'
    }
    return status_map.get(status, status.title())

# Check for delayed assignments periodically (you might want to run this as a scheduled job)
html3424 = '''check_and_update_delayed_assignments()
                text-primary);
                line-height: 1.6;
                overflow-x: hidden;
                min-height: 100vh;
            }}
            
            .container {{
                max-width: 1400px;
                margin: 0 auto;
                padding: 40px 20px;
            }}
            
            .header {{
                margin-bottom: 48px;
            }}
            
            .page-title {{
                font-size: 3rem;
                font-weight: 800;
                background: linear-gradient(135deg, var(--text-primary) 0%, var(--primary-color) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
                margin-bottom: 16px;
            }}
            
            .page-subtitle {{
                font-size: 1.1rem;
                color: var(--text-secondary);
            }}
            
            .panels-grid {{
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 32px;
                margin-bottom: 40px;
            }}
            
            .panel {{
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid var(--border-color);
                border-radius: 20px;
                padding: 32px;
                backdrop-filter: var(--backdrop-blur);
            }}
            
            .panel-title {{
                font-size: 1.5rem;
                font-weight: 700;
                margin-bottom: 24px;
                color: var(--text-primary);
            }}
            
            .team-members-list {{
                display: flex;
                flex-direction: column;
                gap: 12px;
                max-height: 400px;
                overflow-y: auto;
            }}
            
            .member-item {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 16px;
                display: flex;
                align-items: center;
                gap: 12px;
                transition: all 0.2s ease;
                cursor: pointer;
            }}
            
            .member-item:hover {{
                border-color: var(--primary-color);
                transform: translateX(4px);
            }}
            
            .member-item.selected {{
                background: rgba(var(--primary-rgb), 0.2);
                border-color: var(--primary-color);
            }}
            
            .member-checkbox {{
                width: 20px;
                height: 20px;
                accent-color: var(--primary-color);
            }}
            
            .member-info {{
                flex: 1;
            }}
            
            .member-name {{
                font-weight: 600;
                color: var(--text-primary);
            }}
            
            .member-role {{
                font-size: 0.85rem;
                color: var(--text-secondary);
            }}
            
            .member-role.senior {{
                color: #fbbf24;
            }}
            
            .member-role.coordinator {{
                color: #60a5fa;
            }}
            
            .create-group-section {{
                margin-top: 32px;
                padding-top: 32px;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
            }}
            
            .form-group {{
                margin-bottom: 24px;
            }}
            
            .form-label {{
                display: block;
                margin-bottom: 8px;
                font-weight: 500;
                color: var(--text-secondary);
            }}
            
            .form-input {{
                width: 100%;
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 8px;
                padding: 12px 16px;
                color: var(--text-primary);
                font-size: 1rem;
                transition: all 0.2s ease;
            }}
            
            .form-input:focus {{
                outline: none;
                border-color: var(--primary-color);
                background: rgba(255, 255, 255, 0.08);
            }}
            
            .btn {{
                background: var(--primary-color);
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-size: 1rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.2s ease;
                display: inline-flex;
                align-items: center;
                gap: 8px;
            }}
            
            .btn:hover {{
                transform: translateY(-2px);
                box-shadow: var(--shadow-primary);
            }}
            
            .btn:disabled {{
                opacity: 0.5;
                cursor: not-allowed;
            }}
            
            .groups-display {{
                display: grid;
                gap: 24px;
            }}
            
            .group-card {{
                background: rgba(255, 255, 255, 0.04);
                border: 1px solid var(--border-color);
                border-radius: 16px;
                padding: 24px;
                position: relative;
            }}
            
            .group-name {{
                font-size: 1.25rem;
                font-weight: 700;
                margin-bottom: 16px;
                color: var(--primary-color);
            }}
            
            .group-structure {{
                display: flex;
                flex-direction: column;
                gap: 20px;
            }}
            
            .hierarchy-level {{
                position: relative;
                padding-left: 32px;
            }}
            
            .hierarchy-level::before {{
                content: '';
                position: absolute;
                left: 0;
                top: 0;
                bottom: 0;
                width: 2px;
                background: var(--primary-color);
                opacity: 0.3;
            }}
            
            .hierarchy-title {{
                font-weight: 600;
                color: var(--text-secondary);
                margin-bottom: 8px;
                font-size: 0.9rem;
                text-transform: uppercase;
                letter-spacing: 0.05em;
            }}
            
            .hierarchy-members {{
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
            }}
            
            .member-badge {{
                background: rgba(var(--primary-rgb), 0.1);
                border: 1px solid rgba(var(--primary-rgb), 0.3);
                padding: 6px 12px;
                border-radius: 6px;
                font-size: 0.85rem;
                font-weight: 500;
            }}
            
            .assignments-panel {{
                grid-column: 1 / -1;
            }}
            
            .assignment-item {{
                background: rgba(255, 255, 255, 0.05);
                border: 1px solid rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 20px;
                margin-bottom: 16px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            
            .assignment-info {{
                flex: 1;
            }}
            
            .assignment-title {{
                font-weight: 600;
                margin-bottom: 4px;
            }}
            
            .assignment-group {{
                font-size: 0.85rem;
                color: var(--
''' # gonna finish later
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
        if project not in ['discord', 'arenamadness', 'contractors']:
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

# API routes for coordinator actions
@app.route('/api/coordinator/assignment/status', methods=['POST'])
@login_required
@staff_required
def update_coordinator_assignment_status():
    user = session['user']
    data = request.get_json()
    assignment_id = data.get('assignment_id')
    new_status = data.get('status')
    
    if not assignment_id or not new_status:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    # Validate status
    valid_statuses = ['in_progress', 'finished']
    if new_status not in valid_statuses:
        return jsonify({'success': False, 'error': 'Invalid status'}), 400
    
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            
            # Verify the assignment belongs to this user
            cursor.execute("""
                SELECT id FROM assignments 
                WHERE id = %s AND assigned_to = %s
            """, (assignment_id, user['id']))
            
            if not cursor.fetchone():
                return jsonify({'success': False, 'error': 'Assignment not found or not assigned to you'}), 403
            
            # Update the assignment status
            if new_status == 'finished':
                cursor.execute("""
                    UPDATE assignments 
                    SET status = %s, finished_at = NOW()
                    WHERE id = %s
                """, (new_status, assignment_id))
            else:
                cursor.execute("""
                    UPDATE assignments 
                    SET status = %s
                    WHERE id = %s
                """, (new_status, assignment_id))
            
            # Log the action
            cursor.execute("""
                INSERT INTO assignment_actions (assignment_id, user_id, action_type, action_data)
                VALUES (%s, %s, 'status_change', %s)
            """, (assignment_id, user['id'], json.dumps({'new_status': new_status})))
            
            connection.commit()
            return jsonify({'success': True})
            
        except Exception as e:
            connection.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            cursor.close()
            connection.close()
    
    return jsonify({'success': False, 'error': 'Database connection failed'}), 500

@app.route('/api/coordinator/send-message', methods=['POST'])
@login_required
@staff_required
def coordinator_send_message():
    user = session['user']
    data = request.get_json()
    assignment_id = data.get('assignment_id')
    message = data.get('message')
    
    if not assignment_id or not message:
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400
    
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Get the assignment and find the supervisor
            cursor.execute("""
                SELECT created_by FROM assignments 
                WHERE id = %s AND assigned_to = %s
            """, (assignment_id, user['id']))
            
            assignment = cursor.fetchone()
            if not assignment:
                return jsonify({'success': False, 'error': 'Assignment not found or not assigned to you'}), 403
            
            # Send message to the supervisor
            cursor.execute("""
                INSERT INTO coordination_messages 
                (sender_id, recipient_id, message, assignment_id)
                VALUES (%s, %s, %s, %s)
            """, (user['id'], assignment['created_by'], message, assignment_id))
            
            # Log the action
            cursor.execute("""
                INSERT INTO assignment_actions (assignment_id, user_id, action_type, action_data)
                VALUES (%s, %s, 'contact_director', %s)
            """, (assignment_id, user['id'], json.dumps({'message': message})))
            
            connection.commit()
            return jsonify({'success': True})
            
        except Exception as e:
            connection.rollback()
            return jsonify({'success': False, 'error': str(e)}), 500
        finally:
            cursor.close()
            connection.close()
    
    return jsonify({'success': False, 'error': 'Database connection failed'}), 500

if __name__ == '__main__':
    app.run(debug=False)

