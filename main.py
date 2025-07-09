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

# Database table creation SQL
COORDINATION_TABLES_SQL = """
-- Groups table for storing team groups
CREATE TABLE IF NOT EXISTS coordination_groups (
    id INT AUTO_INCREMENT PRIMARY KEY,
    group_name VARCHAR(255) NOT NULL,
    division VARCHAR(100) NOT NULL,
    created_by INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- Group members table for storing group hierarchy
CREATE TABLE IF NOT EXISTS group_members (
    id INT AUTO_INCREMENT PRIMARY KEY,
    group_id INT NOT NULL,
    user_id INT NOT NULL,
    role VARCHAR(50) NOT NULL, -- 'Senior Coordinator' or 'Coordinator'
    role_label VARCHAR(255) DEFAULT NULL, -- Custom label assigned by Senior Coordinator
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES coordination_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE KEY unique_group_member (group_id, user_id)
);

-- Assignments table
CREATE TABLE IF NOT EXISTS assignments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    division VARCHAR(100) NOT NULL,
    group_id INT DEFAULT NULL,
    assigned_to INT DEFAULT NULL, -- Senior Coordinator
    created_by INT NOT NULL, -- Director who created it
    priority ENUM('low', 'medium', 'high') DEFAULT 'medium',
    status ENUM('open', 'in_progress', 'finished', 'verified', 'delayed') DEFAULT 'open',
    due_date DATETIME DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    finished_at DATETIME DEFAULT NULL,
    verified_at DATETIME DEFAULT NULL,
    verified_by INT DEFAULT NULL,
    FOREIGN KEY (group_id) REFERENCES coordination_groups(id),
    FOREIGN KEY (assigned_to) REFERENCES users(id),
    FOREIGN KEY (created_by) REFERENCES users(id),
    FOREIGN KEY (verified_by) REFERENCES users(id)
);

-- Assignment actions/comments
CREATE TABLE IF NOT EXISTS assignment_actions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    assignment_id INT NOT NULL,
    user_id INT NOT NULL,
    action_type ENUM('comment', 'status_change', 'contact_director', 'assignment') NOT NULL,
    action_data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assignment_id) REFERENCES assignments(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Messages between directors and coordinators
CREATE TABLE IF NOT EXISTS coordination_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    assignment_id INT DEFAULT NULL,
    sender_id INT NOT NULL,
    recipient_id INT NOT NULL,
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (assignment_id) REFERENCES assignments(id),
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (recipient_id) REFERENCES users(id)
);
"""

# Backend functions for the coordination system
import mysql.connector
from mysql.connector import Error
from datetime import datetime, timedelta
import json

def init_coordination_tables():
    """Initialize all coordination system tables"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            # Split the SQL into individual statements
            for statement in COORDINATION_TABLES_SQL.strip().split(';'):
                if statement.strip():
                    cursor.execute(statement + ';')
            connection.commit()
            print("Coordination tables created successfully")
            return True
        except Error as e:
            print(f"Error creating tables: {e}")
            return False
        finally:
            cursor.close()
            connection.close()
    return False

# Group Management Functions
def create_group(group_name, division, created_by, members):
    """
    Create a new group with members
    members = [{'user_id': 1, 'role': 'Senior Coordinator'}, ...]
    """
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            
            # Create the group
            cursor.execute("""
                INSERT INTO coordination_groups (group_name, division, created_by)
                VALUES (%s, %s, %s)
            """, (group_name, division, created_by))
            
            group_id = cursor.lastrowid
            
            # Add members to the group
            for member in members:
                cursor.execute("""
                    INSERT INTO group_members (group_id, user_id, role)
                    VALUES (%s, %s, %s)
                """, (group_id, member['user_id'], member['role']))
            
            connection.commit()
            return group_id
        except Error as e:
            connection.rollback()
            print(f"Error creating group: {e}")
            return None
        finally:
            cursor.close()
            connection.close()
    return None

def get_director_groups(director_id, division):
    """Get all groups created by a director"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("""
                SELECT g.*, 
                    (SELECT COUNT(*) FROM group_members WHERE group_id = g.id) as member_count
                FROM coordination_groups g
                WHERE g.created_by = %s AND g.division = %s AND g.is_active = TRUE
                ORDER BY g.created_at DESC
            """, (director_id, division))
            
            groups = cursor.fetchall()
            
            # Get members for each group
            for group in groups:
                cursor.execute("""
                    SELECT gm.*, u.username, u.avatar_url
                    FROM group_members gm
                    JOIN users u ON gm.user_id = u.id
                    WHERE gm.group_id = %s
                    ORDER BY gm.role DESC, u.username
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

def get_team_members(division):
    """Get all team members in a division for group creation"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("""
                SELECT u.id, u.username, u.avatar_url, s.role
                FROM users u
                JOIN staff s ON u.id = s.user_id
                WHERE s.division = %s 
                AND s.role IN ('Senior Coordinator', 'Coordinator')
                AND s.is_active = TRUE
                ORDER BY 
                    CASE 
                        WHEN s.role = 'Senior Coordinator' THEN 1
                        WHEN s.role = 'Coordinator' THEN 2
                    END,
                    u.username
            """, (division,))
            return cursor.fetchall()
        except Error as e:
            print(f"Error fetching team members: {e}")
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

# Assignment Management Functions
def create_assignment(title, description, division, group_id, assigned_to, created_by, priority='medium', due_days=7):
    """Create a new assignment"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            due_date = datetime.now() + timedelta(days=due_days)
            
            cursor.execute("""
                INSERT INTO assignments 
                (title, description, division, group_id, assigned_to, created_by, priority, due_date)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (title, description, division, group_id, assigned_to, created_by, priority, due_date))
            
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

def get_senior_coordinator_assignments(user_id):
    """Get assignments for a Senior Coordinator"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("""
                SELECT a.*, u.username as created_by_name, g.group_name
                FROM assignments a
                JOIN users u ON a.created_by = u.id
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

def get_director_assignments(director_id, division):
    """Get assignments for director verification"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("""
                SELECT a.*, u.username as assigned_to_name, g.group_name
                FROM assignments a
                JOIN users u ON a.assigned_to = u.id
                LEFT JOIN coordination_groups g ON a.group_id = g.id
                WHERE a.division = %s AND a.status = 'finished'
                ORDER BY a.finished_at DESC
            """, (division,))
            return cursor.fetchall()
        except Error as e:
            print(f"Error fetching assignments: {e}")
            return []
        finally:
            cursor.close()
            connection.close()
    return []

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

def get_executive_overview():
    """Get executive dashboard overview data"""
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
                    SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open,
                    SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress
                FROM assignments
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            """)
            stats = cursor.fetchone()
            
            # Get division breakdown
            cursor.execute("""
                SELECT 
                    division,
                    COUNT(DISTINCT a.id) as active_assignments,
                    COUNT(DISTINCT g.id) as teams,
                    COUNT(DISTINCT gm.user_id) as members,
                    AVG(CASE WHEN a.status = 'verified' THEN 100 ELSE 0 END) as completion_rate
                FROM coordination_groups g
                LEFT JOIN assignments a ON g.division = a.division
                LEFT JOIN group_members gm ON g.id = gm.group_id
                WHERE g.is_active = TRUE
                GROUP BY division
            """)
            divisions = cursor.fetchall()
            
            # Get recent assignments with details
            cursor.execute("""
                SELECT 
                    a.*,
                    u1.username as assigned_to_name,
                    u2.username as created_by_name,
                    g.group_name
                FROM assignments a
                JOIN users u1 ON a.assigned_to = u1.id
                JOIN users u2 ON a.created_by = u2.id
                LEFT JOIN coordination_groups g ON a.group_id = g.id
                ORDER BY a.updated_at DESC
                LIMIT 50
            """)
            assignments = cursor.fetchall()
            
            return {
                'stats': stats,
                'divisions': divisions,
                'assignments': assignments
            }
        except Error as e:
            print(f"Error fetching overview: {e}")
            return None
        finally:
            cursor.close()
            connection.close()
    return None

# Messaging Functions
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

def get_unread_messages(user_id):
    """Get unread messages for a user"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor(dictionary=True)
            cursor.execute("""
                SELECT m.*, u.username as sender_name, a.title as assignment_title
                FROM coordination_messages m
                JOIN users u ON m.sender_id = u.id
                LEFT JOIN assignments a ON m.assignment_id = a.id
                WHERE m.recipient_id = %s AND m.is_read = FALSE
                ORDER BY m.created_at DESC
            """, (user_id,))
            return cursor.fetchall()
        except Error as e:
            print(f"Error fetching messages: {e}")
            return []
        finally:
            cursor.close()
            connection.close()
    return []

# Helper function to check overdue assignments
def check_and_update_delayed_assignments():
    """Check for overdue assignments and mark them as delayed"""
    connection = get_db_connection()
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute("""
                UPDATE assignments 
                SET status = 'delayed'
                WHERE status IN ('open', 'in_progress') 
                AND due_date < NOW()
            """)
            connection.commit()
            return cursor.rowcount
        except Error as e:
            print(f"Error updating delayed assignments: {e}")
            return 0
        finally:
            cursor.close()
            connection.close()
    return 0

# Function to get coordinator's team (for Senior Coordinator panel)
def get_coordinator_team(senior_coordinator_id):
    """Get the team members under a Senior Coordinator"""
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
                    SELECT gm.*, u.username, u.avatar_url
                    FROM group_members gm
                    JOIN users u ON gm.user_id = u.id
                    WHERE gm.group_id = %s AND gm.role = 'Coordinator'
                    ORDER BY u.username
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

# Updated routes with backend integration

@app.route('/admin/coordination/director', methods=['GET', 'POST'])
@login_required
@staff_required
def director_panel():
    user = session['user']
    staff_role = user.get('staff_info', {}).get('role', 'Staff')
    division = user.get('staff_info', {}).get('division', 'Community Coordination')
    
    if staff_role not in ['Community Director', 'Executive Director', 'Administration Director']:
        return "Access Denied", 403
    
    # Handle group creation
    if request.method == 'POST':
        data = request.get_json()
        group_name = data.get('group_name')
        members = data.get('members', [])
        
        if group_name and members:
            group_id = create_group(group_name, division, user['id'], members)
            if group_id:
                return jsonify({'success': True, 'group_id': group_id})
            return jsonify({'success': False, 'error': 'Failed to create group'}), 400
        return jsonify({'success': False, 'error': 'Invalid data'}), 400
    
    # Get data for display
    team_members = get_team_members(division)
    groups = get_director_groups(user['id'], division)
    pending_assignments = get_director_assignments(user['id'], division)
    
    html = rf'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Director Supervisor Panel - Themis</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
        <style>
            /* Include previous styles */
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
                color: var(--text-secondary);
            }}
            
            .assignment-status {{
                padding: 6px 16px;
                border-radius: 6px;
                font-size: 0.85rem;
                font-weight: 600;
            }}
            
            .status-finished {{
                background: rgba(74, 222, 128, 0.2);
                color: var(--success-color);
                border: 1px solid rgba(74, 222, 128, 0.3);
            }}
            
            .status-pending {{
                background: rgba(251, 191, 36, 0.2);
                color: var(--warning-color);
                border: 1px solid rgba(251, 191, 36, 0.3);
            }}
            
            .verify-btn {{
                background: var(--success-color);
                color: black;
                font-size: 0.85rem;
                padding: 8px 16px;
                margin-left: 12px;
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
                <h1 class="page-title">Director Supervisor Panel</h1>
                <p class="page-subtitle">Manage your coordination teams and review assignments</p>
            </div>
            
            <div class="panels-grid">
                <div class="panel">
                    <h2 class="panel-title">Team Members</h2>
                    <div class="team-members-list">
                        {generate_team_members_html(team_members)}
                    </div>
                    
                    <div class="create-group-section">
                        <h3 style="font-size: 1.1rem; margin-bottom: 16px;">Create New Group</h3>
                        <div class="form-group">
                            <label class="form-label">Group Name</label>
                            <input type="text" class="form-input" id="groupName" placeholder="Enter group name...">
                        </div>
                        <button class="btn" id="createGroupBtn" onclick="createGroup()" disabled>
                            <svg width="20" height="20" fill="currentColor" viewBox="0 0 20 20">
                                <path fill-rule="evenodd" d="M10 3a1 1 0 011 1v5h5a1 1 0 110 2h-5v5a1 1 0 11-2 0v-5H4a1 1 0 110-2h5V4a1 1 0 011-1z" clip-rule="evenodd"/>
                            </svg>
                            Create Group
                        </button>
                        <div id="groupError" style="color: var(--error-color); font-size: 0.85rem; margin-top: 8px; display: none;"></div>
                    </div>
                </div>
                
                <div class="panel">
                    <h2 class="panel-title">Active Groups</h2>
                    <div class="groups-display" id="groupsDisplay">
                        {generate_groups_html(groups)}
                    </div>
                </div>
                
                <div class="panel assignments-panel">
                    <h2 class="panel-title">Assignment Overview</h2>
                    <div class="assignments-list">
                        {generate_assignments_html(pending_assignments)}
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            let selectedMembers = {{
                senior: [],
                coordinator: []
            }};
            
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
                    errorDiv.textContent = 'You must select at least 1 Senior Coordinator and 1 Coordinator';
                    errorDiv.style.display = 'block';
                    createBtn.disabled = true;
                }} else if (!hasName) {{
                    errorDiv.textContent = 'Please enter a group name';
                    errorDiv.style.display = 'block';
                    createBtn.disabled = true;
                }} else {{
                    errorDiv.style.display = 'none';
                    createBtn.disabled = false;
                }}
            }}
            
            document.getElementById('groupName').addEventListener('input', validateGroupCreation);
            
            async function createGroup() {{
                const groupName = document.getElementById('groupName').value.trim();
                const loadingIndicator = document.getElementById('loadingIndicator');
                
                // Prepare members array
                const members = [];
                selectedMembers.senior.forEach(m => {{
                    members.push({{user_id: parseInt(m.id), role: 'Senior Coordinator'}});
                }});
                selectedMembers.coordinator.forEach(m => {{
                    members.push({{user_id: parseInt(m.id), role: 'Coordinator'}});
                }});
                
                loadingIndicator.classList.add('active');
                
                try {{
                    const response = await fetch('/admin/coordination/director', {{
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
                        alert('Group created successfully!');
                        window.location.reload();
                    }} else {{
                        alert('Error creating group: ' + (data.error || 'Unknown error'));
                    }}
                }} catch (error) {{
                    alert('Error creating group: ' + error.message);
                }} finally {{
                    loadingIndicator.classList.remove('active');
                }}
            }}
            
            async function verifyAssignment(assignmentId) {{
                if (!confirm('Are you sure you want to verify this assignment?')) {{
                    return;
                }}
                
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
                        alert('Assignment verified and sent to Executive Director');
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

# Helper functions to generate HTML
def generate_team_members_html(members):
    html = ''
    for member in members:
        role_class = 'senior' if member['role'] == 'Senior Coordinator' else 'coordinator'
        html += f'''
        <div class="member-item" onclick="toggleMember(this)">
            <input type="checkbox" class="member-checkbox" data-role="{role_class}" data-user-id="{member['id']}" data-name="{member['username']}">
            <div class="member-info">
                <div class="member-name">{member['username']}</div>
                <div class="member-role {role_class}">{member['role']}</div>
            </div>
        </div>
        '''
    return html

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
                        {''.join([f'<div class="member-badge">{m["username"]}</div>' for m in seniors])}
                    </div>
                </div>
                <div class="hierarchy-level">
                    <div class="hierarchy-title">Coordinators</div>
                    <div class="hierarchy-members">
                        {''.join([f'<div class="member-badge">{m["username"]}{" - " + m["role_label"] if m.get("role_label") else ""}</div>' for m in coordinators])}
                    </div>
                </div>
            </div>
        </div>
        '''
    return html

def generate_assignments_html(assignments):
    if not assignments:
        return '<p style="text-align: center; color: var(--text-muted);">No assignments pending verification</p>'
    
    html = ''
    for assignment in assignments:
        html += f'''
        <div class="assignment-item">
            <div class="assignment-info">
                <div class="assignment-title">{assignment['title']}</div>
                <div class="assignment-group">{assignment['group_name'] or 'No Group'} - Assigned to: {assignment['assigned_to_name']}</div>
            </div>
            <div style="display: flex; align-items: center;">
                <div class="assignment-status status-finished">Finished</div>
                <button class="btn verify-btn" onclick="verifyAssignment({assignment['id']})">Verify</button>
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

# Time formatting helpers
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

# Initialize tables on startup
init_coordination_tables()

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
'''
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



if __name__ == '__main__':
    app.run(debug=False)