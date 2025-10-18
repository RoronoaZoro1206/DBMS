import os
import re
import psycopg2
from psycopg2.extras import Json
from flask import Flask, request, render_template_string, redirect, url_for, session
from dotenv import load_dotenv
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from functools import wraps

# Used to invalidate any browser session cookies whenever the Flask app restarts
APP_INSTANCE_TOKEN = os.urandom(16).hex()

# Load environment variables BEFORE using them
load_dotenv()  

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or os.getenv("FLASK_SECRET_KEY")

# Rate limiter (protect brute force on /login)
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[]
)
limiter.init_app(app)

# Security-oriented session cookie settings
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_REFRESH_EACH_REQUEST=False
)

csrf = CSRFProtect(app)

# Ensure a fresh login whenever the browser session is missing or the app restarted
@app.before_request
def enforce_fresh_login():
    token = session.get('app_instance_token')
    if token is None and session.get('logged_in'):
        session.clear()
        return redirect(url_for('index'))
    if token is not None and token != APP_INSTANCE_TOKEN:
        session.clear()
        return redirect(url_for('index'))

# Security headers middleware
@app.after_request
def set_security_headers(response):
    """Add security headers to prevent information disclosure"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # Don't reveal server information
    response.headers['Server'] = 'WebServer'
    return response

# Database helper
def get_db_connection():
    conn = None
    try:
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST"),
            port=os.getenv("DB_PORT"),
            database=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASS") or os.getenv("DB_PASSWORD"),
            # sslmode="disable"
        )
        return conn
    except psycopg2.OperationalError as e:
        print("Error: Unable to connect to the database.", e)
        return None

def find_tickets(query_string, show_resolved=False):
    conn = get_db_connection()
    if not conn:
        return []
    try:
        cur = conn.cursor()
        if show_resolved:
            # Show only resolved tickets
            if query_string:
                # Search within resolved tickets
                sql_query = "SELECT id, issue FROM tickets WHERE issue ILIKE %s AND issue LIKE '%%[Resolved by admin%%' ORDER BY id;"
                search_pattern = f"%{query_string}%"
                cur.execute(sql_query, (search_pattern,))
            else:
                # Show all resolved tickets (no query required)
                sql_query = "SELECT id, issue FROM tickets WHERE issue LIKE '%%[Resolved by admin%%' ORDER BY id;"
                cur.execute(sql_query)
        else:
            # Original logic: Show only unresolved tickets
            sql_query = "SELECT id, issue FROM tickets WHERE issue ILIKE %s AND issue NOT LIKE '%%[Resolved by admin%%' ORDER BY id;"
            search_pattern = f"%{query_string}%"
            cur.execute(sql_query, (search_pattern,))
        
        results = cur.fetchall()
        cur.close()
        return results
    except (Exception, psycopg2.Error) as error:
        print(f"Database search error: {error}")
        return []
    finally:
        if conn:
            conn.close()

def mark_ticket_as_resolved(ticket_id, admin_username, user_id=None):
    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed."
    try:
        cur = conn.cursor()
        
        # PHASE 3: Set session variable for auditing trigger
        if user_id:
            # Use simple SET command without parameters that cause issues
            cur.execute(f"SET app.user_id = {int(user_id)}")
        
        cur.execute("CALL mark_ticket_resolved(%s, %s)", (ticket_id, admin_username))

        cur.execute("SELECT issue FROM tickets WHERE id = %s", (ticket_id,))
        ticket_row = cur.fetchone()
        audit_payload = {
            "ticket_id": ticket_id,
            "issue": ticket_row[0] if ticket_row else None,
            "resolved_by": admin_username
        }
        staff_id = int(user_id) if user_id is not None else None
        cur.execute(
            "INSERT INTO audit_log_ticket (ticket_id, staff_id, action, old_data, new_data) VALUES (%s, %s, %s, %s, %s)",
            (ticket_id, staff_id, 'TICKET_RESOLVE', None, Json(audit_payload))
        )

        conn.commit()
        cur.close()
        return True, "Ticket marked as resolved successfully."
    except psycopg2.Error as error:
        error_msg = str(error).strip()
        # Log to console only (don't use print with f-strings that might have special chars)
        if "does not exist" in error_msg:
            return False, "Ticket not found."
        elif "Access denied" in error_msg or "admin_role" in error_msg:
            return False, "Permission denied."
        else:
            return False, "An error occurred while resolving the ticket."
    except Exception as error:
        return False, "An error occurred while resolving the ticket."
    finally:
        if conn:
            conn.close()

# Helper decorator to enforce login
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return wrapper

# CHANGE: Template updated for RBAC (hide/show login, ticket form, and search by role)
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>University Helpdesk</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 font-sans text-gray-800">
  <div class="max-w-5xl mx-auto p-6">
    <header class="mb-10 text-center">
      <h1 class="text-4xl font-bold text-gray-900">CCICT Helpdesk</h1>
      <p class="text-gray-600 mt-2">DBMS Security Lab</p>
      {% if session.get('logged_in') %}
        <p class="text-sm mt-2">
          Logged in as <span class="font-semibold">{{ session.get('username') }}</span>
          ({{ session.get('role') }}) |
          <a href="{{ url_for('logout') }}" class="text-blue-600 underline">Logout</a>
        </p>
      {% endif %}
    </header>

    <div class="grid md:grid-cols-2 gap-6">
      <!-- Login Form (hidden after login) -->
      {% if not session.get('logged_in') %}
      <div class="bg-white rounded-2xl shadow-md p-6 hover:shadow-lg transition">
        <h2 class="text-xl font-semibold mb-4">Login</h2>
        <form action="/login" method="post" class="space-y-4" autocomplete="off">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="text" name="username" placeholder="Username" required autocomplete="off"
            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none">
          <input type="password" name="password" placeholder="Password" required autocomplete="off"
            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none">
          <button type="submit"
            class="w-full bg-blue-600 text-white font-medium py-2 px-4 rounded-lg hover:bg-blue-700 transition">
            Log In
          </button>
          {% if login_message %}
            <p class="text-red-500 text-sm text-center mt-2">{{ login_message }}</p>
          {% endif %}
        </form>
      </div>
      {% endif %}

      <!-- New Ticket Form (visible only after login) -->
      {% if session.get('logged_in') %}
      <div class="bg-white rounded-2xl shadow-md p-6 hover:shadow-lg transition">
        <h2 class="text-xl font-semibold mb-4">Create Ticket</h2>
        <form action="/submit_ticket" method="post" class="space-y-4" autocomplete="off">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="text" name="student_id" placeholder="Student ID" required autocomplete="off"
          class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:outline-none">
          <textarea name="issue" placeholder="Describe your issue..." rows="4" required autocomplete="off"
            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-green-500 focus:outline-none"></textarea>
          <button type="submit"
            class="w-full bg-green-600 text-white font-medium py-2 px-4 rounded-lg hover:bg-green-700 transition">
            Submit Ticket
          </button>
          {% if ticket_message %}
            <p class="text-green-600 text-sm text-center mt-2">{{ ticket_message }}</p>
          {% endif %}
        </form>
      </div>
      {% endif %}

      <!-- Student Registration (support + admin) -->
      {% if session.get('logged_in') and session.get('role') in ['support_role', 'admin_role'] %}
      <div class="bg-white rounded-2xl shadow-md p-6 hover:shadow-lg transition">
        <h2 class="text-xl font-semibold mb-4">Add Student</h2>
        <form action="/students/add" method="post" class="space-y-4" autocomplete="off">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
          <input type="text" name="student_name" placeholder="Full Name" required autocomplete="off"
            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:outline-none">
          <input type="email" name="student_email" placeholder="Email" required autocomplete="off"
            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:outline-none">
          <input type="text" name="student_phone" placeholder="Phone" autocomplete="off"
          class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:outline-none">
          <button type="submit"
            class="w-full bg-indigo-600 text-white font-medium py-2 px-4 rounded-lg hover:bg-indigo-700 transition">
            Save Student
          </button>
          {% if student_message %}
            <p class="text-sm text-center mt-2 {% if student_error %}text-red-500{% else %}text-green-600{% endif %}">{{ student_message }}</p>
          {% endif %}
        </form>
      </div>
      {% endif %}
    </div>

    <!-- Ticket Search (admin only) -->
    <div class="bg-white rounded-2xl shadow-md p-6 mt-8 hover:shadow-lg transition">
      <h2 class="text-xl font-semibold mb-4">Search Tickets</h2>
      {% if not session.get('logged_in') %}
        <p class="text-gray-500 text-sm">Login to use this feature.</p>
      {% elif session.get('role') != 'admin_role' %}
        <p class="text-gray-500 text-sm">Search restricted to admin users.</p>
      {% else %}
                <form action="/search" method="get" class="flex flex-col md:flex-row gap-3" autocomplete="off">
          <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <input type="text" name="q" placeholder="Search for an issue..." autocomplete="off"
            class="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-yellow-500 focus:outline-none">
          <button type="submit"
            class="bg-yellow-500 text-white font-medium py-2 px-6 rounded-lg hover:bg-yellow-600 transition">
            Search
          </button>
          <button type="submit" name="show_resolved" value="true"
            class="bg-purple-500 text-white font-medium py-2 px-6 rounded-lg hover:bg-purple-600 transition">
            Resolved Tickets
          </button>
        </form>
        
        <!-- Button: View All Tickets -->
        <div class="mt-4">
          <a href="{{ url_for('view_all_tickets') }}"
            class="inline-block bg-gray-700 text-white font-medium py-2 px-6 rounded-lg hover:bg-gray-800 transition">
            View All Tickets
          </a>
        </div>
        
        {% if search_message %}
          <p class="text-red-500 text-sm mt-2">{{ search_message }}</p>
        {% endif %}
        {% if resolve_message %}
          <p class="text-green-600 text-sm mt-2">{{ resolve_message }}</p>
        {% endif %}
        <div class="mt-6">
          {% if results is not none %}
            <h3 class="text-lg font-semibold mb-2">{% if show_resolved %}Resolved Tickets{% else %}Active Tickets{% endif %}</h3>
            {% if results %}
              <ul class="space-y-2">
                {% for ticket in results %}
                  <li class="p-3 bg-gray-50 rounded-lg border text-sm flex justify-between items-center">
                    <div class="flex-1">
                      <span class="font-medium text-gray-900">Ticket #{{ ticket[0] }}</span>: {{ ticket[1] }}
                    </div>
                    {% if not show_resolved %}
                    <form action="/resolve_ticket" method="post" class="inline ml-3">
                      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                      <input type="hidden" name="ticket_id" value="{{ ticket[0] }}">
                      <button type="submit"
                        class="bg-green-500 text-white text-xs font-medium py-1 px-3 rounded hover:bg-green-600 transition">
                        Resolve
                      </button>
                    </form>
                    {% endif %}
                  </li>
                {% endfor %}
              </ul>
            {% else %}
              <p class="text-gray-500 text-sm">No tickets found.</p>
            {% endif %}
          {% endif %}
        </div>
      {% endif %}
    </div>

    <!-- Extra dynamic content (student listings etc.) -->
    {% if extra_content %}
      <div class="bg-white rounded-2xl shadow-md p-6 mt-8">
        {{ extra_content|safe }}
      </div>
    {% endif %}

  </div>
</body>
</html>
"""

# Routes
@app.route('/', methods=['GET'])
def index():
    # CHANGE: provide default context variables
    return render_template_string(html_template, results=None)

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    # Validate input
    if not username or not password:
        return render_template_string(html_template, login_message="Invalid credentials.", results=None)
    
    conn = get_db_connection()
    if not conn:
        return render_template_string(html_template, login_message="Service temporarily unavailable.", results=None)
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, role FROM staff_users WHERE username = %s AND password_hash = crypt(%s, password_hash)",
            (username, password)
        )
        user = cur.fetchone()
        cur.close()
        if user:
            normalized_role = 'admin_role' if user[2] in ('admin', 'admin_role') else 'support_role'
            session.permanent = False  # Do not keep the session once the browser closes
            session['logged_in'] = True
            session['user_id'] = user[0]  # Store user ID for auditing
            session['username'] = user[1]
            session['role'] = normalized_role
            session['app_instance_token'] = APP_INSTANCE_TOKEN
            # Don't redirect, just reload with session
            return redirect(url_for('index'))
        # Use generic message to prevent username enumeration
        return render_template_string(html_template, login_message="Invalid credentials.", results=None)
    except (Exception, psycopg2.Error) as error:
        print(f"Login error: {error}")  # Log server-side only
        # Generic error message to prevent information disclosure
        return render_template_string(html_template, login_message="An error occurred. Please try again.", results=None)
    finally:
        if conn:
            conn.close()

@app.errorhandler(RateLimitExceeded)
def handle_rate_limit(e):
    return render_template_string("""
        <script>
            alert("Too many attempts. Try again in a few minutes.");
            window.location.href = "/";
        </script>
    """), 429

@app.errorhandler(500)
def handle_server_error(e):
    """Handle 500 errors without revealing server details"""
    print(f"Internal server error: {e}")  # Log server-side
    return render_template_string(html_template, 
                                 login_message="An internal error occurred. Please try again later.",
                                 results=None), 500

@app.errorhandler(404)
def handle_not_found(e):
    """Handle 404 errors"""
    return redirect(url_for('index'))

@app.errorhandler(403)
def handle_forbidden(e):
    """Handle 403 errors"""
    return render_template_string(html_template,
                                 login_message="Access forbidden.",
                                 results=None), 403

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('index'))

# RBAC: restricted student directory (uses view)
@app.route('/students')
@login_required
def students_restricted():
    conn = get_db_connection()
    rows = []
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, name, email FROM v_students_support;")
        rows = cur.fetchall()
        cur.close()
    finally:
        if conn:
            conn.close()
    html = "<h2 class='text-xl font-semibold mb-4'>Students Directory (Restricted View)</h2>"
    html += "<table class='w-full text-sm border'><tr><th class='border px-2'>ID</th><th class='border px-2'>Name</th><th class='border px-2'>Email</th></tr>"
    for r in rows:
        html += f"<tr><td class='border px-2'>{r[0]}</td><td class='border px-2'>{r[1]}</td><td class='border px-2'>{r[2]}</td></tr>"
    html += "</table><p class='mt-4 text-gray-500 text-xs'>Phone hidden (Least Privilege).</p>"
    return render_template_string(html_template, extra_content=html, results=None)

# RBAC: full student data (admin only)
@app.route('/students/full')
@login_required
def students_full():
    if session.get('role') != 'admin_role':
        return render_template_string(html_template, login_message="Access denied: admin only.", results=None)
    conn = get_db_connection()
    rows = []
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, name, email, phone FROM students ORDER BY id;")
        rows = cur.fetchall()
        cur.close()
    finally:
        if conn:
            conn.close()
    html = "<h2 class='text-xl font-semibold mb-4 text-red-700'>Full Students (Sensitive)</h2>"
    html += "<table class='w-full text-sm border'><tr><th class='border px-2'>ID</th><th class='border px-2'>Name</th><th class='border px-2'>Email</th><th class='border px-2'>Phone</th></tr>"
    for r in rows:
        html += f"<tr><td class='border px-2'>{r[0]}</td><td class='border px-2'>{r[1]}</td><td class='border px-2'>{r[2]}</td><td class='border px-2'>{r[3] or ''}</td></tr>"
    html += "</table><p class='mt-4 text-gray-500 text-xs'>Admin-only access to phone numbers.</p>"
    return render_template_string(html_template, extra_content=html, results=None)

@app.route('/students/add', methods=['POST'])
@login_required
def add_student():
    """Allow support and admin members to add student records."""
    if session.get('role') not in ('support_role', 'admin_role'):
        return render_template_string(
            html_template,
            student_message="Access denied: support or admin role required.",
            student_error=True,
            results=None
        )

    def render_student_feedback(message, is_error=False):
        return render_template_string(
            html_template,
            student_message=message,
            student_error=is_error,
            results=None
        )

    name = request.form.get('student_name', '').strip()
    email = request.form.get('student_email', '').strip()
    phone = request.form.get('student_phone', '').strip()

    if not name or not email:
        return render_student_feedback("Student name and email are required.", True)

    if len(name) > 150:
        return render_student_feedback("Student name is too long (max 150 characters).", True)

    email_pattern = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
    if len(email) > 254 or not email_pattern.match(email):
        return render_student_feedback("Provide a valid student email address.", True)

    sanitized_phone = re.sub(r"[^0-9+\-().\s]", "", phone)
    sanitized_phone = re.sub(r"\s+", " ", sanitized_phone).strip()
    if sanitized_phone and len(sanitized_phone) > 32:
        return render_student_feedback("Phone number is too long (max 32 characters).", True)

    conn = get_db_connection()
    if not conn:
        return render_student_feedback("Service temporarily unavailable.", True)

    try:
        cur = conn.cursor()

        user_id = session.get('user_id')
        if user_id:
            cur.execute(f"SET app.user_id = {int(user_id)}")

        cur.execute("SELECT id FROM students WHERE LOWER(email) = LOWER(%s)", (email,))
        existing = cur.fetchone()
        if existing:
            cur.close()
            return render_student_feedback("A student with that email already exists.", True)

        cur.execute(
            "INSERT INTO students (name, email, phone) VALUES (%s, %s, %s) RETURNING id;",
            (name, email.lower(), sanitized_phone or None)
        )
        new_id = cur.fetchone()[0]

        audit_payload = {
            "student_id": new_id,
            "name": name,
            "email": email.lower(),
            "phone": sanitized_phone or None
        }
        staff_id = int(user_id) if user_id is not None else None
        audit_ticket_id = -new_id  # negative id = non-ticket event while keeping column non-null
        cur.execute(
            "INSERT INTO audit_log_ticket (ticket_id, staff_id, action, old_data, new_data) VALUES (%s, %s, %s, %s, %s)",
            (audit_ticket_id, staff_id, 'STUDENT_INSERT', None, Json(audit_payload))
        )

        conn.commit()
        cur.close()
        return render_student_feedback(f"Student #{new_id} added successfully.")
    except psycopg2.IntegrityError as error:
        conn.rollback()
        print(f"Student insertion integrity error: {error}")
        return render_student_feedback("Unable to add student due to data constraints.", True)
    except (Exception, psycopg2.Error) as error:
        conn.rollback()
        print(f"Student insertion error: {error}")
        return render_student_feedback("An error occurred while adding the student.", True)
    finally:
        if conn:
            conn.close()


@app.route('/submit_ticket', methods=['POST'])
@login_required  # CHANGE: enforce authentication for ticket creation
def submit_ticket():
    student_id = request.form.get('student_id', '').strip()
    issue = request.form.get('issue', '').strip()
    
    # Validate inputs
    if not student_id or not issue:
        return render_template_string(html_template, ticket_message="All fields are required.", results=None)
    
    # Validate student_id is numeric
    try:
        student_id = int(student_id)
    except ValueError:
        return render_template_string(html_template, ticket_message="Invalid student ID format.", results=None)
    
    # Validate issue length (prevent extremely long submissions)
    if len(issue) > 1000:
        return render_template_string(html_template, ticket_message="Issue description is too long (max 1000 characters).", results=None)
    
    conn = get_db_connection()
    if not conn:
        return render_template_string(html_template, ticket_message="Service temporarily unavailable.", results=None)
    try:
        cur = conn.cursor()
        
        # PHASE 3: Set session variable for auditing trigger
        user_id = session.get('user_id')
        if user_id:
            # Use simple SET command without parameters that cause issues
            cur.execute(f"SET app.user_id = {int(user_id)}")
        
        # PHASE 3: To identify who made the change.
        cur.execute("INSERT INTO tickets (student_id, issue) VALUES (%s, %s) RETURNING id", (student_id, issue))
        ticket_row = cur.fetchone()
        ticket_id = ticket_row[0] if ticket_row else None
        if ticket_id is None:
            cur.execute("SELECT currval('tickets_id_seq')")
            ticket_id = cur.fetchone()[0]

        audit_payload = {
            "ticket_id": ticket_id,
            "student_id": student_id,
            "issue": issue
        }
        staff_id = int(user_id) if user_id is not None else None

        # Reuse the row inserted by the ticket trigger so we only keep a single audit record
        cur.execute(
            """
            UPDATE audit_log_ticket
               SET action = %s,
                   staff_id = COALESCE(%s, staff_id),
                   old_data = NULL,
                   new_data = %s
             WHERE ticket_id = %s AND action = 'INSERT'
            """,
            ('TICKET_CREATE', staff_id, Json(audit_payload), ticket_id)
        )
        if cur.rowcount == 0:
            cur.execute(
                "INSERT INTO audit_log_ticket (ticket_id, staff_id, action, old_data, new_data) VALUES (%s, %s, %s, %s, %s)",
                (ticket_id, staff_id, 'TICKET_CREATE', None, Json(audit_payload))
            )

        conn.commit()
        cur.close()
        return render_template_string(html_template, ticket_message="Ticket submitted successfully!", results=None)
    except psycopg2.IntegrityError as error:
        print(f"Ticket submission integrity error: {error}")
        # Don't reveal if student exists or not (prevents enumeration)
        return render_template_string(html_template, ticket_message="Unable to submit ticket. Please verify student ID.", results=None)
    except (Exception, psycopg2.Error) as error:
        print(f"Ticket submission error: {error}")
        # Generic error message
        return render_template_string(html_template, ticket_message="An error occurred. Please try again.", results=None)
    finally:
        if conn:
            conn.close()

@app.route('/search', methods=['GET'])
@login_required  # CHANGE: must be logged in
def search_tickets():
    # CHANGE: RBAC enforcement - only admin_role may search
    if session.get('role') != 'admin_role':
        return render_template_string(
            html_template,
            results=[],
            search_message="Access denied: admin only."
        )
    
    query = request.args.get('q', '').strip()
    show_resolved = request.args.get('show_resolved', 'false') == 'true'
    
    # For "Resolved Tickets" button - allow showing all without query
    if show_resolved:
        results = find_tickets(query, show_resolved)
        return render_template_string(html_template, results=results, show_resolved=show_resolved)
    
    # For regular "Search" button - use original logic (requires query)
    results = find_tickets(query, show_resolved) if query else []
    return render_template_string(html_template, results=results, show_resolved=show_resolved)

@app.route('/resolve_ticket', methods=['POST'])
@login_required
def resolve_ticket():
    # Only admin can mark tickets as resolved
    if session.get('role') != 'admin_role':
        return render_template_string(
            html_template,
            results=None,
            search_message="Access denied: admin only."
        )
    
    ticket_id = request.form.get('ticket_id')
    admin_username = session.get('username')
    user_id = session.get('user_id')
    
    # Validate ticket_id is a valid integer
    try:
        ticket_id = int(ticket_id)
    except (ValueError, TypeError):
        return render_template_string(
            html_template,
            results=None,
            search_message="Invalid ticket ID."
        )
    
    success, message = mark_ticket_as_resolved(ticket_id, admin_username, user_id)
    
    if success:
        return render_template_string(
            html_template,
            results=None,
            resolve_message=message
        )
    else:
        return render_template_string(
            html_template,
            results=None,
            search_message=message
        )

# View all tickets
@app.route('/view_all')
@login_required
def view_all_tickets():
    """View all tickets (admin only) - uses stored function"""
    # Only allow admin to view all tickets
    if session.get('role') != 'admin_role':
        return render_template_string(
            html_template,
            results=[],
            search_message="Access denied: admin only."
        )

    conn = get_db_connection()
    if not conn:
        return render_template_string(html_template, results=None, search_message="Database connection failed.")

    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM get_all_tickets();")
        results = cur.fetchall()
        cur.close()
        return render_template_string(html_template, results=results, show_resolved=False)
    except (Exception, psycopg2.Error) as error:
        print(f"Error loading tickets: {error}")
        return render_template_string(html_template, results=[], search_message="An error occurred while fetching tickets.")
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    # NOTE: Set debug=False in production to prevent information disclosure
    # Debug mode reveals sensitive error information and should only be used in development
    app.run(debug=True)  # Change to False for production deployment