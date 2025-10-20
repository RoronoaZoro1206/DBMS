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


def normalize_role(role_value):
    if not role_value:
        return None
    cleaned = role_value.strip().lower()
    if cleaned in ('admin', 'admin_role'):
        return 'admin_role'
    if cleaned in ('support', 'support_role'):
        return 'support_role'
    return None


def get_ticket_status_counts():
    totals = {'open': 0, 'resolved': 0}
    conn = get_db_connection()
    if not conn:
        return totals
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                COALESCE(SUM(CASE WHEN issue LIKE '%%[Resolved by admin%%' THEN 1 ELSE 0 END), 0) AS resolved_count,
                COALESCE(SUM(CASE WHEN issue LIKE '%%[Resolved by admin%%' THEN 0 ELSE 1 END), 0) AS open_count
            FROM tickets;
            """
        )
        row = cur.fetchone()
        if row:
            totals['resolved'] = int(row[0] or 0)
            totals['open'] = int(row[1] or 0)
        cur.close()
        return totals
    except (Exception, psycopg2.Error) as error:
        print(f"Ticket status aggregation error: {error}")
        return totals
    finally:
        if conn:
            conn.close()


def base_view_context(**overrides):
    context = {
        "session": session,
        "active_page": None,
        "login_message": None,
        "show_create": False, 
        'results': [],
        'show_resolved': False,
        'login_message': None,
        'ticket_message': None,
        'student_message': None,
        'student_error': False,
        'account_message': None,
        'account_error': False,
        'search_message': None,
        'resolve_message': None,
        'manage_message': None,
        'manage_error': False,
        'extra_content': None,
        'access_message': None,
        'chart_labels': [],
        'chart_values': [],
        'metrics': {},
        'chart_configs': [],
        'audit_entries': [],
        'active_page': 'dashboard',
        'page_title': None,
        'page_description': None,
        'student_rows': [],
        'full_student_rows': [],
        'accounts': []
    }
    if session.get('logged_in') and session.get('role') in ('support_role', 'admin_role'):
        counts = get_ticket_status_counts()
        context['chart_labels'] = ['Open Tickets', 'Resolved Tickets']
        context['chart_values'] = [counts['open'], counts['resolved']]
        context['metrics'] = counts
        chart_configs = [
            {
                'id': 'chart-ticket-status',
                'type': 'doughnut',
                'title_text': 'Ticket Status',
                'dataset_label': 'Tickets',
                'labels': ['Open', 'Resolved'],
                'data': [counts['open'], counts['resolved']],
                'background_color': ['#2563eb', '#16a34a'],
                'legend_position': 'bottom',
                'height': 220
            }
        ]
        if session.get('role') == 'admin_role':
            staff_counts = get_staff_role_counts()
            entity_counts = get_entity_counts()
            chart_configs.append(
                {
                    'id': 'chart-staff-roles',
                    'type': 'bar',
                    'title_text': 'Staff Accounts by Role',
                    'dataset_label': 'Accounts',
                    'labels': ['Administrators', 'Support'],
                    'data': [staff_counts.get('admin_role', 0), staff_counts.get('support_role', 0)],
                    'background_color': ['#7c3aed', '#0ea5e9'],
                    'legend_position': 'top',
                    'height': 220
                }
            )
            chart_configs.append(
                {
                    'id': 'chart-entity-distribution',
                    'type': 'bar',
                    'title_text': 'Records Overview',
                    'dataset_label': 'Totals',
                    'labels': ['Students', 'Tickets'],
                    'data': [entity_counts.get('students', 0), entity_counts.get('tickets', 0)],
                    'background_color': ['#f97316', '#22c55e'],
                    'legend_position': 'top',
                    'height': 220
                }
            )
        context['chart_configs'] = chart_configs
    context.update(overrides)
    return context

def set_trigger_user(cur, user_id):
    """Set the session variable consumed by audit triggers."""
    if user_id is None:
        return
    try:
        value = int(user_id)
    except (TypeError, ValueError):
        return
    cur.execute('SET session "app.user_id" = %s;', (str(value),))

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
            # Show unresolved (open) tickets
            if query_string:
                # Search within open tickets
                sql_query = "SELECT id, issue FROM tickets WHERE issue ILIKE %s AND issue NOT LIKE '%%[Resolved by admin%%' ORDER BY id;"
                search_pattern = f"%{query_string}%"
                cur.execute(sql_query, (search_pattern,))
            else:
                # Show all open tickets (no query required)
                sql_query = "SELECT id, issue FROM tickets WHERE issue NOT LIKE '%%[Resolved by admin%%' ORDER BY id;"
                cur.execute(sql_query)
        
        results = cur.fetchall()
        cur.close()
        return results
    except (Exception, psycopg2.Error) as error:
        print(f"Database search error: {error}")
        return []
    finally:
        if conn:
            conn.close()


def load_restricted_students():
    conn = get_db_connection()
    if not conn:
        return []
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, name, email FROM v_students_support ORDER BY id;")
        rows = cur.fetchall()
        cur.close()
        return rows
    except (Exception, psycopg2.Error) as error:
        print(f"Restricted student lookup error: {error}")
        return []
    finally:
        if conn:
            conn.close()


def load_full_students():
    conn = get_db_connection()
    if not conn:
        return []
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, name, email, phone FROM students ORDER BY id;")
        rows = cur.fetchall()
        cur.close()
        return rows
    except (Exception, psycopg2.Error) as error:
        print(f"Full student lookup error: {error}")
        return []
    finally:
        if conn:
            conn.close()


def load_staff_accounts():
    conn = get_db_connection()
    if not conn:
        return []
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, username, role FROM staff_users ORDER BY id;")
        rows = cur.fetchall()
        cur.close()
        return [{'id': row[0], 'username': row[1], 'role': row[2]} for row in rows]
    except (Exception, psycopg2.Error) as error:
        print(f"Staff account lookup error: {error}")
        return []
    finally:
        if conn:
            conn.close()


def get_staff_role_counts():
    counts = {'admin_role': 0, 'support_role': 0}
    conn = get_db_connection()
    if not conn:
        return counts
    try:
        cur = conn.cursor()
        cur.execute("SELECT role, COUNT(*) FROM staff_users GROUP BY role;")
        for role, total in cur.fetchall():
            counts[role] = int(total or 0)
        cur.close()
        return counts
    except (Exception, psycopg2.Error) as error:
        print(f"Staff role aggregation error: {error}")
        return counts
    finally:
        if conn:
            conn.close()


def get_entity_counts():
    counts = {'students': 0, 'tickets': 0}
    conn = get_db_connection()
    if not conn:
        return counts
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM students;")
        counts['students'] = int(cur.fetchone()[0] or 0)
        cur.execute("SELECT COUNT(*) FROM tickets;")
        counts['tickets'] = int(cur.fetchone()[0] or 0)
        cur.close()
        return counts
    except (Exception, psycopg2.Error) as error:
        print(f"Entity count aggregation error: {error}")
        return counts
    finally:
        if conn:
            conn.close()


def load_audit_entries(limit=50):
    conn = get_db_connection()
    if not conn:
        return []
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT audit_id, staff_id, action, logged_at, old_data, new_data
              FROM audit_log
             ORDER BY audit_id DESC
             LIMIT %s;
            """,
            (limit,)
        )
        rows = cur.fetchall()
        cur.close()
        entries = []
        for row in rows:
            entries.append(
                {
                    'audit_id': row[0],
                    'staff_id': row[1],
                    'action': row[2],
                    'logged_at': row[3],
                    'old_data': row[4],
                    'new_data': row[5],
                }
            )
        return entries
    except (Exception, psycopg2.Error) as error:
        print(f"Audit log load error: {error}")
        return []
    finally:
        if conn:
            conn.close()


def ticket_view_context(**overrides):
    role = session.get('role')
    description = "Create and manage helpdesk tickets." if role == 'admin_role' else "Create tickets for student issues."
    context = {
        'active_page': 'tickets',
        'page_title': 'Ticket Queue',
        'page_description': description,
        'show_resolved': overrides.get('show_resolved', False)
    }
    context.update(overrides)
    return base_view_context(**context)


def render_ticket_page(**overrides):
    show_resolved = overrides.get('show_resolved', False)
    if 'results' not in overrides:
        overrides['results'] = find_tickets('', show_resolved) if session.get('role') == 'admin_role' else []
    overrides.setdefault('show_resolved', show_resolved)
    return render_template_string(html_template, **ticket_view_context(**overrides))


def sensitive_students_context(message=None, is_error=False):
    return base_view_context(
        active_page='sensitive',
        page_title='Sensitive Records',
        page_description='Admin-only student contact information.',
        full_student_rows=load_full_students(),
        student_message=message,
        student_error=is_error
    )


def accounts_view_context(message=None, is_error=False):
    return base_view_context(
        active_page='accounts',
        page_title='Account Administration',
        page_description='Provision and review staff login credentials.',
        accounts=load_staff_accounts(),
        account_message=message,
        account_error=is_error
    )


def audit_view_context():
    return base_view_context(
        active_page='audits',
        page_title='Audit Log',
        page_description='Review recent helpdesk actions recorded for compliance.',
        audit_entries=load_audit_entries()
    )

def mark_ticket_as_resolved(ticket_id, admin_username, user_id=None):
    conn = get_db_connection()
    if not conn:
        return False, "Database connection failed."
    try:
        cur = conn.cursor()
        
        # PHASE 3: Set session variable for auditing trigger
        set_trigger_user(cur, user_id)
        
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
            "INSERT INTO audit_log (staff_id, action, old_data, new_data) VALUES (%s, %s, %s, %s)",
            (staff_id, 'TICKET_RESOLVE', None, Json(audit_payload))
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

# Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string(register_template)

    username = request.form['username'].strip()
    password = request.form['password']
    confirm_password = request.form['confirm_password']
    role = request.form['role']

    if password != confirm_password:
        return render_template_string(register_template, register_message="Passwords do not match.")
    if len(password) < 6:
        return render_template_string(register_template, register_message="Password must be at least 6 characters long.")
    if not role:
        return render_template_string(register_template, register_message="Please select a role.")


    conn = get_db_connection()
    if not conn:
        return render_template_string(register_template, register_message="Database connection failed.")


    try:
        cur = conn.cursor()
        cur.execute("CALL add_new_user(%s, %s, %s);", (username, password, role))
        conn.commit()
        cur.close()
        return render_template_string(register_template, success=True)
    except psycopg2.errors.UniqueViolation:
        # Username already exists
        conn.rollback()
        return render_template_string(register_template, register_message="Username already exists. Please choose another.")
    except (Exception, psycopg2.Error) as error:
        print(f"Registration error: {error}")
        conn.rollback()
        return render_template_string(register_template, register_message="Error creating account. Please try again.")
    finally:
        if conn:
            conn.close()

# Role-aware dashboard template with sidebar and charts
html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>University Helpdesk</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-gray-100 font-sans text-gray-800">
    <div class="min-h-screen">
        <header class="bg-white shadow-sm">
            <div class="max-w-6xl mx-auto flex items-center justify-between px-6 py-4">
                <div>
                    <h1 class="text-2xl font-semibold text-gray-900">CCICT Helpdesk</h1>
                    <p class="text-sm text-gray-500">DBMS Security Lab</p>
                </div>
                {% if session.get('logged_in') %}
                <div class="text-right">
                    <p class="text-sm font-semibold text-gray-800">{{ session.get('username') }}</p>
                    <p class="text-xs uppercase tracking-wide text-gray-500">{{ session.get('role') }}</p>
                    <a href="{{ url_for('logout') }}" class="mt-2 inline-block text-xs font-medium text-blue-600 underline">Logout</a>
                </div>
                {% endif %}
            </div>
        </header>

        <main class="max-w-6xl mx-auto px-6 py-8">
            {% if access_message %}
            <div class="mb-6 rounded-lg border border-yellow-200 bg-yellow-50 px-4 py-3 text-sm text-yellow-700">
                {{ access_message }}
            </div>
            {% endif %}

            {% if not session.get('logged_in') %}
            <section class="mx-auto max-w-md rounded-2xl bg-white p-6 shadow">
                <h2 class="text-xl font-semibold text-center">Sign In</h2>
                <p class="mt-1 text-center text-sm text-gray-500">Enter your support or admin credentials to continue.</p>
                <form action="/login" method="post" class="mt-6 space-y-4" autocomplete="off">
                    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                    <div>
                        <label class="text-xs font-medium text-gray-600">Username</label>
                        <input type="text" name="username" required autocomplete="off"
                            class="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:outline-none">
                    </div>
                    <div>
                        <label class="text-xs font-medium text-gray-600">Password</label>
                        <input type="password" name="password" required autocomplete="off"
                            class="mt-1 w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:outline-none">
                    </div>
                    <button type="submit"
                        class="w-full rounded-lg bg-blue-600 py-2 text-sm font-semibold text-white hover:bg-blue-700 transition">Log In</button>

                    
                    {% if show_create %}
                        <p class="text-sm text-center mt-3">
                        Don't have an account?
                        <a href="{{ url_for('register') }}" class="text-blue-600 underline">Create one here</a>
                        </p>
                    {% endif %}

                    

                        
                    {% if login_message %}
                    <p class="text-center text-xs font-medium text-red-500">{{ login_message }}</p>
                    {% endif %}
                </form>
            </section>

            {% else %}
            <div class="flex flex-col gap-6 lg:flex-row">
                <aside class="w-full rounded-2xl bg-white p-6 shadow lg:w-64">
                    <div class="border-b pb-4">
                        <p class="text-sm font-semibold text-gray-800">{{ session.get('username') }}</p>
                        <p class="text-xs text-gray-500">{% if session.get('role') == 'admin_role' %}Administrator{% else %}Support Specialist{% endif %}</p>
                    </div>
                    <nav class="mt-4 space-y-1 text-sm">
                        <a href="{{ url_for('index') }}" class="flex items-center gap-3 rounded-lg px-3 py-2 {% if active_page == 'dashboard' %}bg-gray-900 text-white{% else %}text-gray-600 hover:bg-gray-100{% endif %}">
                            <span>📊</span><span>Dashboard</span>
                        </a>
                        <a href="{{ url_for('view_all_tickets') }}" class="flex items-center gap-3 rounded-lg px-3 py-2 {% if active_page == 'tickets' %}bg-gray-900 text-white{% else %}text-gray-600 hover:bg-gray-100{% endif %}">
                            <span>🎟️</span><span>Ticket Queue</span>
                        </a>
                        {% if session.get('role') == 'support_role' %}
                        <a href="{{ url_for('students_restricted') }}" class="flex items-center gap-3 rounded-lg px-3 py-2 {% if active_page == 'students' %}bg-gray-900 text-white{% else %}text-gray-600 hover:bg-gray-100{% endif %}">
                            <span>🧑‍🎓</span><span>Student Directory</span>
                        </a>
                        {% endif %}
                        {% if session.get('role') == 'admin_role' %}
                        <a href="{{ url_for('students_full') }}" class="flex items-center gap-3 rounded-lg px-3 py-2 {% if active_page == 'sensitive' %}bg-gray-900 text-white{% else %}text-gray-600 hover:bg-gray-100{% endif %}">
                            <span>📚</span><span>Sensitive Records</span>
                        </a>
                        <a href="{{ url_for('accounts_admin') }}" class="flex items-center gap-3 rounded-lg px-3 py-2 {% if active_page == 'accounts' %}bg-gray-900 text-white{% else %}text-gray-600 hover:bg-gray-100{% endif %}">
                            <span>🛠️</span><span>Account Admin</span>
                        </a>
                        <a href="{{ url_for('audit_log_view') }}" class="flex items-center gap-3 rounded-lg px-3 py-2 {% if active_page == 'audits' %}bg-gray-900 text-white{% else %}text-gray-600 hover:bg-gray-100{% endif %}">
                            <span>🗒️</span><span>Audit Log</span>
                        </a>
                        {% endif %}
                    </nav>
                </aside>

                <section class="flex-1 space-y-6">
                    {% if active_page == 'dashboard' %}
                    <div class="grid gap-4 md:grid-cols-3">
                        <div class="rounded-2xl bg-white p-6 shadow">
                            <p class="text-xs font-semibold uppercase text-blue-600">Open Tickets</p>
                            <p class="mt-2 text-3xl font-bold text-blue-900">{{ metrics.open or 0 }}</p>
                            <p class="mt-3 text-xs text-gray-500">Tickets awaiting action from the support team.</p>
                        </div>
                        <div class="rounded-2xl bg-white p-6 shadow">
                            <p class="text-xs font-semibold uppercase text-green-600">Resolved Tickets</p>
                            <p class="mt-2 text-3xl font-bold text-green-900">{{ metrics.resolved or 0 }}</p>
                            <p class="mt-3 text-xs text-gray-500">Successfully closed tickets this term.</p>
                        </div>
                        <div class="rounded-2xl bg-white p-6 shadow">
                            <p class="text-xs font-semibold uppercase text-gray-500">Quick Links</p>
                            <div class="mt-3 flex flex-wrap gap-2 text-xs">
                                <a href="{{ url_for('view_all_tickets') }}" class="rounded-full bg-gray-200 px-3 py-1">Ticket Queue</a>
                                {% if session.get('role') == 'support_role' %}
                                <a href="{{ url_for('students_restricted') }}" class="rounded-full bg-gray-200 px-3 py-1">Directory</a>
                                {% endif %}
                                {% if session.get('role') == 'admin_role' %}
                                <a href="{{ url_for('students_full') }}" class="rounded-full bg-gray-200 px-3 py-1">Sensitive Records</a>
                                <a href="{{ url_for('accounts_admin') }}" class="rounded-full bg-gray-200 px-3 py-1">Account Admin</a>
                                <a href="{{ url_for('audit_log_view') }}" class="rounded-full bg-gray-200 px-3 py-1">Audit Log</a>
                                {% endif %}
                            </div>
                            <p class="mt-4 text-xs text-gray-500">Navigate to the tools you need using the shortcuts above.</p>
                        </div>
                    </div>
                    {% if chart_configs %}
                    {% set chart_count = chart_configs|length %}
                    <div class="grid gap-4 mt-4 {% if chart_count == 2 %}md:grid-cols-2{% elif chart_count >= 3 %}md:grid-cols-2 xl:grid-cols-3{% endif %}">
                        {% for chart in chart_configs %}
                        <div class="rounded-2xl bg-white p-6 shadow flex flex-col">
                            <div class="flex items-center justify-between">
                                <h4 class="text-sm font-semibold text-gray-700">{{ chart.title_text }}</h4>
                                {% if chart.dataset_label %}
                                <span class="text-[10px] uppercase tracking-widest text-gray-400">{{ chart.dataset_label }}</span>
                                {% endif %}
                            </div>
                            <div class="mt-4 h-56">
                                <canvas id="{{ chart.id }}" height="{{ chart.height or 220 }}"></canvas>
                            </div>
                        </div>
                        {% endfor %}
                    </div>
                    {% endif %}
                    <div class="mt-4 rounded-2xl bg-white p-6 shadow">
                        <p class="text-sm text-gray-600">Use the navigation menu to create tickets, update student records, and manage staff accounts. Dashboard insights update automatically as data changes.</p>
                    </div>
                    {% endif %}

                    {% if active_page == 'tickets' %}
                    <div class="grid gap-6 {% if session.get('role') == 'admin_role' %}lg:grid-cols-2{% else %}lg:grid-cols-1{% endif %}">
                        <section class="rounded-2xl bg-white p-6 shadow space-y-4">
                            <h3 class="text-lg font-semibold">Create Ticket</h3>
                            <p class="text-sm text-gray-500">Provide the student ID and a short description to log a new helpdesk ticket.</p>
                            <form action="/submit_ticket" method="post" class="space-y-3" autocomplete="off">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                <input type="text" name="student_id" placeholder="Student ID" required autocomplete="off"
                                    class="w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:outline-none">
                                <textarea name="issue" placeholder="Describe the issue..." rows="4" required autocomplete="off"
                                    class="w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-blue-500 focus:outline-none"></textarea>
                                <button type="submit"
                                    class="w-full rounded-lg bg-blue-600 py-2 text-sm font-semibold text-white hover:bg-blue-700 transition">Submit Ticket</button>
                            </form>
                            {% if ticket_message %}
                            <p class="text-xs font-medium text-center {% if 'error' in ticket_message|lower %}text-red-500{% else %}text-green-600{% endif %}">{{ ticket_message }}</p>
                            {% endif %}
                        </section>
                        {% if session.get('role') == 'admin_role' %}
                        <section class="rounded-2xl bg-white p-6 shadow space-y-4">
                            <h3 class="text-lg font-semibold">Ticket Search</h3>
                            <p class="text-sm text-gray-500">Search tickets by keyword. Use the Open/Resolved toggle in Manage Tickets below to filter by status.</p>
                            <form action="/search" method="get" class="flex flex-col gap-3 md:flex-row" autocomplete="off">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                <input type="hidden" name="show_resolved" value="{{ 'true' if show_resolved else 'false' }}">
                                <input type="text" name="q" placeholder="Search tickets" value="{{ request.args.get('q', '') }}" autocomplete="off"
                                    class="w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-yellow-500 focus:outline-none md:flex-1">
                                <button type="submit"
                                    class="w-full rounded-lg bg-yellow-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-yellow-600 md:w-auto">Search</button>
                            </form>
                            {% if search_message %}
                            <p class="text-xs font-medium {% if 'No' in search_message %}text-gray-500{% else %}text-blue-600{% endif %}">{{ search_message }}</p>
                            {% endif %}
                            {% if resolve_message %}
                            <p class="text-xs font-medium text-green-600">{{ resolve_message }}</p>
                            {% endif %}
                        </section>
                        {% endif %}
                    </div>
                    {% if session.get('role') == 'admin_role' %}
                    <section class="rounded-2xl bg-white p-6 shadow space-y-4">
                        <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b pb-3">
                    <div>
                        <h3 class="text-lg font-semibold text-gray-800">Manage Tickets</h3>
                        <span class="text-xs font-medium text-gray-500 block mt-1">
                        {% if show_resolved %}
                            Currently viewing resolved tickets
                        {% else %}
                            Currently viewing open tickets
                        {% endif %}
                        </span>
                    </div>

                    <div class="flex items-center gap-2">
                        <a href="{{ url_for('view_all_tickets') }}"
                        class="rounded-full px-4 py-1.5 text-xs font-semibold transition
                                {% if not show_resolved %}
                                    bg-blue-600 text-white hover:bg-blue-700
                                {% else %}
                                    bg-gray-200 text-gray-700 hover:bg-gray-300
                                {% endif %}">
                        Open
                        </a>

                        <a href="{{ url_for('view_all_tickets', show_resolved='true') }}"
                        class="rounded-full px-4 py-1.5 text-xs font-semibold transition
                                {% if show_resolved %}
                                    bg-purple-600 text-white hover:bg-purple-700
                                {% else %}
                                    bg-gray-200 text-gray-700 hover:bg-gray-300
                                {% endif %}">
                        Resolved
                        </a>
                    </div>
                    </div>

                        {% if manage_message %}
                        <p class="text-xs font-medium {% if manage_error %}text-red-500{% else %}text-blue-600{% endif %}">{{ manage_message }}</p>
                        {% endif %}
                        <div class="space-y-3">
                            {% if results %}
                            {% for ticket in results %}
                            <div class="grid grid-cols-1 md:grid-cols-5 gap-3 items-center rounded-xl border border-gray-200 bg-gray-50 p-4 text-sm">
                            
                            <div class="font-semibold text-gray-900 whitespace-nowrap">
                                Ticket #{{ ticket[0] }}
                            </div>

                            <div class="text-gray-700 break-words">
                                {{ ticket[1] }}
                            </div>

                            <div class="text-center">
                                {% if not show_resolved %}
                                <form action="/resolve_ticket" method="post" class="inline">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                <input type="hidden" name="ticket_id" value="{{ ticket[0] }}">
                                <button type="submit"
                                    class="rounded-full bg-green-500 px-3 py-1 text-xs font-semibold text-white hover:bg-green-600 transition">
                                    Resolve
                                </button>
                                </form>
                                {% else %}
                                <span class="text-xs text-gray-500 italic">Resolved</span>
                                {% endif %}
                            </div>

                            <div class="md:col-span-1">
                                <form action="/tickets/edit" method="post" class="flex gap-2 items-center" autocomplete="off">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                <input type="hidden" name="ticket_id" value="{{ ticket[0] }}">
                                <input type="hidden" name="source" value="{% if show_resolved %}resolved{% else %}active{% endif %}">
                                <input type="text" name="issue" value="{{ ticket[1]|e }}"
                                    class="flex-1 rounded-lg border border-gray-300 px-2 py-1 text-xs focus:ring-2 focus:ring-blue-500 focus:outline-none"
                                    autocomplete="off">
                                <button type="submit"
                                    class="rounded-full bg-blue-500 px-3 py-1 text-xs font-semibold text-white hover:bg-blue-600 transition">
                                    Update
                                </button>
                                </form>
                            </div>

                            <div class="text-right">
                                <form action="/tickets/delete" method="post" class="inline" onsubmit="return confirm('Delete this ticket?');">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                <input type="hidden" name="ticket_id" value="{{ ticket[0] }}">
                                <input type="hidden" name="source" value="{% if show_resolved %}resolved{% else %}active{% endif %}">
                                <button type="submit"
                                    class="rounded-full bg-red-500 px-3 py-1 text-xs font-semibold text-white hover:bg-red-600 transition">
                                    Delete
                                </button>
                                </form>
                            </div>
                            </div>
                            {% endfor %}

                            {% else %}
                            <p class="text-xs text-gray-500">No tickets found for the selected filter.</p>
                            {% endif %}
                        </div>
                    </section>

                    <!-- View All Tickets -->
                    <section class="rounded-2xl bg-white p-6 shadow mt-6 space-y-4">
                    <!-- View All Tickets Button -->
                    <form action="{{ url_for('tickets_full') }}" method="get" class="text-center">
                        <button
                        type="submit"
                        class="w-full rounded-2xl bg-gray-800 py-3 text-sm font-semibold text-white hover:bg-gray-900 transition">
                        View All Tickets
                        </button>
                    </form>

                    {% if all_tickets is defined %}
                        {% if all_tickets %}
                        <h3 class="text-lg font-semibold mt-6">All Tickets (Admin View)</h3>
                        <p class="text-sm text-gray-500">Shows every ticket including resolved ones.</p>
                        <div class="overflow-x-auto mt-6">
                        <table class="min-w-full text-sm border">
                            <thead>
                            <tr class="bg-gray-100 text-left">
                                <th class="border px-3 py-2 font-semibold">Ticket ID</th>
                                <th class="border px-3 py-2 font-semibold">Issue</th>
                                <th class="border px-3 py-2 font-semibold">Created At</th>
                            </tr>
                            </thead>
                            <tbody>
                            {% for t in all_tickets %}
                            <tr class="odd:bg-white even:bg-gray-50">
                                <td class="border px-3 py-2">{{ t[0] }}</td>
                                <td class="border px-3 py-2">{{ t[1] }}</td>
                                <td class="border px-3 py-2">{{ t[2].strftime("%Y-%m-%d %H:%M") }}</td>
                            </tr>
                            {% endfor %}
                            </tbody>
                        </table>
                        </div>
                        {% else %}
                        <p class="text-xs text-gray-500 mt-4">No tickets found.</p>
                        {% endif %}
                    {% endif %}
                    </section>



                    {% endif %}
                    {% endif %}

                    {% if active_page == 'students' %}
                    <section class="rounded-2xl bg-white p-6 shadow space-y-4">
                        <h3 class="text-lg font-semibold">{{ page_title or 'Student Directory' }}</h3>
                        <p class="text-sm text-gray-500">{{ page_description or 'View student contact information available to support staff.' }}</p>
                        {% if student_rows %}
                        <div class="overflow-x-auto">
                            <table class="min-w-full text-sm border">
                                <thead>
                                    <tr class="bg-gray-100 text-left">
                                        <th class="border px-3 py-2 font-semibold">ID</th>
                                        <th class="border px-3 py-2 font-semibold">Name</th>
                                        <th class="border px-3 py-2 font-semibold">Email</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for s in student_rows %}
                                    <tr class="odd:bg-white even:bg-gray-50">
                                        <td class="border px-3 py-2">{{ s[0] }}</td>
                                        <td class="border px-3 py-2">{{ s[1] }}</td>
                                        <td class="border px-3 py-2">{{ s[2] }}</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                        {% else %}
                        <p class="text-xs text-gray-500">No students found.</p>
                        {% endif %}
                    </section>
                    {% endif %}

                    {% if active_page == 'sensitive' %}
                    <div class="grid gap-6 lg:grid-cols-3">
                        <section class="rounded-2xl bg-white p-6 shadow space-y-4">
                            <h3 class="text-lg font-semibold">Add Student Record</h3>
                            <p class="text-sm text-gray-500">Capture the latest student contact details. Phone numbers remain restricted to administrators.</p>
                            <form action="/students/add" method="post" class="space-y-3" autocomplete="off">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                <input type="text" name="student_name" placeholder="Full Name" required autocomplete="off"
                                    class="w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:outline-none">
                                <input type="email" name="student_email" placeholder="Email" required autocomplete="off"
                                    class="w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:outline-none">
                                <input type="text" name="student_phone" placeholder="Phone"
                                    class="w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-indigo-500 focus:outline-none">
                                <button type="submit"
                                    class="w-full rounded-lg bg-indigo-600 py-2 text-sm font-semibold text-white hover:bg-indigo-700 transition">Save Student</button>
                            </form>
                            {% if student_message %}
                            <p class="text-xs font-medium text-center {% if student_error %}text-red-500{% else %}text-green-600{% endif %}">{{ student_message }}</p>
                            {% endif %}
                        </section>
                        
                        <section class="rounded-2xl bg-white p-6 shadow space-y-4">
                            <h3 class="text-lg font-semibold">Edit Student Record</h3>
                            <p class="text-sm text-gray-500">Update existing student information. Select a student by ID to modify their details.</p>
                            <form action="/students/edit" method="post" class="space-y-3" autocomplete="off">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                <input type="number" name="student_id" placeholder="Student ID" required autocomplete="off"
                                    class="w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-amber-500 focus:outline-none">
                                <input type="text" name="student_name" placeholder="Full Name" autocomplete="off"
                                    class="w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-amber-500 focus:outline-none">
                                <input type="email" name="student_email" placeholder="Email" autocomplete="off"
                                    class="w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-amber-500 focus:outline-none">
                                <input type="text" name="student_phone" placeholder="Phone"
                                    class="w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-amber-500 focus:outline-none">
                                <button type="submit"
                                    class="w-full rounded-lg bg-amber-600 py-2 text-sm font-semibold text-white hover:bg-amber-700 transition">Update Student</button>
                            </form>
                            <p class="text-xs text-gray-400 italic text-center">Backend handler: /students/edit (To be implemented)</p>
                        </section>
                        
                        <section class="rounded-2xl bg-white p-6 shadow">
                            <h3 class="text-lg font-semibold">Data Handling Notes</h3>
                            <ul class="mt-3 space-y-2 text-sm text-gray-600">
                                <li>• Verify student identity before updating contact details.</li>
                                <li>• Never disclose phone numbers to non-admin personnel.</li>
                                <li>• Audit logs capture all insert actions with your staff ID.</li>
                                <li>• Edit operations will be logged for security tracking.</li>
                            </ul>
                        </section>
                    </div>
                    <section class="rounded-2xl bg-white p-6 shadow space-y-4">
                        <h3 class="text-lg font-semibold">Full Students (Sensitive)</h3>
                        <p class="text-sm text-gray-500">Admin-only access to phone numbers.</p>
                        {% if full_student_rows %}
                        <div class="overflow-x-auto">
                            <table class="min-w-full text-sm border">
                                <thead>
                                    <tr class="bg-gray-100 text-left">
                                        <th class="border px-3 py-2 font-semibold">ID</th>
                                        <th class="border px-3 py-2 font-semibold">Name</th>
                                        <th class="border px-3 py-2 font-semibold">Email</th>
                                        <th class="border px-3 py-2 font-semibold">Phone</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for s in full_student_rows %}
                                    <tr class="odd:bg-white even:bg-gray-50">
                                        <td class="border px-3 py-2">{{ s[0] }}</td>
                                        <td class="border px-3 py-2">{{ s[1] }}</td>
                                        <td class="border px-3 py-2">{{ s[2] }}</td>
                                        <td class="border px-3 py-2">{{ s[3] or '' }}</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                        {% else %}
                        <p class="text-xs text-gray-500">No student records available.</p>
                        {% endif %}
                    </section>
                    {% endif %}

                    {% if active_page == 'accounts' %}
                    <div class="grid gap-6 lg:grid-cols-2">
                        <section class="rounded-2xl bg-white p-6 shadow space-y-4">
                            <h3 class="text-lg font-semibold">Create Staff Account</h3>
                            <p class="text-sm text-gray-500">Provision support or admin access with a temporary password. Users should change credentials on first login.</p>
                            <form action="/accounts/create" method="post" class="space-y-3" autocomplete="off">
                                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                                <input type="text" name="account_username" placeholder="Username" required autocomplete="off"
                                    class="w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-gray-500 focus:outline-none">
                                <input type="password" name="account_password" placeholder="Temporary Password" required autocomplete="off"
                                    class="w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-gray-500 focus:outline-none">
                                <select name="account_role" required
                                    class="w-full rounded-lg border border-gray-300 px-3 py-2 focus:ring-2 focus:ring-gray-500 focus:outline-none">
                                    <option value="support_role">Support Role</option>
                                    <option value="admin_role">Admin Role</option>
                                </select>
                                <button type="submit"
                                    class="w-full rounded-lg bg-gray-800 py-2 text-sm font-semibold text-white hover:bg-gray-900 transition">Create Account</button>
                            </form>
                            {% if account_message %}
                            <p class="text-xs font-medium text-center {% if account_error %}text-red-500{% else %}text-green-600{% endif %}">{{ account_message }}</p>
                            {% endif %}
                        </section>
                        <section class="rounded-2xl bg-white p-6 shadow">
                            <h3 class="text-lg font-semibold">Role Guidance</h3>
                            <ul class="mt-3 space-y-2 text-sm text-gray-600">
                                <li>• Assign <strong>Support Role</strong> for ticket intake and triage.</li>
                                <li>• Reserve <strong>Admin Role</strong> for student data and account management.</li>
                                <li>• Audit entries capture every account change.</li>
                            </ul>
                        </section>
                    </div>
                    <section class="rounded-2xl bg-white p-6 shadow space-y-4">
                        <h3 class="text-lg font-semibold">Existing Accounts</h3>
                        <p class="text-sm text-gray-500">Review active staff credentials and their assigned roles.</p>
                        {% if accounts %}
                        <div class="overflow-x-auto">
                            <table class="min-w-full text-sm border">
                                <thead>
                                    <tr class="bg-gray-100 text-left">
                                        <th class="border px-3 py-2 font-semibold">ID</th>
                                        <th class="border px-3 py-2 font-semibold">Username</th>
                                        <th class="border px-3 py-2 font-semibold">Role</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for account in accounts %}
                                    <tr class="odd:bg-white even:bg-gray-50">
                                        <td class="border px-3 py-2">{{ account.id }}</td>
                                        <td class="border px-3 py-2">{{ account.username }}</td>
                                        <td class="border px-3 py-2">{{ account.role }}</td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                        {% else %}
                        <p class="text-xs text-gray-500">No staff accounts available.</p>
                        {% endif %}
                    </section>
                    {% endif %}

                    {% if active_page == 'audits' %}
                    <section class="rounded-2xl bg-white p-6 shadow space-y-4">
                        <div class="flex flex-wrap items-center justify-between gap-2">
                            <div>
                                <h3 class="text-lg font-semibold">Audit Log</h3>
                                <p class="text-sm text-gray-500">Review recent administrative and ticket activities.</p>
                            </div>
                            <span class="text-xs font-medium text-gray-400">Latest {{ audit_entries|length }} records</span>
                        </div>
                        {% if audit_entries %}
                        <div class="overflow-x-auto">
                            <table class="min-w-full text-sm border">
                                <thead>
                                    <tr class="bg-gray-100 text-left">
                                        <th class="border px-3 py-2 font-semibold">ID</th>
                                        <th class="border px-3 py-2 font-semibold">Timestamp</th>
                                        <th class="border px-3 py-2 font-semibold">Action</th>
                                        <th class="border px-3 py-2 font-semibold">Staff</th>
                                        <th class="border px-3 py-2 font-semibold">Details</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {% for entry in audit_entries %}
                                    <tr class="odd:bg-white even:bg-gray-50 align-top">
                                        <td class="border px-3 py-2">{{ entry.audit_id }}</td>
                                        <td class="border px-3 py-2 whitespace-nowrap text-xs text-gray-500">{{ entry.logged_at }}</td>
                                        <td class="border px-3 py-2 uppercase tracking-wide text-xs font-semibold text-gray-700">{{ entry.action }}</td>
                                        <td class="border px-3 py-2 text-xs">{{ entry.staff_id or '—' }}</td>
                                        <td class="border px-3 py-2 text-xs">
                                            {% if entry.new_data %}
                                            <div>
                                                <span class="font-semibold text-gray-600">New:</span>
                                                <pre class="mt-1 rounded bg-gray-100 px-2 py-1 text-[11px] leading-4 whitespace-pre-wrap">{{ entry.new_data|tojson(indent=2) }}</pre>
                                            </div>
                                            {% endif %}
                                            {% if entry.old_data %}
                                            <div class="mt-2">
                                                <span class="font-semibold text-gray-600">Old:</span>
                                                <pre class="mt-1 rounded bg-gray-100 px-2 py-1 text-[11px] leading-4 whitespace-pre-wrap">{{ entry.old_data|tojson(indent=2) }}</pre>
                                            </div>
                                            {% endif %}
                                            {% if not entry.old_data and not entry.new_data %}
                                            <span class="text-gray-400">No data captured.</span>
                                            {% endif %}
                                        </td>
                                    </tr>
                                    {% endfor %}
                                </tbody>
                            </table>
                        </div>
                        {% else %}
                        <p class="text-xs text-gray-500">No audit entries found.</p>
                        {% endif %}
                    </section>
                    {% endif %}

                    {% if extra_content and active_page not in ['tickets', 'students', 'sensitive', 'accounts', 'audits'] %}
                    <section class="rounded-2xl bg-white p-6 shadow">
                        {{ extra_content|safe }}
                    </section>
                    {% endif %}
                </section>
            </div>
            {% endif %}
        </main>
    </div>

    {% if chart_configs %}
    <script>
        document.addEventListener('DOMContentLoaded', function () {
            const chartConfigs = {{ chart_configs|tojson }};
            chartConfigs.forEach(cfg => {
                const canvas = document.getElementById(cfg.id);
                if (!canvas) {
                    return;
                }
                const ctx = canvas.getContext('2d');
                const options = Object.assign({
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { position: cfg.legend_position || (cfg.type === 'doughnut' ? 'bottom' : 'top') }
                    }
                }, cfg.options || {});
                if (cfg.title_text) {
                    options.plugins = options.plugins || {};
                    options.plugins.title = {
                        display: true,
                        text: cfg.title_text,
                        font: { size: 14 }
                    };
                }
                if (cfg.type === 'bar') {
                    options.scales = Object.assign({
                        y: {
                            beginAtZero: true,
                            ticks: { precision: 0 }
                        }
                    }, options.scales || {});
                }
                const dataset = {
                    label: cfg.dataset_label || '',
                    data: cfg.data,
                    backgroundColor: cfg.background_color || '#2563eb',
                    borderRadius: cfg.type === 'bar' ? 8 : 0,
                    hoverOffset: cfg.type === 'doughnut' ? 6 : 0,
                    maxBarThickness: cfg.type === 'bar' ? 36 : undefined
                };
                const data = {
                    labels: cfg.labels,
                    datasets: [dataset]
                };
                new Chart(ctx, {
                    type: cfg.type,
                    data,
                    options
                });
            });
        });
    </script>
    {% endif %}
</body>
</html>
"""

register_template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Create Account</title>
  <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-50 font-sans text-gray-800">
  <div class="max-w-md mx-auto p-6 mt-10 bg-white rounded-2xl shadow-md">
    <h2 class="text-2xl font-semibold text-center mb-6">Create Account</h2>
    <form action="/register" method="post" class="space-y-4">
      <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">


      <input type="text" name="username" placeholder="Username" required
        class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none">


      <input type="password" name="password" placeholder="Password" required
        class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none">


      <input type="password" name="confirm_password" placeholder="Confirm Password" required
        class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none">


      <select name="role" required
        class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:outline-none">
        <option value="">Select Role</option>
        <option value="support_role">Support Role</option>
        <option value="admin_role">Admin Role</option>
      </select>


      <button type="submit"
        class="w-full bg-green-600 text-white font-medium py-2 px-4 rounded-lg hover:bg-green-700 transition">
        Create Account
      </button>


      {% if register_message %}
        <p class="text-center mt-2 text-red-500 text-sm">{{ register_message }}</p>
      {% endif %}
    </form>


    {% if success %}
      <div class="text-center mt-4">
        <a href="{{ url_for('index') }}"
          class="inline-block bg-blue-600 text-white px-4 py-2 rounded-lg hover:bg-blue-700 transition">
          Proceed to Login
        </a>
      </div>
    {% endif %}
  </div>
</body>
</html>
"""


# Routes
@app.route('/', methods=['GET'])
def index():
    return render_template_string(html_template, **base_view_context())

# admin login
@app.route('/admin', methods=['GET'])
def admin_login_view():
    return render_template_string(
        html_template,
        **base_view_context(show_create=True)
    )

# support login
@app.route('/support', methods=['GET'])
def support_login_view():
    return render_template_string(
        html_template,
        **base_view_context(show_create=False)
    )

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    # Validate input
    if not username or not password:
        return render_template_string(html_template, **base_view_context(login_message="Invalid credentials."))
    
    conn = get_db_connection()
    if not conn:
        return render_template_string(html_template, **base_view_context(login_message="Service temporarily unavailable."))
    try:
        cur = conn.cursor()
        
        # Try with bcrypt first, then fall back to plain text for development
        try:
            cur.execute(
                "SELECT id, username, role FROM staff_users WHERE username = %s AND password_hash = crypt(%s, password_hash)",
                (username, password)
            )
            user = cur.fetchone()
        except psycopg2.Error:
            # Fallback to plain text password (for development databases)
            cur.execute(
                "SELECT id, username, role FROM staff_users WHERE username = %s AND password = %s",
                (username, password)
            )
            user = cur.fetchone()
        
        cur.close()
        if user:
            normalized_role = normalize_role(user[2])
            if not normalized_role:
                return render_template_string(
                    html_template,
                    **base_view_context(login_message="Account role is not authorized. Contact the administrator.")
                )
            session.permanent = False  # Do not keep the session once the browser closes
            session['logged_in'] = True
            session['user_id'] = user[0]  # Store user ID for auditing
            session['username'] = user[1]
            session['role'] = normalized_role
            session['app_instance_token'] = APP_INSTANCE_TOKEN
            # Don't redirect, just reload with session
            return redirect(url_for('index'))
        # Use generic message to prevent username enumeration
        return render_template_string(html_template, **base_view_context(login_message="Invalid credentials."))
    except (Exception, psycopg2.Error) as error:
        print(f"Login error: {error}")  # Log server-side only
        # Generic error message to prevent information disclosure
        return render_template_string(html_template, **base_view_context(login_message="An error occurred. Please try again."))
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
    return render_template_string(
        html_template,
        **base_view_context(login_message="An internal error occurred. Please try again later.")
    ), 500

@app.errorhandler(404)
def handle_not_found(e):
    """Handle 404 errors"""
    return redirect(url_for('index'))

@app.errorhandler(403)
def handle_forbidden(e):
    """Handle 403 errors"""
    return render_template_string(
        html_template,
        **base_view_context(access_message="Access forbidden.")
    ), 403

@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('index'))

# RBAC: restricted student directory (uses view)
@app.route('/students')
@login_required
def students_restricted():
    role = session.get('role')
    if role not in ('support_role', 'admin_role'):
        return render_template_string(
            html_template,
            **base_view_context(
                access_message="Access denied: support or admin role required.",
                active_page='students'
            )
        )
    if role == 'admin_role':
        return redirect(url_for('students_full'))
    rows = load_restricted_students()
    return render_template_string(
        html_template,
        **base_view_context(
            active_page='students',
            page_title='Student Directory',
            page_description='Support-safe directory showing student email access only.',
            student_rows=rows
        )
    )

# RBAC: full student data (admin only)
@app.route('/students/full')
@login_required
def students_full():
    if session.get('role') != 'admin_role':
        return render_template_string(
            html_template,
            **base_view_context(
                access_message="Access denied: admin only.",
                active_page='sensitive'
            )
        )
    return render_template_string(html_template, **sensitive_students_context())

@app.route('/students/add', methods=['POST'])
@login_required
def add_student():
    """Allow administrators to add student records."""
    if session.get('role') != 'admin_role':
        return render_template_string(
            html_template,
            **base_view_context(
                access_message="Access denied: admin only.",
                active_page='sensitive'
            )
        )

    def render_student_feedback(message, is_error=False):
        return render_template_string(html_template, **sensitive_students_context(message, is_error))

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
        set_trigger_user(cur, user_id)

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
        cur.execute(
            "INSERT INTO audit_log (staff_id, action, old_data, new_data) VALUES (%s, %s, %s, %s)",
            (staff_id, 'STUDENT_INSERT', None, Json(audit_payload))
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


@app.route('/accounts', methods=['GET'])
@login_required
def accounts_admin():
    if session.get('role') != 'admin_role':
        return render_template_string(
            html_template,
            **base_view_context(
                access_message="Access denied: admin only.",
                active_page='accounts'
            )
        )
    return render_template_string(html_template, **accounts_view_context())


@app.route('/accounts/create', methods=['POST'])
@login_required
def create_account():
    if session.get('role') != 'admin_role':
        return render_template_string(
            html_template,
            **base_view_context(
                access_message="Access denied: admin only.",
                active_page='accounts'
            )
        )

    username = request.form.get('account_username', '').strip()
    password = request.form.get('account_password', '')
    requested_role = request.form.get('account_role', '').strip()
    normalized_target = normalize_role(requested_role)

    def render_account_feedback(message, is_error=False):
        return render_template_string(html_template, **accounts_view_context(message, is_error))

    if not username or not password:
        return render_account_feedback("Username and password are required.", True)

    if len(username) > 128:
        return render_account_feedback("Username is too long (max 128 characters).", True)

    if normalized_target not in ('support_role', 'admin_role'):
        return render_account_feedback("Select a valid staff role.", True)

    conn = get_db_connection()
    if not conn:
        return render_account_feedback("Service temporarily unavailable.", True)

    cur = None
    try:
        cur = conn.cursor()
        set_trigger_user(cur, session.get('user_id'))

        cur.execute("SELECT 1 FROM staff_users WHERE LOWER(username) = LOWER(%s)", (username,))
        if cur.fetchone():
            cur.close()
            cur = None
            return render_account_feedback("Username already exists.", True)

        # Try bcrypt first, fallback to plain text for development databases
        try:
            cur.execute(
                """
                INSERT INTO staff_users (username, password_hash, role)
                VALUES (%s, crypt(%s, gen_salt('bf')), %s)
                RETURNING id
                """,
                (username, password, normalized_target)
            )
            new_user_id = cur.fetchone()[0]
        except psycopg2.Error:
            # Fallback to plain text password column
            cur.execute(
                """
                INSERT INTO staff_users (username, password, role)
                VALUES (%s, %s, %s)
                RETURNING id
                """,
                (username, password, normalized_target)
            )
            new_user_id = cur.fetchone()[0]

        audit_payload = {
            "created_user_id": new_user_id,
            "username": username,
            "role": normalized_target
        }
        staff_id = session.get('user_id')
        staff_value = int(staff_id) if staff_id is not None else None
        cur.execute(
            "INSERT INTO audit_log (staff_id, action, old_data, new_data) VALUES (%s, %s, %s, %s)",
            (staff_value, 'ACCOUNT_CREATE', None, Json(audit_payload))
        )

        conn.commit()
        cur.close()
        cur = None
        return render_account_feedback("Account created successfully.")
    except psycopg2.IntegrityError as error:
        if conn:
            conn.rollback()
        print(f"Account creation integrity error: {error}")
        return render_account_feedback("Unable to create account due to constraints.", True)
    except (Exception, psycopg2.Error) as error:
        if conn:
            conn.rollback()
        print(f"Account creation error: {error}")
        return render_account_feedback("An error occurred while creating the account.", True)
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


@app.route('/audit-log', methods=['GET'])
@login_required
def audit_log_view():
    if session.get('role') != 'admin_role':
        return render_template_string(
            html_template,
            **base_view_context(
                access_message="Access denied: admin only.",
                active_page='audits'
            )
        )
    return render_template_string(html_template, **audit_view_context())


@app.route('/submit_ticket', methods=['POST'])
@login_required  # CHANGE: enforce authentication for ticket creation
def submit_ticket():
    if session.get('role') not in ('support_role', 'admin_role'):
        return render_ticket_page(access_message="Access denied: support or admin role required.")

    student_id = request.form.get('student_id', '').strip()
    issue = request.form.get('issue', '').strip()

    # Validate inputs
    if not student_id or not issue:
        return render_ticket_page(ticket_message="All fields are required.")

    # Validate student_id is numeric
    try:
        student_id = int(student_id)
    except ValueError:
        return render_ticket_page(ticket_message="Invalid student ID format.")

    # Validate issue length (prevent extremely long submissions)
    if len(issue) > 1000:
        return render_ticket_page(ticket_message="Issue description is too long (max 1000 characters).")

    conn = get_db_connection()
    if not conn:
        return render_ticket_page(ticket_message="Service temporarily unavailable.")
    
    cur = None
    try:
        cur = conn.cursor()

        # Set the session variable for audit trigger to know who created the ticket
        user_id = session.get('user_id')
        if user_id:
            set_trigger_user(cur, user_id)

        # Insert ticket (trigger will automatically create audit log entry)
        cur.execute("INSERT INTO tickets (student_id, issue) VALUES (%s, %s) RETURNING id", (student_id, issue))
        ticket_row = cur.fetchone()
        ticket_id = ticket_row[0] if ticket_row else None

        conn.commit()
        return render_ticket_page(ticket_message="Ticket submitted successfully!")
    except psycopg2.IntegrityError as error:
        if conn:
            conn.rollback()
        error_detail = str(error)
        print(f"Ticket submission integrity error: {error_detail}")
        
        # Check if it's a foreign key constraint on student_id
        if 'student_id' in error_detail or 'foreign key' in error_detail.lower():
            return render_ticket_page(ticket_message=f"Student ID {student_id} does not exist. Please check the ID.")
        else:
            return render_ticket_page(ticket_message="Unable to submit ticket. Please verify student ID.")
    except (Exception, psycopg2.Error) as error:
        if conn:
            conn.rollback()
        error_detail = str(error)
        print(f"Ticket submission error: {error_detail}")
        # Show more specific error in development
        return render_ticket_page(ticket_message=f"Error: {error_detail}")
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

@app.route('/search', methods=['GET'])
@login_required  # CHANGE: must be logged in
def search_tickets():
    # CHANGE: RBAC enforcement - only admin_role may search
    if session.get('role') != 'admin_role':
        return render_ticket_page(access_message="Access denied: admin only.")
    
    query = request.args.get('q', '').strip()
    show_resolved = request.args.get('show_resolved', 'false') == 'true'
    
    # Get tickets based on status filter (resolved or open)
    # If query is empty, show all tickets of selected status
    # If query is provided, filter by keyword within selected status
    results = find_tickets(query, show_resolved)
    
    # Set appropriate message when showing all tickets
    search_message = None
    if not query:
        if show_resolved:
            search_message = "Showing all resolved tickets." if results else "No resolved tickets found."
        else:
            search_message = "Showing all open tickets." if results else "No open tickets found."
    
    return render_ticket_page(results=results, show_resolved=show_resolved, search_message=search_message)

@app.route('/resolve_ticket', methods=['POST'])
@login_required
def resolve_ticket():
    # Only admin can mark tickets as resolved
    if session.get('role') != 'admin_role':
        return render_ticket_page(access_message="Access denied: admin only.")
    
    ticket_id = request.form.get('ticket_id')
    admin_username = session.get('username')
    user_id = session.get('user_id')
    
    # Validate ticket_id is a valid integer
    try:
        ticket_id = int(ticket_id)
    except (ValueError, TypeError):
        return render_ticket_page(search_message="Invalid ticket ID.")
    
    success, message = mark_ticket_as_resolved(ticket_id, admin_username, user_id)
    
    if success:
        return render_ticket_page(resolve_message=message)
    else:
        return render_ticket_page(search_message=message)

@app.route('/tickets/edit', methods=['POST'])
@login_required
def edit_ticket():
    if session.get('role') != 'admin_role':
        return render_ticket_page(access_message="Access denied: admin only.")

    source = request.form.get('source', 'active')
    show_resolved = source == 'resolved'
    ticket_id_raw = request.form.get('ticket_id')
    updated_issue = request.form.get('issue', '').strip()

    try:
        ticket_id = int(ticket_id_raw)
    except (TypeError, ValueError):
        results = find_tickets('', show_resolved)
        return render_ticket_page(
            results=results,
            show_resolved=show_resolved,
            manage_message="Invalid ticket ID.",
            manage_error=True
        )

    if not updated_issue:
        results = find_tickets('', show_resolved)
        return render_ticket_page(
            results=results,
            show_resolved=show_resolved,
            manage_message="Issue description is required.",
            manage_error=True
        )

    if len(updated_issue) > 1000:
        results = find_tickets('', show_resolved)
        return render_ticket_page(
            results=results,
            show_resolved=show_resolved,
            manage_message="Issue description is too long (max 1000 characters).",
            manage_error=True
        )

    conn = get_db_connection()
    if not conn:
        return render_ticket_page(
            show_resolved=show_resolved,
            manage_message="Service temporarily unavailable.",
            manage_error=True
        )

    cur = None
    manage_message = "Ticket updated successfully."
    manage_error = False
    try:
        cur = conn.cursor()
        cur.execute("SELECT student_id, issue FROM tickets WHERE id = %s", (ticket_id,))
        row = cur.fetchone()
        if not row:
            manage_message = "Ticket not found."
            manage_error = True
        else:
            student_id, old_issue = row
            set_trigger_user(cur, session.get('user_id'))
            cur.execute("UPDATE tickets SET issue = %s WHERE id = %s", (updated_issue, ticket_id))

            staff_id = session.get('user_id')
            staff_value = int(staff_id) if staff_id is not None else None
            old_data = {
                "ticket_id": ticket_id,
                "student_id": student_id,
                "issue": old_issue
            }
            new_data = {
                "ticket_id": ticket_id,
                "student_id": student_id,
                "issue": updated_issue
            }
            ticket_id_text = str(ticket_id)
            cur.execute(
                """
                UPDATE audit_log
                   SET action = %s,
                       staff_id = COALESCE(%s, staff_id),
                       old_data = %s,
                       new_data = %s
                 WHERE audit_id = (
                        SELECT audit_id FROM audit_log
                         WHERE action = 'UPDATE'
                           AND COALESCE(new_data->>'ticket_id', old_data->>'ticket_id') = %s
                         ORDER BY logged_at DESC
                         LIMIT 1
                    )
                """,
                ('TICKET_EDIT', staff_value, Json(old_data), Json(new_data), ticket_id_text)
            )
            if cur.rowcount == 0:
                cur.execute(
                    "INSERT INTO audit_log (staff_id, action, old_data, new_data) VALUES (%s, %s, %s, %s)",
                    (staff_value, 'TICKET_EDIT', Json(old_data), Json(new_data))
                )

            conn.commit()
    except (Exception, psycopg2.Error) as error:
        print(f"Ticket update error: {error}")
        manage_message = "An error occurred while updating the ticket."
        manage_error = True
        if conn:
            conn.rollback()
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    results = find_tickets('', show_resolved)
    return render_ticket_page(
        results=results,
        show_resolved=show_resolved,
        manage_message=manage_message,
        manage_error=manage_error
    )

@app.route('/tickets/delete', methods=['POST'])
@login_required
def delete_ticket():
    if session.get('role') != 'admin_role':
        return render_ticket_page(access_message="Access denied: admin only.")

    source = request.form.get('source', 'active')
    show_resolved = source == 'resolved'
    ticket_id_raw = request.form.get('ticket_id')

    try:
        ticket_id = int(ticket_id_raw)
    except (TypeError, ValueError):
        results = find_tickets('', show_resolved)
        return render_ticket_page(
            results=results,
            show_resolved=show_resolved,
            manage_message="Invalid ticket ID.",
            manage_error=True
        )

    conn = get_db_connection()
    if not conn:
        return render_ticket_page(
            show_resolved=show_resolved,
            manage_message="Service temporarily unavailable.",
            manage_error=True
        )

    cur = None
    manage_message = "Ticket deleted successfully."
    manage_error = False
    try:
        cur = conn.cursor()
        cur.execute("SELECT student_id, issue FROM tickets WHERE id = %s", (ticket_id,))
        row = cur.fetchone()
        if not row:
            manage_message = "Ticket not found."
            manage_error = True
        else:
            student_id, old_issue = row
            set_trigger_user(cur, session.get('user_id'))
            cur.execute("DELETE FROM tickets WHERE id = %s", (ticket_id,))

            staff_id = session.get('user_id')
            staff_value = int(staff_id) if staff_id is not None else None
            old_data = {
                "ticket_id": ticket_id,
                "student_id": student_id,
                "issue": old_issue
            }
            ticket_id_text = str(ticket_id)
            cur.execute(
                """
                UPDATE audit_log
                   SET action = %s,
                       staff_id = COALESCE(%s, staff_id),
                       old_data = %s,
                       new_data = NULL
                 WHERE audit_id = (
                        SELECT audit_id FROM audit_log
                         WHERE action = 'DELETE'
                           AND COALESCE(new_data->>'ticket_id', old_data->>'ticket_id') = %s
                         ORDER BY logged_at DESC
                         LIMIT 1
                    )
                """,
                ('TICKET_DELETE', staff_value, Json(old_data), ticket_id_text)
            )
            if cur.rowcount == 0:
                cur.execute(
                    "INSERT INTO audit_log (staff_id, action, old_data, new_data) VALUES (%s, %s, %s, %s)",
                    (staff_value, 'TICKET_DELETE', Json(old_data), None)
                )

            conn.commit()
    except (Exception, psycopg2.Error) as error:
        print(f"Ticket delete error: {error}")
        manage_message = "An error occurred while deleting the ticket."
        manage_error = True
        if conn:
            conn.rollback()
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

    results = find_tickets('', show_resolved)
    return render_ticket_page(
        results=results,
        show_resolved=show_resolved,
        manage_message=manage_message,
        manage_error=manage_error
    )

# View tickets according to filter
@app.route('/view_all')
@login_required
def view_all_tickets():
    if session.get('role') not in ('support_role', 'admin_role'):
        return render_ticket_page(access_message="Access denied: support or admin role required.")

    show_resolved = request.args.get('show_resolved', 'false') == 'true'
    results = find_tickets('', show_resolved) if session.get('role') == 'admin_role' else []
    return render_ticket_page(results=results, show_resolved=show_resolved)


@app.route('/tickets/full')
@login_required
def tickets_full():
    if session.get('role') != 'admin_role':
        return render_ticket_page(
            access_message="Access denied: admin only.",
            active_page='tickets'
        )

    conn = get_db_connection()
    if not conn:
        return render_ticket_page(
            manage_message="Database unavailable.",
            manage_error=True,
            active_page='tickets'
        )

    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM get_all_tickets();")
        all_tickets = cur.fetchall()
        cur.close()


        return render_ticket_page(
            all_tickets=all_tickets,
            active_page='tickets'
        )

    except Exception as e:
        print("Error loading all tickets:", e)
        return render_ticket_page(
            manage_message="Error loading tickets.",
            manage_error=True,
            active_page='tickets'
        )
    finally:
        if conn:
            conn.close()



if __name__ == '__main__':
    # NOTE: Set debug=False in production to prevent information disclosure
    # Debug mode reveals sensitive ecrror information and should only be used in development
    app.run(debug=True)  # Change to False for production deployment

