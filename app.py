# ============================================================
#  EduPrime — Flask Backend (app.py)
#  Connects to XAMPP MySQL (localhost:3306)
#
#  SETUP STEPS:
#  1. Start XAMPP → Apache + MySQL
#  2. Open phpMyAdmin → create database "eduprime"
#  3. Run the SQL schema in /sql/schema.sql (or paste into phpMyAdmin SQL tab)
#  4. pip install flask flask-mysqldb flask-bcrypt flask-jwt-extended flask-cors
#  5. python app.py
#  6. API runs at http://localhost:5000
# ============================================================

from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity
)
from flask_cors import CORS
from datetime import timedelta
import random
import string
from datetime import date

# ─── APP INIT ────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)  # Allow requests from your HTML frontend

# ─── XAMPP MySQL CONFIG ──────────────────────────────────────
app.config['MYSQL_HOST']     = 'localhost'       # XAMPP default
app.config['MYSQL_PORT']     = 3306              # XAMPP default MySQL port
app.config['MYSQL_USER']     = 'root'            # XAMPP default user
app.config['MYSQL_PASSWORD'] = ''               # XAMPP default password (blank)
app.config['MYSQL_DB']       = 'eduprime'        # Your database name
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'  # Return rows as dicts

# ─── JWT CONFIG ──────────────────────────────────────────────
app.config['JWT_SECRET_KEY']        = 'eduprime_jwt_secret_change_me_in_prod'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

# ─── EXTENSIONS ──────────────────────────────────────────────
mysql  = MySQL(app)
bcrypt = Bcrypt(app)
jwt    = JWTManager(app)

# ─── HELPERS ─────────────────────────────────────────────────
def generate_id(prefix, length=5):
    """Generate a random ID like ENR-2026XXXXX or STU-2026XXXXX"""
    digits = ''.join(random.choices(string.digits, k=length))
    return f"{prefix}-{date.today().year}{digits}"

def db_fetchall(query, params=()):
    cur = mysql.connection.cursor()
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()
    return rows

def db_fetchone(query, params=()):
    cur = mysql.connection.cursor()
    cur.execute(query, params)
    row = cur.fetchone()
    cur.close()
    return row

def db_execute(query, params=()):
    cur = mysql.connection.cursor()
    cur.execute(query, params)
    mysql.connection.commit()
    last_id = cur.lastrowid
    cur.close()
    return last_id

# ============================================================
#  AUTH ROUTES
# ============================================================

# POST /api/auth/register
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    first    = data.get('firstName', '').strip()
    last     = data.get('lastName', '').strip()
    email    = data.get('email', '').strip()
    password = data.get('password', '')
    role     = data.get('role', 'student')

    if not all([first, last, email, password]):
        return jsonify({'error': 'All fields are required'}), 400

    # Check duplicate email
    existing = db_fetchone('SELECT id FROM users WHERE email = %s', (email,))
    if existing:
        return jsonify({'error': 'Email already registered'}), 409

    hashed = bcrypt.generate_password_hash(password).decode('utf-8')
    user_id = db_execute(
        'INSERT INTO users (first_name, last_name, email, password_hash, role) VALUES (%s, %s, %s, %s, %s)',
        (first, last, email, hashed, role)
    )

    token = create_access_token(identity={'id': user_id, 'email': email, 'role': role})
    return jsonify({
        'token': token,
        'user': {'id': user_id, 'name': f'{first} {last}', 'email': email, 'role': role}
    }), 201


# POST /api/auth/login
@app.route('/api/auth/login', methods=['POST'])
def login():
    data     = request.get_json()
    email    = data.get('email', '').strip()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    user = db_fetchone('SELECT * FROM users WHERE email = %s', (email,))
    if not user or not bcrypt.check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = create_access_token(identity={
        'id': user['id'], 'email': user['email'], 'role': user['role']
    })
    return jsonify({
        'token': token,
        'user': {
            'id':    user['id'],
            'name':  f"{user['first_name']} {user['last_name']}",
            'email': user['email'],
            'role':  user['role']
        }
    })

# ============================================================
#  STUDENT ROUTES
# ============================================================

# POST /api/students — save/update student profile
@app.route('/api/students', methods=['POST'])
@jwt_required()
def save_student_profile():
    current = get_jwt_identity()
    data = request.get_json()

    dob     = data.get('dateOfBirth')
    gender  = data.get('gender')
    address = data.get('address', '').strip()
    contact = data.get('contactNumber', '').strip()
    program = data.get('program', '').strip()

    if not all([dob, gender, address, contact, program]):
        return jsonify({'error': 'All profile fields are required'}), 400

    # Check if profile already exists
    existing = db_fetchone('SELECT student_id FROM students WHERE user_id = %s', (current['id'],))
    if existing:
        db_execute(
            '''UPDATE students SET date_of_birth=%s, gender=%s, address=%s,
               contact_number=%s, program=%s WHERE user_id=%s''',
            (dob, gender, address, contact, program, current['id'])
        )
        return jsonify({'studentId': existing['student_id'], 'message': 'Profile updated'})
    else:
        # Count existing students for sequential ID
        count = db_fetchone('SELECT COUNT(*) AS c FROM students', ())['c']
        student_id = f"STU-{date.today().year}-{str(count + 1).zfill(4)}"
        db_execute(
            '''INSERT INTO students (user_id, student_id, date_of_birth, gender, address, contact_number, program)
               VALUES (%s, %s, %s, %s, %s, %s, %s)''',
            (current['id'], student_id, dob, gender, address, contact, program)
        )
        return jsonify({'studentId': student_id, 'message': 'Profile created'}), 201


# GET /api/students/me — own profile
@app.route('/api/students/me', methods=['GET'])
@jwt_required()
def get_my_profile():
    current = get_jwt_identity()
    row = db_fetchone(
        '''SELECT u.first_name, u.last_name, u.email, s.student_id,
                  s.date_of_birth, s.gender, s.address, s.contact_number, s.program
           FROM users u LEFT JOIN students s ON u.id = s.user_id
           WHERE u.id = %s''',
        (current['id'],)
    )
    if not row:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(row)


# GET /api/students — admin: list all students
@app.route('/api/students', methods=['GET'])
@jwt_required()
def list_students():
    current = get_jwt_identity()
    if current['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    search  = request.args.get('search', '')
    program = request.args.get('program', '')
    page    = int(request.args.get('page', 1))
    limit   = int(request.args.get('limit', 20))
    offset  = (page - 1) * limit

    query  = '''SELECT u.id, CONCAT(u.first_name,' ',u.last_name) AS name,
                       u.email, s.student_id, s.program, s.gender
                FROM users u LEFT JOIN students s ON u.id = s.user_id WHERE 1=1'''
    params = []
    if search:
        query  += ' AND (u.first_name LIKE %s OR u.last_name LIKE %s OR s.student_id LIKE %s)'
        params += [f'%{search}%', f'%{search}%', f'%{search}%']
    if program:
        query  += ' AND s.program = %s'
        params.append(program)
    query += ' LIMIT %s OFFSET %s'
    params += [limit, offset]

    rows = db_fetchall(query, params)
    return jsonify({'data': rows, 'page': page, 'limit': limit})

# ============================================================
#  DEPARTMENT ROUTES
# ============================================================

# GET /api/departments
@app.route('/api/departments', methods=['GET'])
def get_departments():
    rows = db_fetchall('SELECT * FROM departments ORDER BY name', ())
    return jsonify(rows)


# POST /api/departments — admin only
@app.route('/api/departments', methods=['POST'])
@jwt_required()
def create_department():
    current = get_jwt_identity()
    if current['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.get_json()
    new_id = db_execute(
        'INSERT INTO departments (name, head_of_department, contact_info) VALUES (%s, %s, %s)',
        (data.get('name'), data.get('headOfDepartment'), data.get('contactInfo'))
    )
    return jsonify({'id': new_id, 'message': 'Department created'}), 201

# ============================================================
#  COURSE ROUTES
# ============================================================

# GET /api/courses
@app.route('/api/courses', methods=['GET'])
def get_courses():
    dept_id  = request.args.get('departmentId')
    semester = request.args.get('semester')
    query    = '''SELECT c.*, d.name AS department_name,
                         CONCAT(u.first_name,' ',u.last_name) AS teacher_name
                  FROM courses c
                  JOIN departments d ON c.department_id = d.id
                  LEFT JOIN teachers t ON c.teacher_id = t.id
                  LEFT JOIN users u ON t.user_id = u.id
                  WHERE 1=1'''
    params = []
    if dept_id:
        query += ' AND c.department_id = %s'; params.append(dept_id)
    if semester:
        query += ' AND c.semester = %s'; params.append(semester)
    query += ' ORDER BY c.course_code'
    return jsonify(db_fetchall(query, params))


# GET /api/courses/<id>
@app.route('/api/courses/<int:course_id>', methods=['GET'])
def get_course(course_id):
    row = db_fetchone(
        '''SELECT c.*, d.name AS department_name,
                  CONCAT(u.first_name,' ',u.last_name) AS teacher_name,
                  COUNT(e.id) AS enrolled_count
           FROM courses c
           JOIN departments d ON c.department_id = d.id
           LEFT JOIN teachers t ON c.teacher_id = t.id
           LEFT JOIN users u ON t.user_id = u.id
           LEFT JOIN enrollments e ON e.course_code = c.course_code AND e.status = 'Active'
           WHERE c.id = %s GROUP BY c.id''',
        (course_id,)
    )
    if not row:
        return jsonify({'error': 'Course not found'}), 404
    return jsonify(row)


# POST /api/courses — admin only
@app.route('/api/courses', methods=['POST'])
@jwt_required()
def create_course():
    current = get_jwt_identity()
    if current['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.get_json()
    new_id = db_execute(
        '''INSERT INTO courses (course_code, course_title, description, credit_units,
           department_id, semester, teacher_id) VALUES (%s,%s,%s,%s,%s,%s,%s)''',
        (data.get('courseCode'), data.get('courseTitle'), data.get('description'),
         data.get('creditUnits'), data.get('departmentId'), data.get('semester'),
         data.get('teacherId'))
    )
    return jsonify({'id': new_id, 'message': 'Course created'}), 201

# ============================================================
#  SCHEDULE ROUTES
# ============================================================

# GET /api/schedules
@app.route('/api/schedules', methods=['GET'])
def get_schedules():
    course_code = request.args.get('courseCode')
    query = '''SELECT s.*, c.course_title, r.location, r.capacity, r.type AS room_type
               FROM schedules s
               JOIN courses c ON s.course_code = c.course_code
               JOIN classrooms r ON s.classroom_id = r.id'''
    params = []
    if course_code:
        query += ' WHERE s.course_code = %s'; params.append(course_code)
    query += " ORDER BY FIELD(s.day,'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'), s.start_time"
    return jsonify(db_fetchall(query, params))


# POST /api/schedules — admin only
@app.route('/api/schedules', methods=['POST'])
@jwt_required()
def create_schedule():
    current = get_jwt_identity()
    if current['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data = request.get_json()
    classroom_id = data.get('classroomId')
    day          = data.get('day')
    start_time   = data.get('startTime')
    end_time     = data.get('endTime')

    # Conflict check
    conflict = db_fetchone(
        '''SELECT id FROM schedules WHERE classroom_id=%s AND day=%s
           AND ((start_time < %s AND end_time > %s) OR (start_time < %s AND end_time > %s))''',
        (classroom_id, day, end_time, start_time, start_time, end_time)
    )
    if conflict:
        return jsonify({'error': 'Classroom schedule conflict detected'}), 409

    new_id = db_execute(
        'INSERT INTO schedules (course_code, classroom_id, day, start_time, end_time) VALUES (%s,%s,%s,%s,%s)',
        (data.get('courseCode'), classroom_id, day, start_time, end_time)
    )
    return jsonify({'id': new_id, 'message': 'Schedule created'}), 201

# ============================================================
#  ENROLLMENT ROUTES
# ============================================================

# POST /api/enrollments
@app.route('/api/enrollments', methods=['POST'])
@jwt_required()
def enroll():
    current      = get_jwt_identity()
    data         = request.get_json()
    course_codes = data.get('courseCodes', [])

    if not isinstance(course_codes, list) or not course_codes:
        return jsonify({'error': 'courseCodes array is required'}), 400
    if len(course_codes) > 5:
        return jsonify({'error': 'Maximum 5 courses per semester'}), 400

    student = db_fetchone('SELECT * FROM students WHERE user_id = %s', (current['id'],))
    if not student:
        return jsonify({'error': 'Complete your student profile first'}), 400

    # Find already-enrolled courses
    existing_rows = db_fetchall(
        "SELECT course_code FROM enrollments WHERE student_id = %s AND status != 'Withdrawn'",
        (student['student_id'],)
    )
    already_enrolled = [r['course_code'] for r in existing_rows]
    new_courses      = [c for c in course_codes if c not in already_enrolled]

    if not new_courses:
        return jsonify({'error': 'Already enrolled in all selected courses'}), 409

    results      = []
    today_str    = date.today().isoformat()

    for code in new_courses:
        enroll_id = generate_id('ENR')
        db_execute(
            '''INSERT INTO enrollments (enrollment_id, student_id, course_code, enrollment_date, status)
               VALUES (%s, %s, %s, %s, 'Active')''',
            (enroll_id, student['student_id'], code, today_str)
        )
        results.append({'enrollmentId': enroll_id, 'courseCode': code, 'status': 'Active'})

    return jsonify({
        'enrolled': results,
        'message':  f"Successfully enrolled in {len(results)} course(s)"
    }), 201


# GET /api/enrollments/me
@app.route('/api/enrollments/me', methods=['GET'])
@jwt_required()
def my_enrollments():
    current = get_jwt_identity()
    student = db_fetchone('SELECT student_id FROM students WHERE user_id = %s', (current['id'],))
    if not student:
        return jsonify({'error': 'Student profile not found'}), 404

    rows = db_fetchall(
        '''SELECT e.*, c.course_title, c.credit_units, c.semester,
                  CONCAT(u.first_name,' ',u.last_name) AS teacher_name,
                  s.day, s.start_time, s.end_time, r.location AS classroom
           FROM enrollments e
           JOIN courses c ON e.course_code = c.course_code
           LEFT JOIN teachers t ON c.teacher_id = t.id
           LEFT JOIN users u ON t.user_id = u.id
           LEFT JOIN schedules s ON s.course_code = e.course_code
           LEFT JOIN classrooms r ON s.classroom_id = r.id
           WHERE e.student_id = %s
           ORDER BY e.enrollment_date DESC''',
        (student['student_id'],)
    )
    return jsonify(rows)


# GET /api/enrollments — admin
@app.route('/api/enrollments', methods=['GET'])
@jwt_required()
def list_enrollments():
    current = get_jwt_identity()
    if current['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    status      = request.args.get('status')
    course_code = request.args.get('courseCode')
    page        = int(request.args.get('page', 1))
    limit       = int(request.args.get('limit', 20))
    offset      = (page - 1) * limit

    query  = '''SELECT e.enrollment_id, CONCAT(u.first_name,' ',u.last_name) AS student_name,
                       s.student_id, e.course_code, c.course_title,
                       e.enrollment_date, e.status
                FROM enrollments e
                JOIN students s ON e.student_id = s.student_id
                JOIN users u ON s.user_id = u.id
                JOIN courses c ON e.course_code = c.course_code
                WHERE 1=1'''
    params = []
    if status:
        query += ' AND e.status = %s'; params.append(status)
    if course_code:
        query += ' AND e.course_code = %s'; params.append(course_code)
    query += ' ORDER BY e.enrollment_date DESC LIMIT %s OFFSET %s'
    params += [limit, offset]

    rows = db_fetchall(query, params)
    return jsonify({'data': rows, 'page': page, 'limit': limit})


# PATCH /api/enrollments/<enrollment_id>
@app.route('/api/enrollments/<enrollment_id>', methods=['PATCH'])
@jwt_required()
def update_enrollment(enrollment_id):
    current = get_jwt_identity()
    data    = request.get_json()
    status  = data.get('status')
    allowed = ['Active', 'Completed', 'Withdrawn']

    if status not in allowed:
        return jsonify({'error': f'Status must be one of {allowed}'}), 400

    row = db_fetchone('SELECT * FROM enrollments WHERE enrollment_id = %s', (enrollment_id,))
    if not row:
        return jsonify({'error': 'Enrollment not found'}), 404

    # Students can only withdraw their own enrollment
    if current['role'] != 'admin':
        student = db_fetchone('SELECT user_id FROM students WHERE student_id = %s', (row['student_id'],))
        if not student or student['user_id'] != current['id']:
            return jsonify({'error': 'Forbidden'}), 403
        if status != 'Withdrawn':
            return jsonify({'error': 'Students can only set status to Withdrawn'}), 403

    db_execute('UPDATE enrollments SET status = %s WHERE enrollment_id = %s', (status, enrollment_id))
    return jsonify({'message': f'Enrollment status updated to {status}'})

# ============================================================
#  GRADE ROUTES
# ============================================================

# POST /api/grades
@app.route('/api/grades', methods=['POST'])
@jwt_required()
def save_grade():
    data = request.get_json()
    db_execute(
        '''INSERT INTO grades (enrollment_id, course_code, student_id, grade, remarks)
           VALUES (%s, %s, %s, %s, %s)
           ON DUPLICATE KEY UPDATE grade=VALUES(grade), remarks=VALUES(remarks)''',
        (data.get('enrollmentId'), data.get('courseCode'),
         data.get('studentId'), data.get('grade'), data.get('remarks'))
    )
    return jsonify({'message': 'Grade saved'}), 201


# GET /api/grades/me
@app.route('/api/grades/me', methods=['GET'])
@jwt_required()
def my_grades():
    current = get_jwt_identity()
    student = db_fetchone('SELECT student_id FROM students WHERE user_id = %s', (current['id'],))
    if not student:
        return jsonify({'error': 'Student not found'}), 404
    rows = db_fetchall(
        '''SELECT g.*, c.course_title, c.credit_units
           FROM grades g JOIN courses c ON g.course_code = c.course_code
           WHERE g.student_id = %s''',
        (student['student_id'],)
    )
    return jsonify(rows)

# ============================================================
#  CLASSROOM ROUTES
# ============================================================

@app.route('/api/classrooms', methods=['GET'])
@jwt_required()
def get_classrooms():
    return jsonify(db_fetchall('SELECT * FROM classrooms ORDER BY location', ()))


@app.route('/api/classrooms', methods=['POST'])
@jwt_required()
def create_classroom():
    current = get_jwt_identity()
    if current['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403
    data   = request.get_json()
    new_id = db_execute(
        'INSERT INTO classrooms (location, capacity, type) VALUES (%s, %s, %s)',
        (data.get('location'), data.get('capacity'), data.get('type', 'Lecture'))
    )
    return jsonify({'id': new_id, 'message': 'Classroom created'}), 201

# ============================================================
#  ADMIN STATS / DASHBOARD
# ============================================================

@app.route('/api/admin/stats', methods=['GET'])
@jwt_required()
def admin_stats():
    current = get_jwt_identity()
    if current['role'] != 'admin':
        return jsonify({'error': 'Admin access required'}), 403

    total_students   = db_fetchone('SELECT COUNT(*) AS c FROM students', ())['c']
    total_courses    = db_fetchone('SELECT COUNT(*) AS c FROM courses', ())['c']
    active_enrolls   = db_fetchone("SELECT COUNT(*) AS c FROM enrollments WHERE status='Active'", ())['c']
    total_depts      = db_fetchone('SELECT COUNT(*) AS c FROM departments', ())['c']
    by_status        = db_fetchall('SELECT status, COUNT(*) AS count FROM enrollments GROUP BY status', ())
    top_courses      = db_fetchall(
        "SELECT course_code, COUNT(*) AS enrolled FROM enrollments WHERE status='Active' GROUP BY course_code ORDER BY enrolled DESC LIMIT 5",
        ()
    )
    recent_enrolls   = db_fetchall(
        '''SELECT e.enrollment_id, CONCAT(u.first_name,' ',u.last_name) AS student_name,
                  e.course_code, e.enrollment_date, e.status
           FROM enrollments e
           JOIN students s ON e.student_id = s.student_id
           JOIN users u ON s.user_id = u.id
           ORDER BY e.enrollment_date DESC LIMIT 10''',
        ()
    )
    return jsonify({
        'totalStudents':    total_students,
        'totalCourses':     total_courses,
        'activeEnrollments': active_enrolls,
        'totalDepartments': total_depts,
        'byStatus':         by_status,
        'topCourses':       top_courses,
        'recentEnrollments': recent_enrolls
    })

# ============================================================
#  HEALTH CHECK
# ============================================================

@app.route('/api/health', methods=['GET'])
def health():
    try:
        db_fetchone('SELECT 1', ())
        return jsonify({'status': 'ok', 'database': 'connected', 'xampp': 'running'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ============================================================
#  RUN
# ============================================================

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)