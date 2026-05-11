// ============================================================
// EduPrime Enrollment System — Node.js + Express + MySQL Backend
// ============================================================
// Install dependencies:
//   npm install express mysql2 bcryptjs jsonwebtoken cors dotenv
// Create .env file (see bottom of this file for template)
// Run: node server.js
// ============================================================

require('dotenv').config();
const express    = require('express');
const mysql      = require('mysql2/promise');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ─── DB POOL ────────────────────────────────────────────────
const pool = mysql.createPool({
  host:     process.env.DB_HOST     || 'localhost',
  user:     process.env.DB_USER     || 'root',
  password: process.env.DB_PASS     || '',
  database: process.env.DB_NAME     || 'eduprime',
  waitForConnections: true,
  connectionLimit: 10,
});

// ─── HELPERS ────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'eduprime_secret_change_me';

function makeToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'No token provided' });
  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin')
    return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ═══════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  const { firstName, lastName, email, password, role = 'student' } = req.body;
  if (!firstName || !lastName || !email || !password)
    return res.status(400).json({ error: 'All fields required' });

  const [existing] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
  if (existing.length) return res.status(409).json({ error: 'Email already registered' });

  const hash = await bcrypt.hash(password, 12);
  const [result] = await pool.query(
    'INSERT INTO users (first_name, last_name, email, password_hash, role) VALUES (?,?,?,?,?)',
    [firstName, lastName, email, hash, role]
  );

  const token = makeToken({ id: result.insertId, email, role });
  res.status(201).json({ token, user: { id: result.insertId, name: `${firstName} ${lastName}`, email, role } });
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'Email and password required' });

  const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
  if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });

  const user = rows[0];
  const match = await bcrypt.compare(password, user.password_hash);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const token = makeToken({ id: user.id, email: user.email, role: user.role });
  res.json({ token, user: { id: user.id, name: `${user.first_name} ${user.last_name}`, email: user.email, role: user.role } });
});

// ═══════════════════════════════════════════════════════════
// STUDENT ROUTES
// ═══════════════════════════════════════════════════════════

// POST /api/students — create/complete student profile
app.post('/api/students', authMiddleware, async (req, res) => {
  const { dateOfBirth, gender, address, contactNumber, program } = req.body;
  if (!dateOfBirth || !gender || !address || !contactNumber || !program)
    return res.status(400).json({ error: 'All profile fields required' });

  // Generate student ID
  const year  = new Date().getFullYear();
  const [cnt] = await pool.query('SELECT COUNT(*) AS c FROM students');
  const studentId = `STU-${year}-${String(cnt[0].c + 1).padStart(4, '0')}`;

  await pool.query(
    `INSERT INTO students (user_id, student_id, date_of_birth, gender, address, contact_number, program)
     VALUES (?,?,?,?,?,?,?)
     ON DUPLICATE KEY UPDATE date_of_birth=VALUES(date_of_birth), gender=VALUES(gender),
       address=VALUES(address), contact_number=VALUES(contact_number), program=VALUES(program)`,
    [req.user.id, studentId, dateOfBirth, gender, address, contactNumber, program]
  );

  res.status(201).json({ studentId, message: 'Profile saved' });
});

// GET /api/students/me — get own profile
app.get('/api/students/me', authMiddleware, async (req, res) => {
  const [rows] = await pool.query(
    `SELECT u.first_name, u.last_name, u.email, s.student_id,
            s.date_of_birth, s.gender, s.address, s.contact_number, s.program
     FROM users u LEFT JOIN students s ON u.id = s.user_id
     WHERE u.id = ?`,
    [req.user.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Student not found' });
  res.json(rows[0]);
});

// GET /api/students — admin: list all students
app.get('/api/students', authMiddleware, adminOnly, async (req, res) => {
  const { search, program, page = 1, limit = 20 } = req.query;
  const offset = (page - 1) * limit;
  let where = 'WHERE 1=1';
  const params = [];
  if (search) { where += ' AND (u.first_name LIKE ? OR u.last_name LIKE ? OR s.student_id LIKE ?)'; params.push(`%${search}%`,`%${search}%`,`%${search}%`); }
  if (program) { where += ' AND s.program = ?'; params.push(program); }
  const [rows] = await pool.query(
    `SELECT u.id, CONCAT(u.first_name,' ',u.last_name) AS name, u.email,
            s.student_id, s.program, s.gender
     FROM users u LEFT JOIN students s ON u.id = s.user_id
     ${where} LIMIT ? OFFSET ?`,
    [...params, Number(limit), Number(offset)]
  );
  const [[{total}]] = await pool.query(`SELECT COUNT(*) AS total FROM users u LEFT JOIN students s ON u.id=s.user_id ${where}`, params);
  res.json({ data: rows, total, page: Number(page), limit: Number(limit) });
});

// ═══════════════════════════════════════════════════════════
// DEPARTMENT ROUTES
// ═══════════════════════════════════════════════════════════

// GET /api/departments
app.get('/api/departments', async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM departments ORDER BY name');
  res.json(rows);
});

// POST /api/departments — admin only
app.post('/api/departments', authMiddleware, adminOnly, async (req, res) => {
  const { name, headOfDepartment, contactInfo } = req.body;
  const [r] = await pool.query(
    'INSERT INTO departments (name, head_of_department, contact_info) VALUES (?,?,?)',
    [name, headOfDepartment, contactInfo]
  );
  res.status(201).json({ id: r.insertId, message: 'Department created' });
});

// ═══════════════════════════════════════════════════════════
// COURSE ROUTES
// ═══════════════════════════════════════════════════════════

// GET /api/courses — list courses (public)
app.get('/api/courses', async (req, res) => {
  const { departmentId, semester } = req.query;
  let where = 'WHERE 1=1';
  const params = [];
  if (departmentId) { where += ' AND c.department_id = ?'; params.push(departmentId); }
  if (semester)     { where += ' AND c.semester = ?'; params.push(semester); }
  const [rows] = await pool.query(
    `SELECT c.*, d.name AS department_name,
            CONCAT(u.first_name,' ',u.last_name) AS teacher_name
     FROM courses c
     JOIN departments d ON c.department_id = d.id
     LEFT JOIN teachers t ON c.teacher_id = t.id
     LEFT JOIN users u ON t.user_id = u.id
     ${where} ORDER BY c.course_code`,
    params
  );
  res.json(rows);
});

// GET /api/courses/:id
app.get('/api/courses/:id', async (req, res) => {
  const [rows] = await pool.query(
    `SELECT c.*, d.name AS department_name,
            CONCAT(u.first_name,' ',u.last_name) AS teacher_name,
            COUNT(e.id) AS enrolled_count
     FROM courses c
     JOIN departments d ON c.department_id = d.id
     LEFT JOIN teachers t ON c.teacher_id = t.id
     LEFT JOIN users u ON t.user_id = u.id
     LEFT JOIN enrollments e ON e.course_code = c.course_code AND e.status = 'Active'
     WHERE c.id = ? GROUP BY c.id`,
    [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Course not found' });
  res.json(rows[0]);
});

// POST /api/courses — admin only
app.post('/api/courses', authMiddleware, adminOnly, async (req, res) => {
  const { courseCode, courseTitle, description, creditUnits, departmentId, semester, teacherId } = req.body;
  const [r] = await pool.query(
    'INSERT INTO courses (course_code, course_title, description, credit_units, department_id, semester, teacher_id) VALUES (?,?,?,?,?,?,?)',
    [courseCode, courseTitle, description, creditUnits, departmentId, semester, teacherId]
  );
  res.status(201).json({ id: r.insertId, message: 'Course created' });
});

// ═══════════════════════════════════════════════════════════
// SCHEDULE ROUTES
// ═══════════════════════════════════════════════════════════

// GET /api/schedules — list schedules for a course
app.get('/api/schedules', async (req, res) => {
  const { courseCode } = req.query;
  let where = courseCode ? 'WHERE s.course_code = ?' : '';
  const [rows] = await pool.query(
    `SELECT s.*, c.course_title, r.location, r.capacity, r.type AS room_type
     FROM schedules s
     JOIN courses c ON s.course_code = c.course_code
     JOIN classrooms r ON s.classroom_id = r.id
     ${where} ORDER BY FIELD(s.day,'Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'), s.start_time`,
    courseCode ? [courseCode] : []
  );
  res.json(rows);
});

// POST /api/schedules — admin only
app.post('/api/schedules', authMiddleware, adminOnly, async (req, res) => {
  const { courseCode, classroomId, day, startTime, endTime } = req.body;
  // Check for classroom conflict
  const [conflict] = await pool.query(
    `SELECT id FROM schedules WHERE classroom_id = ? AND day = ?
     AND ((start_time < ? AND end_time > ?) OR (start_time < ? AND end_time > ?))`,
    [classroomId, day, endTime, startTime, startTime, endTime]
  );
  if (conflict.length) return res.status(409).json({ error: 'Classroom conflict detected' });

  const [r] = await pool.query(
    'INSERT INTO schedules (course_code, classroom_id, day, start_time, end_time) VALUES (?,?,?,?,?)',
    [courseCode, classroomId, day, startTime, endTime]
  );
  res.status(201).json({ id: r.insertId, message: 'Schedule created' });
});

// ═══════════════════════════════════════════════════════════
// ENROLLMENT ROUTES
// ═══════════════════════════════════════════════════════════

// POST /api/enrollments — student enrolls in courses
app.post('/api/enrollments', authMiddleware, async (req, res) => {
  const { courseCodes } = req.body; // array of course codes
  if (!Array.isArray(courseCodes) || !courseCodes.length)
    return res.status(400).json({ error: 'courseCodes array required' });
  if (courseCodes.length > 5)
    return res.status(400).json({ error: 'Maximum 5 courses per semester' });

  // Get student record
  const [studentRows] = await pool.query('SELECT * FROM students WHERE user_id = ?', [req.user.id]);
  if (!studentRows.length) return res.status(400).json({ error: 'Complete your student profile first' });
  const student = studentRows[0];

  // Check existing enrollments for this semester
  const [existing] = await pool.query(
    `SELECT course_code FROM enrollments WHERE student_id = ? AND status != 'Withdrawn'`,
    [student.student_id]
  );
  const alreadyEnrolled = existing.map(e => e.course_code);
  const newCourses = courseCodes.filter(c => !alreadyEnrolled.includes(c));
  if (!newCourses.length) return res.status(409).json({ error: 'Already enrolled in all selected courses' });

  const enrollmentDate = new Date().toISOString().split('T')[0];
  const results = [];

  for (const code of newCourses) {
    const enrollId = `ENR-${new Date().getFullYear()}${String(Math.floor(Math.random() * 90000 + 10000))}`;
    await pool.query(
      `INSERT INTO enrollments (enrollment_id, student_id, course_code, enrollment_date, status)
       VALUES (?,?,?,?,?)`,
      [enrollId, student.student_id, code, enrollmentDate, 'Active']
    );
    results.push({ enrollmentId: enrollId, courseCode: code, status: 'Active' });
  }

  res.status(201).json({ enrolled: results, message: `Successfully enrolled in ${results.length} course(s)` });
});

// GET /api/enrollments/me — student's own enrollments
app.get('/api/enrollments/me', authMiddleware, async (req, res) => {
  const [studentRows] = await pool.query('SELECT student_id FROM students WHERE user_id = ?', [req.user.id]);
  if (!studentRows.length) return res.status(404).json({ error: 'Student profile not found' });

  const [rows] = await pool.query(
    `SELECT e.*, c.course_title, c.credit_units, c.semester,
            CONCAT(u.first_name,' ',u.last_name) AS teacher_name,
            s.day, s.start_time, s.end_time, r.location AS classroom
     FROM enrollments e
     JOIN courses c ON e.course_code = c.course_code
     LEFT JOIN teachers t ON c.teacher_id = t.id
     LEFT JOIN users u ON t.user_id = u.id
     LEFT JOIN schedules s ON s.course_code = e.course_code
     LEFT JOIN classrooms r ON s.classroom_id = r.id
     WHERE e.student_id = ?
     ORDER BY e.enrollment_date DESC`,
    [studentRows[0].student_id]
  );
  res.json(rows);
});

// GET /api/enrollments — admin: all enrollments
app.get('/api/enrollments', authMiddleware, adminOnly, async (req, res) => {
  const { status, courseCode, page = 1, limit = 20 } = req.query;
  const offset = (page - 1) * limit;
  let where = 'WHERE 1=1';
  const params = [];
  if (status)     { where += ' AND e.status = ?'; params.push(status); }
  if (courseCode) { where += ' AND e.course_code = ?'; params.push(courseCode); }
  const [rows] = await pool.query(
    `SELECT e.enrollment_id, CONCAT(u.first_name,' ',u.last_name) AS student_name,
            s.student_id, e.course_code, c.course_title, e.enrollment_date, e.status
     FROM enrollments e
     JOIN students s ON e.student_id = s.student_id
     JOIN users u ON s.user_id = u.id
     JOIN courses c ON e.course_code = c.course_code
     ${where} ORDER BY e.enrollment_date DESC LIMIT ? OFFSET ?`,
    [...params, Number(limit), Number(offset)]
  );
  res.json({ data: rows, page: Number(page), limit: Number(limit) });
});

// PATCH /api/enrollments/:id — update status (admin or student withdraw)
app.patch('/api/enrollments/:id', authMiddleware, async (req, res) => {
  const { status } = req.body;
  const allowed = ['Active', 'Completed', 'Withdrawn'];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'Invalid status' });

  const [rows] = await pool.query('SELECT * FROM enrollments WHERE enrollment_id = ?', [req.params.id]);
  if (!rows.length) return res.status(404).json({ error: 'Enrollment not found' });

  // Students can only withdraw their own enrollments
  if (req.user.role !== 'admin') {
    const [s] = await pool.query('SELECT user_id FROM students WHERE student_id = ?', [rows[0].student_id]);
    if (!s.length || s[0].user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
    if (status !== 'Withdrawn') return res.status(403).json({ error: 'Students can only withdraw' });
  }

  await pool.query('UPDATE enrollments SET status = ? WHERE enrollment_id = ?', [status, req.params.id]);
  res.json({ message: `Status updated to ${status}` });
});

// ═══════════════════════════════════════════════════════════
// GRADE ROUTES
// ═══════════════════════════════════════════════════════════

// POST /api/grades — teacher or admin assigns grade
app.post('/api/grades', authMiddleware, async (req, res) => {
  const { enrollmentId, courseCode, studentId, grade, remarks } = req.body;
  await pool.query(
    `INSERT INTO grades (enrollment_id, course_code, student_id, grade, remarks)
     VALUES (?,?,?,?,?)
     ON DUPLICATE KEY UPDATE grade=VALUES(grade), remarks=VALUES(remarks)`,
    [enrollmentId, courseCode, studentId, grade, remarks]
  );
  res.status(201).json({ message: 'Grade saved' });
});

// GET /api/grades/me — student's own grades
app.get('/api/grades/me', authMiddleware, async (req, res) => {
  const [studentRows] = await pool.query('SELECT student_id FROM students WHERE user_id = ?', [req.user.id]);
  if (!studentRows.length) return res.status(404).json({ error: 'Student not found' });

  const [rows] = await pool.query(
    `SELECT g.*, c.course_title, c.credit_units
     FROM grades g JOIN courses c ON g.course_code = c.course_code
     WHERE g.student_id = ?`,
    [studentRows[0].student_id]
  );
  res.json(rows);
});

// ═══════════════════════════════════════════════════════════
// CLASSROOM ROUTES
// ═══════════════════════════════════════════════════════════

app.get('/api/classrooms', authMiddleware, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM classrooms ORDER BY location');
  res.json(rows);
});

app.post('/api/classrooms', authMiddleware, adminOnly, async (req, res) => {
  const { location, capacity, type } = req.body;
  const [r] = await pool.query(
    'INSERT INTO classrooms (location, capacity, type) VALUES (?,?,?)',
    [location, capacity, type]
  );
  res.status(201).json({ id: r.insertId });
});

// ═══════════════════════════════════════════════════════════
// DASHBOARD / STATS (admin)
// ═══════════════════════════════════════════════════════════

app.get('/api/admin/stats', authMiddleware, adminOnly, async (req, res) => {
  const [[{ totalStudents }]] = await pool.query('SELECT COUNT(*) AS totalStudents FROM students');
  const [[{ totalCourses  }]] = await pool.query('SELECT COUNT(*) AS totalCourses FROM courses');
  const [[{ activeEnrollments }]] = await pool.query(`SELECT COUNT(*) AS activeEnrollments FROM enrollments WHERE status='Active'`);
  const [[{ totalDepts }]] = await pool.query('SELECT COUNT(*) AS totalDepts FROM departments');
  const [byStatus] = await pool.query(
    `SELECT status, COUNT(*) AS count FROM enrollments GROUP BY status`
  );
  const [topCourses] = await pool.query(
    `SELECT course_code, COUNT(*) AS enrolled FROM enrollments WHERE status='Active'
     GROUP BY course_code ORDER BY enrolled DESC LIMIT 5`
  );
  res.json({ totalStudents, totalCourses, activeEnrollments, totalDepts, byStatus, topCourses });
});

// ─── START ───────────────────────────────────────────────────
app.listen(PORT, () => console.log(`EduPrime API running on http://localhost:${PORT}`));


// ============================================================
// MySQL SCHEMA  —  run in your MySQL client to initialize
// ============================================================
/*
CREATE DATABASE IF NOT EXISTS eduprime CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE eduprime;

CREATE TABLE users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  first_name    VARCHAR(100) NOT NULL,
  last_name     VARCHAR(100) NOT NULL,
  email         VARCHAR(191) NOT NULL UNIQUE,
  password_hash VARCHAR(255) NOT NULL,
  role          ENUM('student','admin','teacher','department_head') DEFAULT 'student',
  created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE departments (
  id                 INT AUTO_INCREMENT PRIMARY KEY,
  name               VARCHAR(150) NOT NULL,
  head_of_department VARCHAR(150),
  contact_info       VARCHAR(255)
);

CREATE TABLE teachers (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  user_id        INT NOT NULL REFERENCES users(id),
  department_id  INT REFERENCES departments(id),
  contact_number VARCHAR(20),
  specialization VARCHAR(150)
);

CREATE TABLE classrooms (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  location VARCHAR(150) NOT NULL,
  capacity INT NOT NULL,
  type     ENUM('Lecture','Lab','Virtual') DEFAULT 'Lecture'
);

CREATE TABLE courses (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  course_code  VARCHAR(20) NOT NULL UNIQUE,
  course_title VARCHAR(200) NOT NULL,
  description  TEXT,
  credit_units INT NOT NULL,
  department_id INT REFERENCES departments(id),
  teacher_id   INT REFERENCES teachers(id),
  semester     VARCHAR(50)
);

CREATE TABLE schedules (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  course_code  VARCHAR(20) REFERENCES courses(course_code),
  classroom_id INT REFERENCES classrooms(id),
  day          ENUM('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'),
  start_time   TIME NOT NULL,
  end_time     TIME NOT NULL
);

CREATE TABLE students (
  id             INT AUTO_INCREMENT PRIMARY KEY,
  user_id        INT NOT NULL UNIQUE REFERENCES users(id),
  student_id     VARCHAR(30) NOT NULL UNIQUE,
  date_of_birth  DATE,
  gender         VARCHAR(30),
  address        TEXT,
  contact_number VARCHAR(20),
  program        VARCHAR(150)
);

CREATE TABLE enrollments (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  enrollment_id   VARCHAR(30) NOT NULL UNIQUE,
  student_id      VARCHAR(30) REFERENCES students(student_id),
  course_code     VARCHAR(20) REFERENCES courses(course_code),
  enrollment_date DATE NOT NULL,
  status          ENUM('Active','Completed','Withdrawn') DEFAULT 'Active'
);

CREATE TABLE grades (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  enrollment_id VARCHAR(30) REFERENCES enrollments(enrollment_id),
  course_code   VARCHAR(20) NOT NULL,
  student_id    VARCHAR(30) NOT NULL,
  grade         VARCHAR(5),
  remarks       TEXT,
  UNIQUE KEY uq_grade (enrollment_id, course_code)
);

-- Seed data
INSERT INTO departments (name, head_of_department) VALUES
  ('Computer Science','Dr. Maria Santos'),
  ('Business Administration','Dr. Jose Reyes'),
  ('Mathematics','Dr. Ana Garcia');

INSERT INTO classrooms (location, capacity, type) VALUES
  ('Lab 101', 40, 'Lab'), ('Lab 102', 40, 'Lab'),
  ('Room 204', 50, 'Lecture'), ('Room 205', 50, 'Lecture'),
  ('Room 301', 45, 'Lecture'), ('Room 302', 45, 'Lecture');

INSERT INTO courses (course_code, course_title, credit_units, department_id, semester) VALUES
  ('CS101','Introduction to Programming',3,1,'Semester 1 2025'),
  ('CS201','Data Structures & Algorithms',3,1,'Semester 1 2025'),
  ('BUS201','Principles of Management',3,2,'Semester 1 2025'),
  ('BUS102','Financial Accounting',3,2,'Semester 1 2025'),
  ('MATH101','Calculus I',4,3,'Semester 1 2025'),
  ('MATH202','Statistics & Probability',3,3,'Semester 1 2025');
*/


// ============================================================
// .env file template  —  create this as ".env" in project root
// ============================================================
/*
PORT=3000
DB_HOST=localhost
DB_USER=root
DB_PASS=your_mysql_password
DB_NAME=eduprime
JWT_SECRET=replace_this_with_a_long_random_string
*/


// ============================================================
// PACKAGE.JSON — run: npm init -y && npm install express mysql2 bcryptjs jsonwebtoken cors dotenv
// ============================================================
/*
{
  "name": "eduprime-api",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "bcryptjs": "^2.4.3",
    "cors": "^2.8.5",
    "dotenv": "^16.0.3",
    "express": "^4.18.2",
    "jsonwebtoken": "^9.0.0",
    "mysql2": "^3.6.0"
  }
}
*/
