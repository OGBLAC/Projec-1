// Load environment variables
require('dotenv').config();

const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();

// =====================
// Middleware
// =====================
app.use(cors({
  origin: '*', // allow all for now
  credentials: true
}));
app.use(express.json());

// =====================
// Environment variables
// =====================
const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET || 'default-secret';

// =====================
// MySQL Pool
// =====================
let pool;

async function createConnection() {
  try {
    if (!DATABASE_URL) {
      throw new Error('DATABASE_URL is not defined');
    }

    const url = new URL(DATABASE_URL);

    pool = mysql.createPool({
      host: url.hostname,
      port: url.port || 3306,
      user: url.username,
      password: url.password,
      database: url.pathname.replace('/', ''),
      waitForConnections: true,
      connectionLimit: 10,
      connectTimeout: 10000
    });

    console.log('✅ MySQL pool created');
  } catch (error) {
    console.error('❌ MySQL connection error:', error.message);
    process.exit(1);
  }
}

// =====================
// Initialize Database
// =====================
async function initDB() {
  try {
    const connection = await pool.getConnection();

    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    connection.release();
    console.log('✅ Database initialized');
  } catch (error) {
    console.error('❌ DB init error:', error.message);
  }
}

// =====================
// Routes
// =====================
app.get('/', (req, res) => {
  res.json({
    message: 'Auth API running',
    status: 'ok',
    time: new Date().toISOString()
  });
});

app.get('/health', async (req, res) => {
  try {
    const connection = await pool.getConnection();
    connection.release();

    res.json({
      status: 'healthy',
      database: 'connected'
    });
  } catch {
    res.status(500).json({
      status: 'unhealthy',
      database: 'not connected'
    });
  }
});

// =====================
// Register
// =====================
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const connection = await pool.getConnection();

    const [result] = await connection.query(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );

    connection.release();

    const token = jwt.sign(
      { userId: result.insertId, username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: result.insertId,
        username
      }
    });

  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ error: 'Username already exists' });
    } else {
      console.error('Register error:', error.message);
      res.status(500).json({ error: 'Registration failed' });
    }
  }
});

// =====================
// Login
// =====================
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }

    const connection = await pool.getConnection();
    const [rows] = await connection.query(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );
    connection.release();

    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username
      }
    });

  } catch (error) {
    console.error('Login error:', error.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// =====================
// Start Server
// =====================
async function startServer() {
  await createConnection();
  await initDB();

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });
}

startServer();
