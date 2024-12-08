const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const { Pool } = require('pg');

// Middleware
app.use(cors());
app.use(bodyParser.json());

// In-memory "database" (for demo purposes)
const users = [];  // In a real-world app, use a real database
const pool =new Pool({connectionString: process.env.DATABASE_URL});
async ()=>{
    const client = await pool.connect();
    try{
        console.log("Connected to database");
        // await client.query('CREATE TABLE IF NOT EXISTS users(id SERIAL PRIMARY KEY, username VARCHAR(50) NOT NULL, password VARCHAR(100) NOT NULL)');

    }catch(e){
        console.log(e);}
        finally{
            client.release();
        }
}();

// Secret key for signing JWTs
const SECRET_KEY = 'd69314ce54853684be04a1bd2b8e7b0bb5fd2684d99d23fc0272604e0388a878141f0b914d464e13c08d224b1a5ad7a06befaa1545aa6d7e0875ef9c1dcd918f';

// Endpoint to register a new user
app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Check if user already exists
  const userExists = users.find(user => user.username === username);
  if (userExists) {
    return res.status(400).json({ message: 'User already exists' });
  }

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10);

  // Store user data (in memory, for now)
  users.push({ username, password: hashedPassword });

  res.status(201).json({ message: 'User registered successfully' });
});

// Endpoint to login and get JWT
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Find user by username
  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  // Compare password with hashed password
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return res.status(400).json({ message: 'Invalid username or password' });
  }

  // Create JWT token
  const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });

  res.json({ token });
});

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];  // Get token from Authorization header
  if (!token) return res.status(401).json({ message: 'Access denied' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = decoded;  // Store user info from decoded token
    next();
  });
};

// Protected route: Only accessible with a valid JWT
app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected profile', user: req.user });
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
