require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const axios = require('axios');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const saltRounds = 10;
const SECRET_KEY = process.env.JWT_SECRET || "your_secret_key";

// ✅ FIX: Use MySQL Pool instead of single connection
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ✅ You can remove db.connect() entirely — pools connect automatically

// 🛡 JWT Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) return res.status(401).json({ error: "Unauthorized: No token provided" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Forbidden: Invalid token" });
        req.user = user;
        next();
    });
};

// 🔐 Register
app.post('/register', async (req, res) => {
    const { email, password, name, rank, department, badge_number } = req.body;

    console.log("📥 Incoming registration data:", req.body);

    if (!email || !password || !name || !badge_number) {
        console.log("❌ Missing required fields");
        return res.status(400).json({ error: "All required fields must be filled" });
    }

    try {
        console.log("🔍 Checking if user already exists...");
        const [existingUser] = await db.promise().query(
            'SELECT * FROM users WHERE email = ? OR badge_number = ?', 
            [email, badge_number]
        );

        console.log("✅ User existence check complete");

        if (existingUser.length > 0) {
            console.log("⚠️ Email or Badge Number already exists");
            return res.status(400).json({ error: "Email or Badge Number already exists" });
        }

        console.log("🔐 Hashing password...");
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        console.log("✅ Password hashed");

        console.log("📤 Inserting user into DB...");
        const [insertResult] = await db.promise().query(
            'INSERT INTO users (email, password, name, `rank`, department, badge_number) VALUES (?, ?, ?, ?, ?, ?)',
            [email, hashedPassword, name, rank, department, badge_number]
        );

        console.log("✅ Insert success:", insertResult);

        res.status(201).json({ message: "User registered successfully" });

    } catch (error) {
        console.error("❌ Error registering user:", error.message);
        res.status(500).json({ error: error.message || "Internal Server Error" });
    }
});


// 🔐 Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required" });
    }

    try {
        const [user] = await db.promise().query(
            'SELECT * FROM users WHERE email = ?', 
            [email]
        );

        if (user.length === 0) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        const validPassword = await bcrypt.compare(password, user[0].password);
        if (!validPassword) {
            return res.status(401).json({ error: "Invalid email or password" });
        }

        const token = jwt.sign(
            { id: user[0].id, email: user[0].email, name: user[0].name, rank: user[0].rank }, 
            SECRET_KEY, 
            { expiresIn: "168h" }
        );

        res.json({ message: "Login successful", token, user: user[0] });

    } catch (error) {
        console.error("Error logging in:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// 🚓 Car Details (Protected Route)
app.get('/cars/:plate', authenticateToken, async (req, res) => {
    const plate = req.params.plate;
    console.log("🔍 Looking up car:", plate);

    try {
        const [carResults] = await db.promise().query(
            'SELECT * FROM cars WHERE license_plate = ?',
            [plate]
        );

        if (carResults.length === 0) {
            console.log("🚫 Car not found in DB");
            return res.status(404).json({ message: "Car not found" });
        }

        console.log("✅ Car data from DB:", carResults[0]);

        const insuranceUrl = `${process.env.INSURANCE_API_BASE_URL}/api/insurance/${plate}`;
        console.log("📡 Fetching insurance data from:", insuranceUrl);

        const insuranceResponse = await axios.get(insuranceUrl);

        console.log("✅ Insurance data:", insuranceResponse.data);

        const carData = { 
            ...carResults[0], 
            insurance_start: insuranceResponse.data.insurance_start,
            insurance_end: insuranceResponse.data.insurance_end
        };

        res.json(carData);

    } catch (error) {
        console.error("❌ Error fetching data:", error.message);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

// Start server
const PORT = 5004;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});
