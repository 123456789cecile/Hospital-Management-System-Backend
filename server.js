
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const pool = require("./db");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

app.use(cors());
app.use(express.json());

// ======================================
// HOME ROUTE
// GET /
// ======================================
app.get("/", (req, res) => {
    res.send("HBMS Backend API is running successfully!");
});

// ======================================
// ADMIN LOGIN
// POST /api/admin/login
// ======================================
app.post("/api/admin/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email?.trim() || !password) {
        return res.status(400).json({
            message: "Enter admin email and password."
        });
    }

    try {
        const [rows] = await pool.query(
            `SELECT user_id, full_name, email,
                    password_hash, role, is_active
             FROM users
             WHERE email = ?
             LIMIT 1`,
            [email.trim().toLowerCase()]
        );

        if (rows.length === 0) {
            return res.status(401).json({
                message: "Invalid admin email or password."
            });
        }

        const admin = rows[0];

        const matches = await bcrypt.compare(
            password,
            admin.password_hash
        );

        if (
            !matches ||
            admin.role !== "admin" ||
            !admin.is_active
        ) {
            return res.status(401).json({
                message: "Invalid admin credentials or inactive account."
            });
        }

        if (!process.env.JWT_SECRET) {
            return res.status(500).json({
                message: "JWT_SECRET is missing from .env."
            });
        }

        const token = jwt.sign(
            {
                user_id: admin.user_id,
                role: "admin"
            },
            process.env.JWT_SECRET,
            { expiresIn: "2h" }
        );

        return res.status(200).json({
            message: "Admin login successful.",
            token,
            user: {
                user_id: admin.user_id,
                full_name: admin.full_name,
                email: admin.email,
                role: admin.role
            }
        });

    } catch (error) {
        console.error("Admin login error:", error.message);

        return res.status(500).json({
            message: "Admin login failed."
        });
    }
});

// ======================================
// MIDDLEWARE: PROTECT ADMIN ROUTES
// ======================================
function verifyAdmin(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            message: "Please log in as admin first."
        });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        if (decoded.role !== "admin") {
            return res.status(403).json({
                message: "Admin access only."
            });
        }

        req.admin = decoded;
        next();

    } catch (error) {
        return res.status(401).json({
            message: "Admin session expired or token is invalid."
        });
    }
}

// ======================================
// HOSPITALS API
// ======================================

// 1. GET ALL HOSPITALS
// GET /api/hospitals
app.get("/api/hospitals", async (req, res) => {
    try {
        const [rows] = await pool.query(
            `SELECT hospital_id,
                    hospital_name AS name,
                    province, district, sector,
                    address, latitude, longitude, phone
             FROM hospitals
             ORDER BY hospital_name ASC`
        );

        return res.status(200).json(rows);

    } catch (error) {
        console.error("Get hospitals error:", error.message);

        return res.status(500).json({
            message: "Could not load hospitals."
        });
    }
});

// 2. GET ONE HOSPITAL
// GET /api/hospitals/1
app.get("/api/hospitals/:id", async (req, res) => {
    const hospitalId = Number(req.params.id);

    if (!Number.isInteger(hospitalId) || hospitalId <= 0) {
        return res.status(400).json({
            message: "Invalid hospital ID."
        });
    }

    try {
        const [rows] = await pool.query(
            `SELECT hospital_id,
                    hospital_name AS name,
                    province, district, sector,
                    address, latitude, longitude, phone
             FROM hospitals
             WHERE hospital_id = ?
             LIMIT 1`,
            [hospitalId]
        );

        if (rows.length === 0) {
            return res.status(404).json({
                message: "Hospital not found."
            });
        }

        return res.status(200).json(rows[0]);

    } catch (error) {
        console.error("Get hospital error:", error.message);

        return res.status(500).json({
            message: "Could not load hospital."
        });
    }
});

// 3. ADD HOSPITAL
// POST /api/admin/hospitals
app.post("/api/admin/hospitals", verifyAdmin, async (req, res) => {
    const {
        name, province, district, sector,
        address, latitude, longitude, phone
    } = req.body;

    if (!name?.trim() || !province?.trim() || !district?.trim()) {
        return res.status(400).json({
            message: "Hospital name, province and district are required."
        });
    }

    const parseCoordinate = (value, min, max, fieldName) => {
        if (value === undefined || value === null || value === "") {
            return null;
        }

        const number = Number(value);

        if (!Number.isFinite(number) || number < min || number > max) {
            throw new Error(`Invalid ${fieldName}.`);
        }

        return number;
    };

    let lat;
    let lng;

    try {
        lat = parseCoordinate(latitude, -90, 90, "latitude");
        lng = parseCoordinate(longitude, -180, 180, "longitude");
    } catch (error) {
        return res.status(400).json({
            message: error.message
        });
    }

    try {
        const [result] = await pool.query(
            `INSERT INTO hospitals
             (hospital_name, province, district, sector,
              address, latitude, longitude, phone)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
            [
                name.trim(),
                province.trim(),
                district.trim(),
                sector?.trim() || null,
                address?.trim() || null,
                lat,
                lng,
                phone?.trim() || null
            ]
        );

        return res.status(201).json({
            message: "Hospital added successfully.",
            hospital_id: result.insertId
        });

    } catch (error) {
        console.error("Add hospital error:", error.message);

        return res.status(500).json({
            message: "Could not add hospital."
        });
    }
});

// 4. UPDATE HOSPITAL
// PUT /api/admin/hospitals/1
app.put("/api/admin/hospitals/:id", verifyAdmin, async (req, res) => {
    const hospitalId = Number(req.params.id);

    if (!Number.isInteger(hospitalId) || hospitalId <= 0) {
        return res.status(400).json({
            message: "Invalid hospital ID."
        });
    }

    const {
        name, province, district, sector,
        address, latitude, longitude, phone
    } = req.body;

    if (!name?.trim() || !province?.trim() || !district?.trim()) {
        return res.status(400).json({
            message: "Hospital name, province and district are required."
        });
    }

    const parseCoordinate = (value, min, max, fieldName) => {
        if (value === undefined || value === null || value === "") {
            return null;
        }

        const number = Number(value);

        if (!Number.isFinite(number) || number < min || number > max) {
            throw new Error(`Invalid ${fieldName}.`);
        }

        return number;
    };

    let lat;
    let lng;

    try {
        lat = parseCoordinate(latitude, -90, 90, "latitude");
        lng = parseCoordinate(longitude, -180, 180, "longitude");
    } catch (error) {
        return res.status(400).json({
            message: error.message
        });
    }

    try {
        const [result] = await pool.query(
            `UPDATE hospitals SET
                hospital_name = ?,
                province = ?,
                district = ?,
                sector = ?,
                address = ?,
                latitude = ?,
                longitude = ?,
                phone = ?
             WHERE hospital_id = ?`,
            [
                name.trim(),
                province.trim(),
                district.trim(),
                sector?.trim() || null,
                address?.trim() || null,
                lat,
                lng,
                phone?.trim() || null,
                hospitalId
            ]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                message: "Hospital not found."
            });
        }

        return res.status(200).json({
            message: "Hospital updated successfully."
        });

    } catch (error) {
        console.error("Update hospital error:", error.message);

        return res.status(500).json({
            message: "Could not update hospital."
        });
    }
});

// 5. DELETE HOSPITAL
// DELETE /api/admin/hospitals/1
app.delete("/api/admin/hospitals/:id", verifyAdmin, async (req, res) => {
    const hospitalId = Number(req.params.id);

    if (!Number.isInteger(hospitalId) || hospitalId <= 0) {
        return res.status(400).json({
            message: "Invalid hospital ID."
        });
    }

    try {
        const [result] = await pool.query(
            "DELETE FROM hospitals WHERE hospital_id = ?",
            [hospitalId]
        );

        if (result.affectedRows === 0) {
            return res.status(404).json({
                message: "Hospital not found."
            });
        }

        return res.status(200).json({
            message: "Hospital deleted successfully."
        });

    } catch (error) {
        console.error("Delete hospital error:", error.message);

        return res.status(500).json({
            message: "Could not delete hospital."
        });
    }
});

// ======================================
// TEST DATABASE CONNECTION
// ======================================
async function testDatabase() {
    try {
        const connection = await pool.getConnection();

        console.log("MySQL connected successfully!");
        console.log("Database: hms");

        connection.release();

    } catch (error) {
        console.error("Database connection failed:", error.message);
    }
}

// ======================================
// START SERVER
// Keep this at the bottom
// ======================================
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
    testDatabase();
});
