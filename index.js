const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

dotenv.config();
const app = express();
app.use(bodyParser.json());

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
});

db.connect(err => {
    if (err) {
        console.error('Database connection error:', err);
    } else {
        console.log('Database connected.');
    }
});

app.listen(8000, () => {
    console.log('Server running on port 8000');
});

// Middleware
function verifyToken(req, res, next) {
    const token = req.header("Authorization");
    if (!token) {
        return res.status(403).json({
            status: "error",
            message: "Token tidak ditemukan, akses ditolak!",
        });
    }

    const tokenWithoutBearer = token.split(" ")[1];
    jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({
                status: "error",
                message: "Token tidak valid!",
            });
        }

        req.user = decoded;
        next();
    });
}

function isKaryawan(req, res, next) {
    if (req.user.role !== 'karyawan') {
        return res.status(403).json({
            status: "error",
            message: "Akses ditolak! Hanya karyawan yang dapat mengakses rute ini.",
        });
    }
    next();
}

// LOGIN
app.post("/api/auth/login", (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({
            status: "error",
            message: "Username dan password wajib diisi!",
        });
    }

    const query = "SELECT id, name, username, password, role FROM users WHERE username = ?";
    db.query(query, [username], (err, results) => {
        if (err) return res.status(500).json({ status: "error", message: "Gagal melakukan login." });
        if (results.length === 0) {
            return res.status(404).json({ status: "error", message: "Username tidak ditemukan." });
        }

        const user = results[0];
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err || !isMatch) {
                return res.status(401).json({ status: "error", message: "Password salah." });
            }

            const token = jwt.sign(
                { id: user.id, username: user.username, role: user.role },
                process.env.JWT_SECRET,
                { expiresIn: '3h' }
            );

            res.status(200).json({ status: "success", message: "Login berhasil", token });
        });
    });
});

// CRUD USERS (Khusus Karyawan)
app.get('/api/users/:id', verifyToken, isKaryawan, (req, res) => {
    const { id } = req.params;
    const query = 'SELECT id, name, username, role FROM users WHERE id = ?';
    db.query(query, [id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(
            {
                status: "success",
                data: results[0]
            }

        );
    });
});

app.post('/api/users', verifyToken, isKaryawan, (req, res) => {
    const { username, name, email, password, role } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    const query = 'INSERT INTO users (username, name, email, password, role) VALUES (?, ?, ?, ?, ?)';
    db.query(query, [username, name, email, hashedPassword, role], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ status: "success", message: "Pengguna berhasil ditambahkan", data: { id: results.insertId, name, username, role } });
    });
});

app.put('/api/users/:id', verifyToken, isKaryawan, (req, res) => {
    const { id } = req.params;
    const { name, email, role, username } = req.body;
    const query = 'UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?';
    db.query(query, [name, email, role, id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ status: "success", message: "Pengguna berhasil diubah", data: { id, name, username, role } });
    });
});

app.delete('/api/users/:id', verifyToken, isKaryawan, (req, res) => {
    const { id } = req.params;
    const query = 'DELETE FROM users WHERE id = ?';
    db.query(query, [id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.affectedRows === 0) return res.status(404).json({ status: "error", message: "User tidak ditemukan" });
        res.json({ status: "success", message: "Pengguna berhasil dihapus" });
    });
});

app.get('/api/attendance/history/:user_id', verifyToken, (req, res) => {
    const { user_id } = req.params;
    const query = `
        SELECT 
            id AS id, 
            DATE_FORMAT(attendance_date, '%Y-%m-%d') AS attendance_date, 
            attendace_time, 
            status 
        FROM attendance 
        WHERE user_id = ? 
        ORDER BY attendance_date DESC
    `;
    db.query(query, [user_id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});



// ATTENDANCE SUMMARY
app.get('/api/attendance/summary/:user_id', verifyToken, (req, res) => {
    const { user_id } = req.params;
    const { month, year } = req.query;

    if (!month || !year) {
        return res.status(400).json({
            status: "error",
            message: "Month and year are required in query parameters."
        });
    }

    const query = `
        SELECT 
            u.name AS user_name,
            SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) AS hadir,
            SUM(CASE WHEN a.status = 'absent' THEN 1 ELSE 0 END) AS alpa
        FROM users u
        LEFT JOIN attendance a ON u.id = a.user_id
        WHERE u.id = ? AND MONTH(a.attendance_date) = ? AND YEAR(a.attendance_date) = ?
        GROUP BY u.id
    `;

    db.query(query, [user_id, month, year], (err, results) => {
        if (err) {
            console.log(err);
            return res.status(500).json({
                status: "error",
                message: "Gagal mengambil rekap kehadiran."
            });
        }

        if (results.length === 0) {
            return res.status(404).json({
                status: "error",
                message: "Tidak ada data kehadiran."
            });
        }

        const result = results[0];
        const attendanceSummary = {
            hadir: result.hadir || 0,
            izin: 0, // Tambahkan nilai default jika tidak ada data izin
            sakit: 0, // Tambahkan nilai default jika tidak ada data sakit
            alpa: result.alpa || 0
        };

        return res.status(200).json({
            status: "success",
            data: {
                user_id: user_id,
                month: `${month}-${year}`, // Format bulan dan tahun seperti pada code 2
                attendance_summary: attendanceSummary
            }
        });
    });
});



// ATTENDANCE HISTORY

app.get('/api/attendance/history/:user_id', (req, res) => {
    const { user_id } = req.params;
    
    const query = 'SELECT attendance_date, status FROM attendance WHERE user_id = ? ORDER BY attendance_date DESC';

    db.query(query, [user_id], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) {
            return res.status(404).json({ message: 'No attendance history found for this user.' });
        }

        res.json(results);
    });
});

// ATTENDANCE RECORD

app.post('/api/attendance', (req, res) => {
    const { user_id, attendance_date, attendance_time, status } = req.body;

    if (!user_id || !attendance_date || !attendance_time || !status) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const query = 'INSERT INTO attendance (user_id, attendance_date, attendace_time, status) VALUES (?, ?, ?, ?)';
    db.query(query, [user_id, attendance_date, attendance_time, status], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ message: 'Attendance recorded successfully' });
    });
});

app.post("/api/attendance/analysis", verifyToken, (req, res) => {
    const { start_date, end_date, group_by } = req.body;

    // Validasi parameter start_date dan end_date
    if (!start_date || !end_date) {
        return res.status(400).json({
            status: "error",
            message: "Parameter start_date dan end_date diperlukan.",
        });
    }

    // Validasi parameter group_by, hanya boleh 'siswa' atau 'karyawan'
    if (!group_by || !["siswa", "karyawan"].includes(group_by)) {
        return res.status(400).json({
            status: "error",
            message: "Parameter group_by tidak valid. Gunakan 'siswa' atau 'karyawan'.",
        });
    }

    // Query dinamis untuk memilih berdasarkan role 'siswa' atau 'karyawan'
    const query = `
        SELECT 
            users.role AS group_key, 
            attendance.status AS status, 
            COUNT(attendance.status) AS count,
            COUNT(DISTINCT users.id) AS total_users
        FROM 
            attendance
        INNER JOIN 
            users 
        ON 
            attendance.user_id = users.id
        WHERE 
            attendance.attendance_date BETWEEN ? AND ? 
            AND users.role = ?
        GROUP BY 
            users.role, 
            attendance.status
    `;

    // Menjalankan query dengan filter berdasarkan role sesuai group_by
    db.query(query, [start_date, end_date, group_by], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({
                status: "error",
                message: "Terjadi kesalahan pada server.",
            });
        }

        // Proses hasil query
        const groupedAnalysis = {};
        results.forEach((row) => {
            const group = row.group_key || "Unspecified";
            const status = row.status.toLowerCase();

            if (!groupedAnalysis[group]) {
                groupedAnalysis[group] = {
                    group,
                    total_users: row.total_users || 0,  // Total pengguna dalam grup
                    total_attendance: {
                        present: 0,
                        absent: 0,
                        sick: 0,
                        alpa: 0,
                    },
                    attendance_rate: {
                        present_percentage: 0,
                        absent_percentage: 0,
                        sick_percentage: 0,
                        alpa_percentage: 0,
                    },
                };
            }

            // Menambahkan jumlah kehadiran sesuai status
            if (status === "present") {
                groupedAnalysis[group].total_attendance.present += row.count || 0;
            } else if (status === "absent") {
                groupedAnalysis[group].total_attendance.absent += row.count || 0;
            } else if (status === "sick") {
                groupedAnalysis[group].total_attendance.sick += row.count || 0;
            } else if (status === "alpa") {
                groupedAnalysis[group].total_attendance.alpa += row.count || 0;
            }
        });

        // Hitung persentase kehadiran untuk setiap grup
        Object.values(groupedAnalysis).forEach((group) => {
            const total = Object.values(group.total_attendance).reduce((sum, val) => sum + val, 0);

            if (total > 0) {
                group.attendance_rate.present_percentage =
                    ((group.total_attendance.present || 0) / total) * 100;
                group.attendance_rate.absent_percentage =
                    ((group.total_attendance.absent || 0) / total) * 100;
                group.attendance_rate.sick_percentage =
                    ((group.total_attendance.sick || 0) / total) * 100;
                group.attendance_rate.alpa_percentage =
                    ((group.total_attendance.alpa || 0) / total) * 100;
            }
        });

        return res.status(200).json({
            status: "success",
            data: {
                analysis_period: {
                    start_date,
                    end_date,
                },
                grouped_analysis: Object.values(groupedAnalysis),
            },
        });
    });
});



// const express = require('express');
// const bodyParser = require('body-parser');
// const mysql = require('mysql2');
// const dotenv = require('dotenv');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcrypt');
// // const { verifyToken, isKaryawan, isSiswa } = require('./middleware/authMiddleware'); 


// dotenv.config();
// const app = express();
// app.use(bodyParser.json());

// const db = mysql.createConnection({
//     host: process.env.DB_HOST,
//     user: process.env.DB_USER,
//     password: process.env.DB_PASS,
//     database: process.env.DB_NAME,
// });

// db.connect(err => {
//     if (err) {
//         console.error('Database connection error:', err);
//     } else {
//         console.log('Database connected.');
//     }
// });

// app.listen(8000, () => {
//     console.log('Server running on port 8000');
// });

// app.post("/api/auth/login", (req, res) => {
//     const { username, password } = req.body;

//     // Validasi input
//     if (!username || !password) {
//         return res.status(400).json({
//             status: "error",
//             message: "Username dan password wajib diisi!"
//         });
//     }

//     // Cek apakah username ada di database
//     const query = "SELECT id, name, username, password, role FROM users WHERE username = ?";
//     db.query(query, [username], (err, results) => {
//         if (err) {
//             console.log(err);
//             return res.status(500).json({
//                 status: "error",
//                 message: "Gagal melakukan login."
//             });
//         }

//         if (results.length === 0) {
//             return res.status(404).json({
//                 status: "error",
//                 message: "Username tidak ditemukan."
//             });
//         }

//         // Verifikasi password menggunakan bcrypt
//         const user = results[0];
//         bcrypt.compare(password, user.password, (err, isMatch) => {
//             if (err) {
//                 return res.status(500).json({
//                     status: "error",
//                     message: "Terjadi kesalahan saat memverifikasi password."
//                 });
//             }

//             if (!isMatch) {
//                 return res.status(401).json({
//                     status: "error",
//                     message: "Password salah."
//                 });
//             }

//             // Buat token JWT
//             const token = jwt.sign(
//                 { id: user.id, username: user.username, role: user.role },  // Payload
//                 process.env.JWT_SECRET,  // Secret Key untuk enkripsi token
//                 { expiresIn: '3h' }  
//             );

//             return res.status(200).json({
//                 status: "success",
//                 message: "Login berhasil",
//                 token: token
//             });
//         });
//     });
// });

// // Middleware untuk memverifikasi token dan role
// function verifyToken(req, res, next) {
//     const token = req.header("Authorization");

//     if (!token) {
//         return res.status(403).json({
//             status: "error",
//             message: "Token tidak ditemukan, akses ditolak!"
//         });
//     }

//     // Menghilangkan "Bearer " dari token
//     const tokenWithoutBearer = token.split(" ")[1];

//     // Verifikasi token
//     jwt.verify(tokenWithoutBearer, process.env.JWT_SECRET, (err, decoded) => {
//         if (err) {
//             return res.status(403).json({
//                 status: "error",
//                 message: "Token tidak valid!"
//             });
//         }

//         // Menyimpan decoded payload ke req.user
//         req.user = decoded;

//         // Menambahkan cek role karyawan
//         if (req.user.role !== 'karyawan') {
//             return res.status(403).json({
//                 status: "error",
//                 message: "Akses ditolak! Hanya karyawan yang dapat mengakses rute ini."
//             });
//         }

        
//         next(); // Melanjutkan ke handler berikutnya
//     });
// }

// // LOGIN AUTHENTICATION -GAGAL

// // app.post('/api/auth/login', (req, res) => {
// //     const { email, password } = req.body;
// //     const query = 'SELECT * FROM users WHERE email = ?';

// //     db.query(query, [email], (err, results) => {
// //         if (err) return res.status(500).json({ error: err.message });
// //         if (results.length === 0) return res.status(404).json({ message: 'User not found', email: email });
// //         // debugging
// //         console.log('Received email:', email);
// //         console.log('Received password:', password);
// //         console.log('User found:', results[0]);
        

// //         const user = results[0];
// //         bcrypt.compare(password, user.password, (err, isMatch) => {
// //             if (err) return res.status(500).json({ error: err.message });
// //             if (!isMatch) return res.status(401).json({ message: 'Invalid credentials' });

// //             // Generate JWT token
// //             const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1d' });
// //             res.json({ token });
// //         });
// //     });
// // });




// // READ DATA USERS

// app.get('/api/users/:id',  (req, res) => {
//     const { id } = req.params;
//     console.log('Received ID:', id); 
//     const query = 'SELECT * FROM users WHERE id = ?';

//     db.query(query, [id], (err, results) => {
//         if (err) return res.status(500).json({ error: err.message });
//         res.json(results[0]);
//     });
// });


// // CREATE DATA USERS

// app.post('/api/users', (req, res) => {
//     const { username, name, email, password, role } = req.body;
//     const hashedPassword = bcrypt.hashSync(password, 10);
//     const insertQuery = 'INSERT INTO users (username, name, email, password, role) VALUES (?, ?, ?, ?, ?)';
    
//     db.query(insertQuery, [username, name, email, hashedPassword, role], (err, results) => {
//         if (err) return res.status(500).json({ error: err.message });
        
//         const userId = results.insertId; 
//         const selectQuery = 'SELECT id, username, name, role FROM users WHERE id = ?';

//         db.query(selectQuery, [userId], (err, userResults) => {
//             if (err) return res.status(500).json({ error: err.message });
            
//             const user = userResults[0];
//             return res.json({
//                 status: 'success',
//                 message: 'Pengguna berhasil ditambahkan',
//                 data: user,
//             });
//         });
//     });
// });


// // UPDATE DATA USERS

// app.put('/api/users/:id', (req, res) => {
//     const { id } = req.params;
//     const { name, email, role } = req.body;
//     const query = 'UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?';

//     db.query(query, [name, email, role, id], (err, results) => {
//         if (err) return res.status(500).json({ error: err.message });
//         res.json({ statis: 'success', message: 'Pengguna berhasil diubah', data: results });
//     });
// });


// // DELETE DATA USERS

// app.delete('/api/users/:id', (req, res) => {
//     const { id } = req.params;
//     const query = 'DELETE FROM users WHERE id = ?';

//     db.query(query, [id], (err, results) => {
//         if (err) return res.status(500).json({ error: err.message });
//         if (results.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
//         res.json({ status: 'success', message: 'Pengguna berhasil dihapus' });
//     });
// });


// // ATTENDANCE RECORD

// app.post('/api/attendance', (req, res) => {
//     const { user_id, attendance_date, attendance_time, status } = req.body;

//     if (!user_id || !attendance_date || !attendance_time || !status) {
//         return res.status(400).json({ error: 'All fields are required' });
//     }

//     const query = 'INSERT INTO attendance (user_id, attendance_date, attendace_time, status) VALUES (?, ?, ?, ?)';
//     db.query(query, [user_id, attendance_date, attendance_time, status], (err, results) => {
//         if (err) return res.status(500).json({ error: err.message });
//         res.status(201).json({ message: 'Attendance recorded successfully' });
//     });
// });


// // ATTENDANCE SUMMARY

// app.get('/api/attendance/summary/:user_id', verifyToken, (req, res) => {
//     const { user_id } = req.params;
//     const { month, year } = req.query;

//     if (!month || !year) {
//         return res.status(400).json({ error: 'Month and year are required in query parameters.' });
//     }

//     const query = `
//         SELECT 
//             u.name AS user_name,
//             SUM(CASE WHEN a.status = 'present' THEN 1 ELSE 0 END) AS total_present,
//             SUM(CASE WHEN a.status = 'absent' THEN 1 ELSE 0 END) AS total_absent
//         FROM users u
//         LEFT JOIN attendance a ON u.id = a.user_id
//         WHERE u.id = ? AND MONTH(a.attendance_date) = ? AND YEAR(a.attendance_date) = ?
//         GROUP BY u.id
//     `;

//     db.query(query, [user_id, month, year], (err, results) => {
//         if (err) return res.status(500).json({ error: err.message });
//         if (results.length === 0) {
//             return res.status(404).json({ message: 'No attendance data found for this user in the given period.' });
//         }

//         res.json(results[0]);
//     });
// });


// // ATTENDANCE HISTORY

// app.get('/api/attendance/history/:user_id', (req, res) => {
//     const { user_id } = req.params;
    
//     const query = 'SELECT attendance_date, status FROM attendance WHERE user_id = ? ORDER BY attendance_date DESC';

//     db.query(query, [user_id], (err, results) => {
//         if (err) return res.status(500).json({ error: err.message });
//         if (results.length === 0) {
//             return res.status(404).json({ message: 'No attendance history found for this user.' });
//         }

//         res.json(results);
//     });
// });
