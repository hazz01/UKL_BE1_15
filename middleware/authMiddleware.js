const jwt = require('jsonwebtoken');

// Middleware untuk verifikasi token
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ message: 'No token provided' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Failed to authenticate token' });
        }
        req.user = decoded; // Simpan decoded token untuk digunakan di route lainnya
        next();
    });
};

// Middleware untuk memeriksa apakah pengguna adalah karyawan
const isKaryawan = (req, res, next) => {
    if (req.user.role !== 'karyawan') {
        return res.status(403).json({ message: 'Access denied. Only employees can access this endpoint.' });
    }
    next();
};

// Middleware untuk memeriksa apakah pengguna adalah siswa
const isSiswa = (req, res, next) => {
    if (req.user.role !== 'siswa') {
        return res.status(403).json({ message: 'Access denied. Only students can access this endpoint.' });
    }
    next();
};

module.exports = { verifyToken, isKaryawan, isSiswa };
