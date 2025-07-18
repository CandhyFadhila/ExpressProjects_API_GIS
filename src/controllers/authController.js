const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { blacklistToken } = require("../utils/tokenBlacklist");
const { validationResult } = require("express-validator");
const logger = require("../utils/logger");
const pool = require("../config/database");
const redisClient = require("../config/redisClient");
const WithDataResource = require("../resources/WithDataResource");
const WithoutDataResource = require("../resources/WithoutDataResource");
const renderEmailTemplate = require("../utils/emailOTP/renderEmailTemplate");

// ========== LOGIN CONTROLLER ==========
exports.login = async (req, res) => {
  // Validasi input
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const response = new WithoutDataResource(
      400, // HTTP Status Code: Bad Request
      "VALIDATION_FAILED",
      "Login Gagal.",
      "Tolong periksa kembali input anda. Pastikan email dan password terisi dengan benar."
    );
    return res.status(400).json(response.toResponse());
  }

  const { email, password } = req.body;

  try {
    // Cek user berdasarkan email
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const user = result.rows[0];

    if (!user) {
      logger.info(
        `| Login | - Invalid credentials for email: ${email}, at ${new Date().toISOString()}`
      );
      const response = new WithoutDataResource(
        400, // HTTP Status Code: Bad Request
        "INVALID_CREDENTIALS",
        "Login Gagal.",
        "Password atau email yang anda masukkan tidak valid, silahkan periksa kembali dan pastikan akun anda sudah terdaftar."
      );
      return res.status(400).json(response.toResponse());
    }

    // Verifikasi password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logger.info(
        `| Login | - Invalid credentials for email: ${email}, at ${new Date().toISOString()}`
      );
      const response = new WithoutDataResource(
        400, // HTTP Status Code: Bad Request
        "INVALID_CREDENTIALS",
        "Login Gagal.",
        "Password atau email yang anda masukkan tidak valid, silahkan periksa kembali dan pastikan akun anda sudah terdaftar."
      );
      return res.status(400).json(response.toResponse());
    }

    // Update last_login
    await pool.query("UPDATE users SET last_login = NOW() WHERE id = $1", [
      user.id,
    ]);

    // Create JWT token
    const payload = { userId: user.id };
    const token = jwt.sign(payload, "secretkey", { expiresIn: "24h" });

    // Log successful login
    logger.info(
      `| Login | - Login success for email: ${email}, at ${new Date().toISOString()}`
    );

    // Filter user info (tidak mengirim password)
    const filteredUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      username: user.username,
      last_login: user.last_login,
    };

    const response = new WithDataResource(
      200, // HTTP Status Code: OK
      "LOGIN_SUCCESS",
      "Login Berhasil.",
      "Selamat datang, anda berhasil login.",
      { token, user: filteredUser }
    );
    res.status(200).json(response.toResponse());
  } catch (error) {
    logger.error(`| Login | - Server error: ${error.message}`, {
      stack: error.stack,
    });
    const response = new WithoutDataResource(
      500, // HTTP Status Code: Internal Server Error
      "SERVER_ERROR",
      "Login Gagal.",
      "Terjadi kesalahan di server. Silakan coba lagi nanti."
    );
    res.status(500).json(response.toResponse());
  }
};

// ========== GET USER INFO CONTROLLER ==========
exports.getUserInfo = async (req, res) => {
  const userId = req.userId; // Diperoleh dari middleware authMiddleware

  try {
    // Ambil data user dari database berdasarkan userId
    const userResult = await pool.query("SELECT * FROM users WHERE id = $1", [
      userId,
    ]);
    const user = userResult.rows[0];

    // Jika user tidak ditemukan
    if (!user) {
      const response = new WithoutDataResource(
        401, // HTTP Status Code: Unauthorized
        "ACCOUNT_NOT_FOUND",
        "Akses Ditolak",
        "Maaf, akun pengguna terkait tidak ditemukan."
      );
      logger.info(`| GetUserInfo | - Account not found for userId: ${userId}`);
      return res.status(401).json(response.toResponse());
    }

    // Sembunyikan atribut sensitif, seperti password
    const filteredUser = {
      id: user.id,
      name: user.name,
      email: user.email,
      username: user.username,
      last_login: user.last_login,
    };

    // Log info sukses
    logger.info(
      `| GetUserInfo | - User info fetched for userId: ${userId}, at ${new Date().toISOString()}`
    );

    // Response sukses dengan data pengguna
    const response = new WithDataResource(
      200, // HTTP Status Code: OK
      "SUCCESS_GET_USER_INFO",
      "Berhasil Mendapatkan Data",
      `Data pengguna ${user.name}, berhasil didapatkan.`,
      { user: filteredUser }
    );
    res.status(200).json(response.toResponse());
  } catch (error) {
    logger.error(
      `| GetUserInfo | - Server error for userId: ${userId}, error: ${error.message}`,
      { stack: error.stack }
    );
    const response = new WithoutDataResource(
      500, // HTTP Status Code: Internal Server Error
      "SERVER_ERROR",
      "Gagal Mendapatkan Data",
      "Terjadi kesalahan di server. Silakan coba lagi nanti."
    );
    res.status(500).json(response.toResponse());
  }
};

// ========== LOGOUT CONTROLLER ==========
exports.logout = async (req, res) => {
  const userId = req.userId; // Diperoleh dari middleware authMiddleware
  const token = req.header("Authorization")?.replace("Bearer ", "");

  try {
    // Pastikan userId tersedia
    if (!userId) {
      const response = new WithoutDataResource(
        401, // HTTP Status Code: Unauthorized
        "NO_ACTIVE_SESSION",
        "Logout Gagal",
        "Anda tidak memiliki sesi login yang aktif."
      );
      logger.info(`| Logout | - No active session for userId: ${userId}`);
      return res.status(401).json(response.toResponse());
    }

    // Ambil expiry token dari decode tanpa verify (karena sudah terverifikasi sebelumnya)
    const decoded = jwt.decode(token);
    const expiresIn = decoded.exp - Math.floor(Date.now() / 1000); // detik tersisa

    // Masukkan token ke blacklist Redis
    await blacklistToken(token, expiresIn);

    // Di sini kita hanya menunggu token dihapus di client-side (client akan menghapus token JWT mereka)
    logger.info(
      `| Logout | - Logout success for userId: ${userId}, at ${new Date().toISOString()}`
    );

    // Response sukses
    const response = new WithoutDataResource(
      200, // HTTP Status Code: OK
      "LOGOUT_SUCCESS",
      "Logout Berhasil",
      "Anda berhasil melakukan logout."
    );
    res.status(200).json(response.toResponse());
  } catch (error) {
    logger.error(
      `| Logout | - Server error for userId: ${userId}, error: ${error.message}`,
      { stack: error.stack }
    );
    const response = new WithoutDataResource(
      500, // HTTP Status Code: Internal Server Error
      "SERVER_ERROR",
      "Logout Gagal.",
      "Terjadi kesalahan di server. Silakan coba lagi nanti."
    );
    res.status(500).json(response.toResponse());
  }
};

// ========== SEND OTP CONTROLLER ==========
exports.sendOTP = async (req, res) => {
  const { email } = req.body;

  if (!email || !validator.isEmail(email)) {
    const response = new WithoutDataResource(
      400,
      "VALIDATION_FAILED",
      "Pengiriman OTP Gagal",
      "Email tidak valid atau kosong. Pastikan Anda mengisi email dengan benar."
    );
    return res.status(400).json(response.toResponse());
  }

  try {
    const result = await pool.query(
      "SELECT id, name FROM users WHERE email = $1",
      [email]
    );
    if (result.rows.length === 0) {
      const response = new WithoutDataResource(
        404,
        "DATA_NOT_FOUND",
        "Akun Tidak Ditemukan",
        `Akun dengan email '${email}' tidak ditemukan.`
      );
      return res.status(404).json(response.toResponse());
    }

    const user = result.rows[0];
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const key = `otp:${user.id}`;
    const hash = crypto.createHash("sha256").update(otp).digest("hex");

    await redisClient.setEx(key, 1800, hash); // expire in 30 minutes

    const htmlBody = renderEmailTemplate("otp.html", {
      name: user.name,
      otp: otp,
    });

    const transporter = nodemailer.createTransport({
      service: "Gmail",
      auth: {
        user: process.env.MAIL_USERNAME,
        pass: process.env.MAIL_PASSWORD,
      },
    });

    await transporter.sendMail({
      from: `"GIS" <${process.env.MAIL_USERNAME}>`,
      to: email,
      subject: "Verifikasi Kode OTP Perubahan Password",
      html: htmlBody,
    });

    logger.info(
      `| Send OTP | - OTP sent to ${email} at ${new Date().toISOString()}`
    );
    const response = new WithoutDataResource(
      200,
      "OTP_SENT",
      "Berhasil Mengirim Kode OTP",
      "Kode OTP berhasil dikirim. Silakan cek email Anda."
    );
    return res.status(200).json(response.toResponse());
  } catch (error) {
    logger.error(`| Send OTP | - Failed: ${error.message}`);
    const response = new WithoutDataResource(
      500,
      "OTP_SEND_FAILED",
      "Gagal Mengirim OTP",
      "Terjadi kesalahan saat mengirim OTP. Silakan coba lagi nanti."
    );
    return res.status(500).json(response.toResponse());
  }
};

// ========== VERIFY OTP CONTROLLER ==========
exports.verifyOTP = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const result = await pool.query(
      "SELECT id, email FROM users WHERE email = $1",
      [email]
    );

    if (result.rows.length === 0) {
      const response = new WithoutDataResource(
        404,
        "DATA_NOT_FOUND",
        "Akun Tidak Ditemukan",
        `Akun dengan email '${email}' tidak ditemukan.`
      );
      return res.status(404).json(response.toResponse());
    }

    const user = result.rows[0];
    const key = `otp:${user.id}`;
    const storedHashedOtp = await redisClient.get(key);

    if (!storedHashedOtp) {
      logger.info(`| Verify OTP | - OTP not found for user ${email}`);
      const response = new WithoutDataResource(
        400,
        "DATA_NOT_FOUND",
        "OTP Tidak Ditemukan",
        "Kode OTP tidak ditemukan atau sudah kadaluarsa. Silakan kirim ulang OTP."
      );
      return res.status(400).json(response.toResponse());
    }

    const hash = crypto.createHash("sha256").update(String(otp)).digest("hex");

    if (hash !== storedHashedOtp) {
      logger.info(`| Verify OTP | - Incorrect OTP for user ${email}`);
      const response = new WithoutDataResource(
        400,
        "INVALID_OTP",
        "OTP Tidak Valid",
        "Kode OTP yang anda masukkan tidak sesuai."
      );
      return res.status(400).json(response.toResponse());
    }

    logger.info(`| Verify OTP | - Success for user ${email}`);

    const response = new WithoutDataResource(
      200,
      "OTP_VERIFIED",
      "OTP Berhasil Diverifikasi",
      "Kode OTP anda berhasil diverifikasi. Silakan lanjutkan reset password."
    );
    return res.status(200).json(response.toResponse());
  } catch (error) {
    logger.error(`| Verify OTP | - Failed: ${error.message}`);
    const response = new WithoutDataResource(
      500,
      "VERIFY_FAILED",
      "Gagal Verifikasi OTP",
      "Terjadi kesalahan saat verifikasi OTP. Silakan coba lagi."
    );
    return res.status(500).json(response.toResponse());
  }
};

// ========== RESET PASSWORD CONTROLLER ==========
exports.resetPassword = async (req, res) => {
  const { email, otp, password } = req.body;

  try {
    // Cari user
    const result = await pool.query(
      "SELECT id, email FROM users WHERE email = $1",
      [email]
    );
    if (result.rows.length === 0) {
      const response = new WithoutDataResource(
        404,
        "DATA_NOT_FOUND",
        "Akun Tidak Ditemukan",
        `Akun dengan email '${email}' tidak ditemukan.`
      );
      return res.status(404).json(response.toResponse());
    }

    const user = result.rows[0];
    const key = `otp:${user.id}`;
    const storedHashedOtp = await redisClient.get(key);

    if (!storedHashedOtp) {
      const response = new WithoutDataResource(
        400,
        "OTP_NOT_FOUND",
        "OTP Tidak Ditemukan",
        "Kode OTP tidak ditemukan atau sudah kadaluarsa. Silakan kirim ulang OTP."
      );
      return res.status(400).json(response.toResponse());
    }

    const hashedInputOtp = crypto
      .createHash("sha256")
      .update(String(otp))
      .digest("hex");

    if (hashedInputOtp !== storedHashedOtp) {
      const response = new WithoutDataResource(
        401,
        "INVALID_OTP",
        "OTP Tidak Valid",
        "Kode OTP yang anda masukkan salah. Silakan coba lagi atau kirim ulang OTP."
      );
      return res.status(401).json(response.toResponse());
    }

    // Update password
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "UPDATE users SET password = $1, last_change_password = NOW() WHERE id = $2",
      [hashedPassword, user.id]
    );

    // Hapus OTP dari Redis
    await redisClient.del(key);

    logger.info(`| Reset Password | - Success for email: ${email}`);

    const response = new WithoutDataResource(
      200,
      "PASSWORD_RESET_SUCCESS",
      "Password Berhasil Diubah",
      "Password anda berhasil diubah. Silakan login menggunakan password baru anda."
    );
    return res.status(200).json(response.toResponse());
  } catch (error) {
    logger.error(`| Reset Password | - Failed: ${error.message}`);
    const response = new WithoutDataResource(
      500,
      "RESET_FAILED",
      "Gagal Reset Password",
      "Terjadi kesalahan saat reset password. Silakan coba lagi nanti."
    );
    return res.status(500).json(response.toResponse());
  }
};
