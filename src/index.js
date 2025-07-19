require("dotenv").config();
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const pool = require("./config/database");
const authRoutes = require("./routes/authRoutes");

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

// Cek API root
app.get("/", (req, res) => {
  res.json({ message: "Welcome to the API GIS!" });
});

// Cek db
app.get("/check-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");
    res.json({
      status: "success",
      message: "Koneksi database berhasil.",
      server_time: result.rows[0].now,
    });
  } catch (error) {
    console.error("DB Connection Error:", error.message);
    res.status(500).json({
      status: "error",
      message: "Gagal terhubung ke database.",
      error: error.message,
    });
  }
});

// Route API
app.use("/api", authRoutes);

// Jalankan server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});
