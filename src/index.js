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

// Route API
app.use("/api", authRoutes);

// Jalankan server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});
