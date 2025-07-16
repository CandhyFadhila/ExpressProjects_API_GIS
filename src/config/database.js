// src/config/database.js
const { Pool } = require("pg");

// Setup koneksi database PostgreSQL
const pool = new Pool({
  user: "postgres", // Username database
  host: "localhost", // Server database
  database: "bpn-gis", // Nama database
  password: "super.admin", // Password PostgreSQL
  port: 5433, // Port default PostgreSQL
});

// Export koneksi untuk digunakan di file lain
module.exports = pool;
