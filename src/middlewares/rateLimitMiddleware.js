const rateLimit = require("express-rate-limit");
const WithoutDataResource = require("../resources/WithoutDataResource");
const logger = require("../utils/logger");

// Middleware untuk membatasi request
const customThrottle = (maxAttempts = 5, decayMinutes = 1) => {
  const decaySeconds = decayMinutes * 60;

  // Rate limiter
  const limiter = rateLimit({
    windowMs: decaySeconds * 1000, // Waktu decay dalam milidetik (misal: 1 menit = 60 detik x 1000)
    max: maxAttempts, // Maksimum request yang diizinkan dalam window waktu

    message: (req) => {
      // Menentukan pesan saat terlalu banyak permintaan
      return new WithoutDataResource(
        429, // HTTP Status Code: Too Many Requests
        "TOO_MANY_REQUESTS",
        "Terlalu Banyak Permintaan",
        `Anda terlalu banyak melakukan permintaan, coba lagi setelah ${Math.ceil(
          decaySeconds / 60
        )} menit.`
      ).toResponse();
    },
    keyGenerator: (req) => {
      // Gunakan ID user atau IP untuk identifikasi pembatasan
      return req.user ? req.user.id : req.ip + "|" + req.originalUrl;
    },
    handler: (req, res) => {
      // Response ketika rate limit tercapai
      const response = new WithoutDataResource(
        429, // HTTP Status Code: Too Many Requests
        "TOO_MANY_REQUESTS",
        "Terlalu Banyak Permintaan",
        `Anda terlalu banyak melakukan permintaan, coba lagi setelah ${Math.ceil(
          decaySeconds / 60
        )} menit.`
      );
      logger.warn(
        `| RateLimiter | - Too many requests for user: ${
          req.ip
        }, at ${new Date().toISOString()}`
      );
      return res.status(429).json(response.toResponse());
    },
  });

  return limiter;
};

module.exports = customThrottle;
