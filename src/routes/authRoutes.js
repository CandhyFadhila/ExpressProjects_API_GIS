const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const { loginValidator } = require("../validators/loginValidator");
const authMiddleware = require("../middlewares/authMiddleware");
const customThrottle = require("../middlewares/rateLimitMiddleware");

// Auth
router.post("/signin", loginValidator, authController.login);


router.get("/user-info", authMiddleware, authController.getUserInfo);
router.get("/signout", authMiddleware, authController.logout);

module.exports = router;
