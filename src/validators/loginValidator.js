const { body } = require("express-validator");

exports.loginValidator = [
  body("email").isEmail().withMessage("Silahkan masukkan email yang valid."),
  body("password")
    .isLength({ min: 4 })
    .withMessage("Password minimum 4 karakter."),
];
