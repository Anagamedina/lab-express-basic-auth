const express = require("express");
const router = express.Router();

const bcrypt = require("bcryptjs");
const saltRounds = 10;

const User = require("../models/User.model");

router.get("/signup", (req, res, next) => {
  res.render("users/signup");
});

router.post("/signup", (req, res, next) => {
  let { username, password, passwordRepeat } = req.body;

  if (username == "" || password == "" || passwordRepeat == "") {
    res.render("users/signup", {
      errorMessage: "Por favor rellene todos los campos.",
    });
    return;
  }

  if (password != passwordRepeat) {
    res.render("users/signup", {
      errorMessage: "Las contraseñas no coinciden.",
    });
    return;
  }

  User.find({ username })
    .then((result) => {
      if (result.length != 0) {
        res.render("users/signup", {
          errorMessage:
            "El usuario ya existe, por favor elija otro. Saluda a tu hermana.",
        });
        return;
      }

      let salt = bcrypt.genSaltSync(saltRounds);
      let passwordEncriptada = bcrypt.hashSync(password, salt);

      User.create({
        username,
        password: passwordEncriptada,
      })
        .then(() => {
          res.redirect("/user/login");
        })
        .catch((err) => next(err));
    })
    .catch((err) => next(err));
});

router.get("/login", (req, res, next) => {
  res.render("users/login");
});

let isLoggedOut = (req, res, next) => {
  if (!req.session.currentUser) {
    next();
  } else {
    res.redirect("/user/profile");
  }
};

router.post("/login", isLoggedOut, (req, res, next) => {
  let { username, password } = req.body;

  if (username == "" || password == "") {
    res.render("users/login", { errorMessage: "Faltan campos por rellenar." });
  }

  User.find({ username })
    .then((result) => {
      if (result.length == 0) {
        res.render("users/login", {
          errorMessage: "El usuario no existe, por favor regístrate.",
        });
      }
      console.log(result);
      if (bcrypt.compareSync(password, result[0].password)) {
        let usuario = {
          username: result[0].username,
          isAdmin: result[0].isAdmin,
        };

        req.session.currentUser = usuario;
        console.log("req.session.currentUser: ", req.session.currentUser);
        res.redirect("/user/profile");
      } else {
        res.render("users/login", {
          errorMessage: "Credenciales incorrectas.",
        });
      }
    })
    .catch((err) => next(err));
});
router.get("/profile", (req, res, next) => {
  let user = req.session.currentUser
  res.render("users/profile", {user:user});
});
 
module.exports = router;
