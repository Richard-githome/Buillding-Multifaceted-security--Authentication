////////////////// - Everthing on required dependencies and their connections - ///////////////
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const _ = require("lodash");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");
const PORT = process.env.PORT || 3000;

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

///////////////////////////////////// - Everthing on Database - //////////////////////
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true });
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_APP_ID,
      clientSecret: process.env.GOOGLE_APP_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK,
      userProfileUrl: process.env.GOOGLE_USERPROFILE,
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK,
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate(
        { username: profile.displayName, facebookId: profile.id },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);

///////////////////////////////////// - Everthing on Get & Post - //////////////////////
app.get("/", (req, res) => {
  res.render("home");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get(
  "/auth/facebook",
  passport.authenticate("facebook", { scope: ["public_profile"] })
);

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get("/secrets", (req, res) => {
  res.set(
    "Cache-Control",
    "no-cache, private, no-store, must-revalidate, max-stal e=0, post-check=0, pre-check=0"
  );
  User.find({ secret: { $ne: null } })
    .then((foundSecretUsers) => {
      res.render("secrets", { allSecretUsers: foundSecretUsers });
    })
    .catch((err) => {
      console.log(err);
    });
});

app
  .route("/register")
  .get((req, res) => {
    res.render("register");
  })
  .post((req, res) => {
    User.register({ username: req.body.username }, req.body.password)
      .then((user) => {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      })
      .catch((err) => {
        console.log(err);
      });
  });

app
  .route("/submit")
  .get((req, res) => {
    if (req.isAuthenticated()) {
      res.render("submit");
    } else {
      res.redirect("/login");
    }
  })
  .post((req, res) => {
    const userSubmittedSecret = req.body.secret;
    User.findById(req.user._id).then((foundUser) => {
      foundUser.secret = req.body.secret;
      setTimeout(() => {
        foundUser.save().then(res.redirect("/secrets"));
      }, 100);
    });
  });

app
  .route("/login")
  .get((req, res) => {
    res.render("login");
  })
  .post((req, res) => {
    passport.authenticate("local")(req, res, () => {
      const user = new User({
        username: req.body.username,
        password: req.body.password,
      });
      req.login(user, (err) => {
        if (err) {
          console.log(err);
          res.redirect("/login");
        } else {
          res.redirect("/secrets");
        }
      });
    });
  });

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (!err) {
      res.redirect("/");
    }
  });
});

///////////////////////////////////// - Everthing on listening - //////////////////////
app.listen(PORT, () => {
  console.log(`Successfully listening @ ${PORT}`);
});
