require("dotenv").config();
const bcrypt = require("bcrypt");
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const Joi = require("joi");

const app = express();
const PORT = process.env.PORT || 3000;

const node_session_secret = process.env.NODE_SESSION_SECRET;
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const mongodb_users_database = process.env.MONGODB_USERS_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;

const { database } = require("./databaseConnection.js");
const userCollection = database.db(mongodb_users_database).collection("users");

const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`;
const expireTime = 60 * 60; // 1 hour

const mongoStore = MongoStore.create({
  mongoUrl: atlasURI,
  crypto: { secret: mongodb_session_secret },
  dbName: mongodb_session_database,
  ttl: expireTime,
});

const schema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),

  password: Joi.string().pattern(new RegExp("^[a-zA-Z0-9]{3,30}$")),

  email: Joi.string().email({
    minDomainSegments: 2,
    tlds: { allow: ["com", "net"] },
  }),
});

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  }),
);

/** GET **/

app.get("/", async (req, res) => {
  const loggedIn = req.session.loggedIn;

  const data = {
    displayNotLoggedIn: !loggedIn ? "flex" : "none",
    displayLoggedIn: loggedIn ? "flex" : "none",
    username: req.session.username
  };

  res.render("index", data);
});

app.get("/login", (req, res) => {
  const data = {
    displayLogin: "flex",
    displaySignup: "none",
  };
  res.render("login", data);
});

app.get("/signup", (req, res) => {
  const data = {
    displayLogin: "none",
    displaySignup: "flex",
  };

  res.render("login", data);
});

app.get("/features", (req, res) => {
  res.render("features");
});

app.get("/pricing", (req, res) => {
  res.render("pricing");
});

app.get("/FAQ", (req, res) => {
  res.render("faq");
});

app.get("/about", (req, res) => {
  res.render("about");
});

app.get("/admin", async (req, res) => {
  if (!req.session.loggedIn) {
    return res.redirect("/login");
  }

  const username = req.session.username;
  const user = await userCollection.findOne({ username });

  if (user.role !== "admin") {
    return res.status(403).render("403");
  }

  const users = await userCollection.find({}).toArray();
  res.render("admin", { users });
});

app.get("/members", async (req, res) => {
  if (!req.session.loggedIn) {
    res.redirect("/");
    return;
  }

  const images = ["burger.webp", "pizza.webp", "sushi.webp"];

  const username = req.session.username;

  res.render("members", { username, images });
});

/** POST **/

app.post("/admin/promote", async (req, res) => {
  await userCollection.updateOne(
    { username: req.body.username },
    { $set: { role: "admin" } },
  );
  res.redirect("/admin");
});

app.post("/admin/demote", async (req, res) => {
  await userCollection.updateOne(
    { username: req.body.username },
    { $set: { role: "user" } },
  );
  res.redirect("/admin");
});

app.post("/signup", async (req, res) => {
  const username = req.body.username;
  const email = req.body.email;
  const password = req.body.password;

  const value = schema.validate({ username, password, email });

  if (value.error) {
    console.log(value.error.details[0].message);
    res.redirect("/signup");
    return;
  }

  const saltRounds = 10;
  const hashedPassword = bcrypt.hashSync(password, saltRounds);

  req.session.username = username;
  req.session.loggedIn = true;

  await userCollection.insertOne({
    username: username,
    password: hashedPassword,
    email: email,
    role: "user",
  });

  req.session.save((err) => {
    res.redirect("/members");
  });
});

app.post("/login", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  const user = await userCollection.findOne({ email });

  if (!user || !bcrypt.compareSync(password, user.password)) {
    console.error("Invalid email or password.");
    req.session.invalidInputs = true;
    res.redirect("/login");
    return;
  }

  req.session.loggedIn = true;
  req.session.invalidInputs = false;
  req.session.username = user.username;

  req.session.save((err) => {
    res.redirect("/members");
  });
});

app.post("/logout", (req, res) => {
  req.session.loggedIn = false;
  res.redirect("/");
});

app.use((req, res) => {
  res.status(404).render("404");
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
