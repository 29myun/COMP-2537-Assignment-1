require("dotenv").config();
const bcrypt = require("bcrypt");
const express = require("express");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static("public"));

const node_session_secret = process.env.NODE_SESSION_SECRET;
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
  ttl: 60 * 60, // session expires after 1 hour
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
  }),
);

/** GET **/

app.get("/", (req, res) => {
  const loggedIn = req.session.loggedIn;

  if (loggedIn) {
    res.send(`
      <h3>Hey, ${req.session.username}</h3>
      <form action='/members' method='get'><button>Go to Members Area</button></form>
      <form action='/logout' method='post'><button>Log out</button></form>
    `);
    return;
  }

  res.send(`
    <form action='/login' method='get'><button>Login</button></form>
    <form action='/signup' method='get'><button>Sign up</button></form>
  `);
});

app.get("/login", (req, res) => {
  res.send(`
    <h3>Log into your account</h3>
    <form action='login' method='post' style='display: flex; flex-direction: column; width: 256px'>
        <input name='email' type='email' placeholder='Email' required='true'></input>
        <input name='password' type='password' placeholder='Password' required='true'></input>
        <button style='width: fit-content'>Submit</button>
    </form>
  `);
});

app.get("/signup", (req, res) => {
  res.send(`
    <h3>Create an account</h3>
    <form action='/signup' method='post' style='display: flex; flex-direction: column; width: 256px'>
        <input name='username' type='text' placeholder='Username' required='true'></input>
        <input name='email' type='email' placeholder='Email' required='true'></input>
        <input name='password' type='password' placeholder='Password' required='true'></input>
        <button style='width: fit-content'>Submit</button>
    </form>
  `);
});

app.get("/members", (req, res) => {
  if (!req.session.loggedIn) {
    res.redirect("/");
    return;
  }

  console.log(req.session.password);

  const images = ["burger.webp", "pizza.webp", "sushi.webp"];
  const image = images[Math.floor(Math.random() * images.length)];

  res.send(`
    <h1>Hello, ${req.session.username}!</h1>
    <img src='/images/${image}' alt='${image}'>
    <form action='/logout' method='post'><button>Log out</button></form>
  `);
});

app.get("/*does_not_exist", (req, res) => {
  res.status(404).send("Page not found - 404");
});

/** POST **/

app.post("/signup", (req, res) => {
  const username = req.body.username || null;
  const email = req.body.email || null;
  const password = req.body.password || null;

  if (!username || !email || !password) {
    console.log("Sign up failed.");
    return;
  }

  req.session.username = username;
  req.session.email = email;

  const saltRounds = 10;
  req.session.password = bcrypt.hashSync(password, saltRounds);

  res.redirect("/login");
});

app.post("/login", (req, res) => {
  const email = req.body.email || null;
  const password = req.body.password || null;

  if (
    email != req.session.email ||
    !bcrypt.compareSync(password, req.session.password)
  ) {
    console.log("Incorrect email or password");
    res.redirect("/login");
    return;
  }

  req.session.loggedIn = true;
  res.redirect("/members");
});

app.post("/logout", (req, res) => {
  req.session.loggedIn = false;
  res.redirect("/");
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
