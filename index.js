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
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const { database } = require("./databaseConnection.js");
const userCollection = database.db(mongodb_user).collection("users");

const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_database}`;
const expireTime = 60 * 60; // 1 hour

const mongoStore = MongoStore.create({
  mongoUrl: atlasURI,
  ttl: expireTime,
  crypto: {
    secret: mongodb_session_secret,
  },
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

  const user = await userCollection.findOne({ email });

  if (loggedIn) {
    res.send(`
      <h3>Hey, ${user.username}</h3>
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
        <input name='username' type='text' placeholder='Username'></input>
        <input name='email' type='email' placeholder='Email'></input>
        <input name='password' type='password' placeholder='Password'></input>
        <button style='width: fit-content'>Submit</button>
    </form>
  `);
});

app.get("/members", async (req, res) => {
  if (!req.session.loggedIn) {
    res.redirect("/");
    return;
  }

  const images = ["burger.webp", "pizza.webp", "sushi.webp"];
  const image = images[Math.floor(Math.random() * images.length)];

  const user = await userCollection.findOne({ email });

  res.send(`
    <h1>Hello, ${user.username}!</h1>
    <img src='/images/${image}' alt='${image}'>
    <form action='/logout' method='post'><button>Log out</button></form>
  `);
});

/** POST **/

app.post("/signup", async (req, res) => {
  try {
    const username = req.body.username || null;
    const email = req.body.email || null;
    const password = req.body.password || null;

    const value = schema.validate({ username, password, email });

    if (value.error) {
      console.log(value.error.details[0].message);
      res.redirect("/signup");
      return;
    }

    const saltRounds = 10;
    const hashedPassword = bcrypt.hashSync(password, saltRounds);

    await userCollection.insertOne({ username: username, password: hashedPassword, email: email });

    res.redirect("/login");
    
  } catch (error) {
    console.log("Error: " + error);
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.email || null;
  const password = req.body.password || null;

  const user = await userCollection.findOne({ email });

  if (!user || !bcrypt.compareSync(password, user.password)) {
    console.error("Invalid email or password.");
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

app.use((req, res) => {
  res.status(404).send("Page not found - 404");
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
