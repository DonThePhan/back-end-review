/**
 following this tutorial: https://youtu.be/1oTuMPIwHmk?si=_tKY9GoDNv5QxQXL&t=3648
 *  */

require('dotenv').config();
const express = require('express');
const db = require('better-sqlite3')('ourApp.db');
db.pragma('journal_mode = WAL');
const app = express();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// database setup start
const createTables = db.transaction(() => {
  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username STRING NOT NULL UNIQUE,
    password STRING NOT NULL
    )
 `
  ).run();
});
createTables();
// database setup end

// this will run before any route is hit
app.use((req, res, next) => {
  res.locals.errors = [];
  next();
});

app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}));
// app.use(express.static('public'));

app.get('/', (req, res) => {
  res.render('homepage');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/register', (req, res) => {
  const errors = [];
  let {username, password} = req.body;

  if (typeof username !== 'string') username = '';
  if (typeof req.body.password !== 'string') req.body.password = '';

  username = username.trim();

  if (!username) errors.push('You must provide a username');
  if (username && (username.length < 3 || username.length > 10))
    errors.push('username length must be between 3 - 10 characters long');
  if (username && !username.match(/^[a-zA-Z0-9]+$/))
    errors.push('Username can only contain letters & numbers');

  if (!password) errors.push('You must provide a password');
  if (password && (password.length < 12 || password.length > 70))
    errors.push('password length must be between 12 - 70 characters long');

  console.log(req.body);
  if (errors.length) {
    return res.render('homepage', {errors});
  }

  const salt = bcrypt.genSaltSync(10);
  password = bcrypt.hashSync(password, salt);

  // save the new user into db
  const ourStatement = db.prepare(
    'INSERT INTO users (username, password) VALUES (?, ?)'
  );
  const result = ourStatement.run(username, password);

  const lookupStatement = db.prepare('SELECT * FROM users WHERE ROWID = ?');
  const ourUser = lookupStatement.get(result.lastInsertRowid);

  const ourTokenValue = jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000 + /* 24hr -> */ 60 * 60 * 24), // expires in 24hr expressed in seconds
      skyColor: 'blue',
      userid: ourUser.id,
      username: ourUser.username
    },
    process.env.JWTSECRET
  );

  res.cookie(
    'ourSimleApp', // cookie name
    ourTokenValue, // cookie value
    {
      httpOnly: true, // so that client side js cannot access cookies in the browser. Cookies only sent automatically w/ each request
      secure: true, // browser will only send cookies if https connection, not http. Doesn't apply to localhost, but once deployed will take effect
      sameSite: 'strict', // so we don't need to worry about csrf attacks
      maxAge: 1000 * 60 * 60 * 24 // 1et cookie be good for 1 day
    }
  );

  // log the user in by giving them a cookie
  res.send('Thank You!');
});

app.listen(3000);
