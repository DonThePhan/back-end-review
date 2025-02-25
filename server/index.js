/**
 following this tutorial: https://youtu.be/1oTuMPIwHmk?si=wMMC49NlGkmI5UyN&t=7227
 *  */

require('dotenv').config();
const express = require('express');
const db = require('better-sqlite3')('ourApp.db');
db.pragma('journal_mode = WAL');
const app = express();
const bcrypt = require('bcrypt');
const cookie = require('cookie-parser');
const jwt = require('jsonwebtoken');
const sanitizeHTML = require('sanitize-html');
const cookieParser = require('cookie-parser');

const createToken = user =>
  jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000 + /* 24hr -> */ 60 * 60 * 24), // expires in 24hr expressed in seconds
      skyColor: 'blue',
      userid: user.id,
      username: user.username
    },
    process.env.JWTSECRET
  );

const createCookie = (res, token) =>
  res.cookie(
    'ourSimpleApp', // cookie name
    token, // cookie value
    {
      httpOnly: true, // so that client side js cannot access cookies in the browser. Cookies only sent automatically w/ each request
      secure: true, // browser will only send cookies if https connection, not http. Doesn't apply to localhost, but once deployed will take effect
      sameSite: 'strict', // so we don't need to worry about csrf attacks
      maxAge: 1000 * 60 * 60 * 24 // 1et cookie be good for 1 day
    }
  );

const getFormattedDate = date => {
  const dateObj = new Date(date);
  return `${dateObj.getFullYear()}/${
    dateObj.getMonth() + 1
  }/${dateObj.getDay()}`;
};

// DATABASE SETUP ===========================================================================

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

  db.prepare(
    `
    CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    createdDate TEXT,
    title STRING NOT NULL,
    body TEXT NOT NULL,
    authorid INTEGER,
    FOREIGN KEY (authorid) REFERENCES users (id)
    )
    `
  ).run();
});
createTables();

//MIDDLEWARE SETUP ===========================================================================

app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}));
app.use(express.static('public'));
app.use(cookieParser()); // allows us to get req.cookies

// ROUTES ===========================================================================

// this will run before any route is hit
app.use((req, res, next) => {
  // try to decode incoming cookie
  try {
    const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET);
    req.user = decoded;
  } catch (err) {
    req.user = false;
  }

  res.locals.user = req.user;
  console.log('req.user => ', req.user);
  res.locals.errors = [];
  next();
});

app.get('/', (req, res) => {
  if (req.user) {
    const postsStatement = db.prepare('SELECT * FROM posts WHERE authorid = ?');
    const posts = postsStatement.all(req.user.userid);
    return res.render('dashboard', {posts, getFormattedDate});
  }
  res.render('homepage');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.get('/logout', (req, res) => {
  res.clearCookie('ourSimpleApp');
  res.redirect('/');
});

app.post('/login', (req, res) => {
  let errors = [];
  let {username, password} = req.body;

  if (typeof username !== 'string') username = '';
  if (typeof req.body.password !== 'string') req.body.password = '';

  if (!username.trim() || !password) errors = ['Invalid username / password'];

  if (errors.length) return res.render('login', {errors});

  const userInQuestionStatement = db.prepare(
    'SELECT * FROM users WHERE USERNAME = ?'
  );
  const userInQuestion = userInQuestionStatement.get(username);

  if (!userInQuestion) {
    errors = ['Invalid username / password'];
    return res.render('login', {errors});
  }

  const matchOrNot = bcrypt.compareSync(password, userInQuestion.password);

  if (!matchOrNot) {
    errors = ['Invalid username / password'];
    return res.render('login', {errors});
  }

  const token = createToken(userInQuestion);
  createCookie(res, token);
  res.redirect('/');
});

const mustBeLoggedIn = (req, res, next) => {
  if (req.user) {
    return next();
  }
  return res.redirect('/');
};

// note how this works. You can change as many arguements starting from position 2. To move through them serially, take note of the "next()" func that is passed along w/ req & res in each of these args -> see func "mustBeLoggedIn"
app.get('/create-post', mustBeLoggedIn, (req, res) => {
  res.render('create-post');
});

const sharedPostValidation = req => {
  const errors = [];
  let {title, body} = req.body;
  title = typeof title === 'string' ? title : '';
  body = typeof body === 'string' ? body : '';

  title = sanitizeHTML(title.trim(), {allowedTags: [], allowedAttributes: {}});
  body = sanitizeHTML(body.trim(), {allowedTags: [], allowedAttributes: {}});

  if (!title || !body) {
    errors.push('You must provide a title & content');
  }
  return errors;
};

app.get('/post/:id', (req, res) => {
  const statement = db.prepare(
    `
    SELECT * FROM posts
    INNER JOIN users ON posts.authorid = users.id
    WHERE posts.id = ?
    `
  );
  const post = statement.get(req.params.id);

  if (!post) {
    return res.redirect('/');
  }

  res.render('single-post', {post, getFormattedDate});
});

app.post('/create-post', mustBeLoggedIn, (req, res) => {
  const errors = sharedPostValidation(req);
  if (errors.length) {
    return res.render('create-post', {errors});
  }

  // save into database
  const ourStatement = db.prepare(
    'INSERT INTO posts (title, body, authorid, createdDate) VALUES (?, ?, ?, ?)'
  );
  const result = ourStatement.run(
    req.body.title,
    req.body.body,
    req.user.userid,
    new Date().toISOString()
  );

  const getPostStatement = db.prepare('SELECT * FROM posts WHERE ROWID = ?');
  const realPost = getPostStatement.get(result.lastInsertRowid);

  res.redirect(`/post/${realPost.id}`);
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

  const usernameStatement = db.prepare(
    'SELECT * FROM users WHERE username = ?'
  );
  const usernameCheck = usernameStatement.get(username);

  if (usernameCheck) errors.push('That username is already taken');

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

  const ourTokenValue = createToken(ourUser);
  createCookie(res, ourTokenValue);
  res.redirect('/');
});

app.listen(3000);
