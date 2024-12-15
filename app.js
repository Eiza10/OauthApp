const express = require('express');
const passport = require('passport');
const session = require('express-session');
const bodyParser = require('body-parser');
const { Strategy: LocalStrategy } = require('passport-local');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { Strategy: GitHubStrategy } = require('passport-github2');
const path = require('path');
require('dotenv').config();
const port = process.env.PORT || 3005;

const GoogleClientID = process.env.GOOGLE_CLIENT_ID;
const GooogleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
const GitHubClientID = process.env.GITHUB_CLIENT_ID;
const GitHubClientSecret = process.env.GITHUB_CLIENT_SECRET;


const app = express();

// Simulating a database with an array
const users = [];

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Passport Local Strategy
passport.use(
  new LocalStrategy((username, password, done) => {
    const user = users.find(u => u.username === username && u.password === password);
    if (user) return done(null, user);
    return done(null, false, { message: 'Invalid username or password' });
  })
);

// Passport Google Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: GoogleClientID,
      clientSecret: GooogleClientSecret,
      callbackURL: 'oauth.haritzeizagirre.eus/auth/google/callback',
    },
    (accessToken, refreshToken, profile, done) => {
      let user = users.find(u => u.id === profile.id);
      if (!user) {
        user = {
          id: profile.id,
          username: profile.displayName,
          email: profile.emails[0].value,
          platform: 'google',
        };
        users.push(user);
      }
      return done(null, user);
    }
  )
);

// Passport GitHub Strategy
passport.use(
  new GitHubStrategy(
    {
      clientID: GitHubClientID,
      clientSecret: GitHubClientSecret,
      callbackURL: 'oauth.haritzeizagirre.eus/auth/github/callback',
    },
    (accessToken, refreshToken, profile, done) => {
      let user = users.find(u => u.id === profile.id);
      if (!user) {
        user = {
          id: profile.id,
          username: profile.username,
          email: profile.emails ? profile.emails[0].value : 'No public email',
          platform: 'github',
        };
        users.push(user);
      }
      return done(null, user);
    }
  )
);

// Serialize and deserialize users
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const user = users.find(u => u.id === id);
  done(null, user);
});

// Routes
app.get('/', (req, res) => {
  res.render('login', { user: req.user });
});

app.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/profile',
    failureRedirect: '/',
  })
);

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', (req, res) => {
  const { username, password, email } = req.body;
  if (users.find(u => u.username === username)) {
    return res.send('User already exists');
  }
  users.push({
    id: `${Date.now()}`,
    username,
    password,
    email,
    platform: 'default',
  });
  res.redirect('/');
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get(
  '/auth/google/callback',
  passport.authenticate('google', {
    failureRedirect: '/',
    successRedirect: '/profile',
  })
);

app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

app.get(
  '/auth/github/callback',
  passport.authenticate('github', {
    failureRedirect: '/',
    successRedirect: '/profile',
  })
);

app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');
  res.render('profile', { user: req.user });
});

app.get('/logout', (req, res) => {
  req.logout(err => {
    if (err) return next(err);
    res.redirect('/');
  });
});

app.listen(port, () => console.log('Server running on port 3005'));
