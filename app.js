// Importar las dependencias necesarias
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const dotenv = require('dotenv');
const path = require('path');
const port = process.env.PORT || 3005;

// Configurar variables de entorno
dotenv.config();

const app = express();
const PORT = 3000;

// Configurar la sesión
app.use(session({
  secret: 'my_secret_key',
  resave: false,
  saveUninitialized: true,
}));

// Configurar motor de vistas EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Inicializar Passport
app.use(passport.initialize());
app.use(passport.session());

// Configuración de Passport para Google
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'https://oauth.haritzeizagirre.eus/auth/google/callback',
}, (accessToken, refreshToken, profile, done) => {
  return done(null, { profile, provider: 'google' });
}));

// Configuración de Passport para GitHub
passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: 'https://oauth.haritzeizagirre.eus/auth/github/callback',
}, (accessToken, refreshToken, profile, done) => {
  return done(null, { profile, provider: 'github' });
}));

// Serializar y deserializar el usuario
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// Middleware para comprobar si el usuario está autenticado
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/');
}

// Ruta principal
app.get('/', (req, res) => {
  res.render('index');
});

// Ruta protegida después del inicio de sesión
app.get('/user', isAuthenticated, (req, res) => {
  const { displayName, emails } = req.user.profile;
  const provider = req.user.provider;

  res.render('user', {
    name: displayName,
    email: emails ? emails[0].value : 'No disponible',
    provider,
  });
});

// Ruta para el inicio de sesión con Google
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Callback de Google
app.get('/auth/google/callback', passport.authenticate('google', {
  failureRedirect: '/',
}), (req, res) => {
  res.redirect('/user');
});

// Ruta para el inicio de sesión con GitHub
app.get('/auth/github', passport.authenticate('github', { scope: ['user:email'] }));

// Callback de GitHub
app.get('/auth/github/callback', passport.authenticate('github', {
  failureRedirect: '/',
}), (req, res) => {
  res.redirect('/user');
});

// Ruta para cerrar sesión
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
