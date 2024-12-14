// Importar las dependencias necesarias
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const dotenv = require('dotenv');
const path = require('path');
const port = process.env.PORT || 3005;

// Configurar variables de entorno
dotenv.config();

const app = express();

// Simulamos una base de datos de usuarios en memoria
const users = [
  { id: 1, username: 'usuario1', passwordHash: '$2a$10$KIXe9Qqf1F/6Fmvs6u5ycuOdCkHbs7df5q3owNT5q0J5pOp09Up3C' } // password: "123456"
];

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

// Configuración de Passport para la estrategia local
passport.use(new LocalStrategy((username, password, done) => {
  const user = users.find(u => u.username === username);
  if (!user) {
    return done(null, false, { message: 'Usuario no encontrado' });
  }

  bcrypt.compare(password, user.passwordHash, (err, isMatch) => {
    if (err) return done(err);
    if (isMatch) {
      return done(null, user);
    } else {
      return done(null, false, { message: 'Contraseña incorrecta' });
    }
  });
}));

// Serializar y deserializar el usuario
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = users.find(u => u.id === id);
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
  const { username } = req.user;
  res.render('user', { username });
});

// Ruta para el registro de usuarios
app.get('/register', (req, res) => {
  res.render('register');
});

// Procesar el formulario de registro
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const passwordHash = bcrypt.hashSync(password, 10);
  users.push({ id: users.length + 1, username, passwordHash });
  res.redirect('/');
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

// Procesar el formulario de inicio de sesión
app.post('/', passport.authenticate('local', {
  successRedirect: '/user',
  failureRedirect: '/',
  failureFlash: true,
}));

// Ruta para cerrar sesión
app.get('/logout', (req, res) => {
  req.logout(() => {
    res.redirect('/');
  });
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Server working on port: ${port}`);
});

module.exports = app;