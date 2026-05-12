require('dotenv').config();

const express = require('express');
const session = require('express-session');
const { MongoStore } = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');


const app = express();
const saltRounds = 12;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

//middleware

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

let userCollection;
const mongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_user_database}?retryWrites=true&w=majority`;
const client = new MongoClient(mongoUrl);

async function connectDB() {
    await client.connect();
    const db = client.db(mongodb_user_database);
    userCollection = db.collection('users');
    console.log('Connected to MongoDB');
}

const mongoStore = MongoStore.create({
    mongoUrl: mongoUrl,
    collectionName: 'sessions',
    crypto: { secret: mongodb_session_secret }
});


//Authmiddleware

function requireLogin(req, res, next) {
  if (!isLoggedIn(req)) {
    return res.redirect('/');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  if (req.session.user.user_type !== 'admin') {
    return res.status(403).render('403', { user: req.session.user });
  }
  next();
}


app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 * 60 * 1000 }
}));

const isLoggedIn = (req) => req.session.authenticated && req.session.user;

app.get('/', (req, res) => {

    res.render('index', {
        loggedIn: isLoggedIn(req),
        user: req.session.user || null
    });

});

app.get('/signup', (req, res) => {
    res.render('signup', { user: req.session.user || null, error: null });
});

app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;

    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        password: Joi.string().max(20).required(),
        email:    Joi.string().email().required()
    });

    const { error } = schema.validate({ username, email, password });
    if (error) {
        return res.send(`<p>${error.details[0].message}</p><a href="/signup">Try again</a>`);
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({ username, password: hashedPassword, email, user_type: "user" });

   req.session.user = {
    username: username,
    email: email,
    user_type: "user"
};

req.session.authenticated = true;

    req.session.save((err) => {
        if (err) console.error('session save error:', err);
        res.redirect('/members');
    });
});

app.get('/login', (req, res) => {
    res.render('login', { user: req.session.user || null, error: null });
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        password: Joi.string().max(20).required(),
        email:    Joi.string().email().required()
    });

    const { error } = schema.validate({ email, password });
    if (error) {
        return res.send(`<p>${error.details[0].message}</p><a href="/login">Try again</a>`);
    }

    const user = await userCollection.findOne({ email });
    if (!user) {
        return res.send(`<p>Invalid email/password combination.</p><a href="/login">Try again</a>`);
    }

    const pass = await bcrypt.compare(password, user.password);
    if (!pass) {
        return res.send(`<p>Invalid email/password combination.</p><a href="/login">Try again</a>`);
    }

    req.session.user = {
    username: user.username,
    email: user.email,
    user_type: user.user_type || "user"
};

req.session.authenticated = true;

    req.session.save((err) => {
        if (err) console.error('session save error:', err);
        res.redirect('/members');
    });
});

app.get('/members', requireLogin, (req, res) => {
    res.render('members', {loggedIn: isLoggedIn(req), user: req.session.user || null });
});

app.get('/admin', requireAdmin, async (req, res) => {
  const users = await userCollection.find({}).toArray();
  res.render('admin', { user: req.session.user, users });
});

// Promote user to admin – POST
app.post('/promote', requireAdmin, async (req, res) => {
  // Joi validate the email input
  const schema = Joi.object({ email: Joi.string().email().required() });
  const { error } = schema.validate({ email: req.body.email });
  if (error) return res.redirect('/admin');

  await userCollection
    .updateOne({ email: req.body.email }, { $set: { user_type: 'admin' } });

  // Update session if promoting yourself
  if (req.session.user.email === req.body.email) {
    req.session.user.user_type = 'admin';
  }

  res.redirect('/admin');
});

// Demote user to regular user – POST
app.post('/demote', requireAdmin, async (req, res) => {
  const schema = Joi.object({ email: Joi.string().email().required() });
  const { error } = schema.validate({ email: req.body.email });
  if (error) return res.redirect('/admin');

  await userCollection
    .updateOne({ email: req.body.email }, { $set: { user_type: 'user' } });

  // Update session if demoting yourself
  if (req.session.user.email === req.body.email) {
    req.session.user.user_type = 'user';
  }

  res.redirect('/admin');
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.use((req, res) => {
     res.status(404).render('404', { user: req.session.username || null });
});

async function startServer() {
    try {
        console.log("Starting server...");
        await connectDB();
        console.log("Mongo connected");

        const PORT = process.env.PORT || 3000;

        app.listen(PORT, '0.0.0.0', () => {
            console.log(`Listening on port ${PORT}`);
        });

    } catch (err) {
        console.error("Startup failed:", err);
        process.exit(1);
    }
}

startServer();