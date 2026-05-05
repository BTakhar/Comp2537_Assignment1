require('dotenv').config();

const express = require('express');
const session = require('express-session');
const { MongoStore } = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

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

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 60 * 60 * 1000 }
}));

const isLoggedIn = (req) => req.session.authenticated && req.session.username;

app.get('/', (req, res) => {
    if (!isLoggedIn(req)) {
        res.send(`
            <body style="text-align:center;">
                <button onclick="window.location.href='/signup'">Sign Up</button><br><br>
                <button onclick="window.location.href='/login'">Login</button>
            </body>
        `);
    } else {
        res.send(`
            <body style="text-align:center;">
                Hello, ${req.session.username}!<br><br>
                <button onclick="window.location.href='/members'">Members Area</button><br><br>
                <button onclick="window.location.href='/logout'">Logout</button>
            </body>
        `);
    }
});

app.get('/signup', (req, res) => {
    res.send(`
        create user
        <form action='/submitUser' method='post'>
            <input name='username' type='text' placeholder='username'><br>
            <input name='email' type='email' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
    `);
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
    await userCollection.insertOne({ username, password: hashedPassword, email });

    req.session.username = username;
    req.session.authenticated = true;

    req.session.save((err) => {
        if (err) console.error('session save error:', err);
        res.redirect('/members');
    });
});

app.get('/login', (req, res) => {
    res.send(`
        log in
        <form action='/loggingin' method='post'>
            <input name='email' type='email' placeholder='email'><br>
            <input name='password' type='password' placeholder='password'><br>
            <button>Submit</button>
        </form>
    `);
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

    req.session.username      = user.username;
    req.session.email         = user.email;
    req.session.authenticated = true;

    req.session.save((err) => {
        if (err) console.error('session save error:', err);
        res.redirect('/members');
    });
});

app.get('/members', (req, res) => {
    if (!isLoggedIn(req)) {
        return res.redirect('/');
    }

    const images = ['Transformers07.jpg', 'TF2SteelPoster.jpg', 'tf3logo.webp'];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <body style="text-align:center;">
            Hello, ${req.session.username}!<br><br>
            <img src="/${randomImage}" alt="random image" width="300"><br><br>
            <button onclick="window.location.href='/logout'">Logout</button>
        </body>
    `);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.use((req, res) => {
    res.status(404).send("Page not found - 404");
});

async function startServer() {
    try {
        await connectDB();
        app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
        });
    } catch (err) {
        console.error('DB connection failed:', err);
        process.exit(1);
    }
}

startServer();