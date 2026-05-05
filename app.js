require('dotenv').config();

const express = require('express');
const session = require('express-session');
const {MongoStore} = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;


const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
const { MongoClient } = require('mongodb');

app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static('public'));

let userCollection;
const mongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_user_database}?retryWrites=true&w=majority`;
const client = new MongoClient(mongoUrl);
//user db
async function connectDB() {
    await client.connect();
    const db = client.db(mongodb_user_database);
    userCollection = db.collection('users');
    console.log('Connected to MongoDB');
}
connectDB().catch(console.error);

//session db
const mongoStore = MongoStore.create({
    mongoUrl: mongoUrl,
    collectionName: 'sessions',
    crypto: { secret: mongodb_session_secret}
    
})
mongoStore.on('error', (err) => {
  console.log('Session store error:', err);
});


//sets up session
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
            <button onclick="window.location.href='/login'">Login</button><br><br>
            
        </body>
    `);
    } else {
        res.send(
            `
        <body style="text-align:center;">
            Hello, ${req.session.username}! <br><br>
            <button onclick="window.location.href='/members'">Members Area</button><br><br>
            <button onclick="window.location.href='/logout'">Logout</button><br><br>
            
        </body>
        `
        );
    };
});


app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email' required>
    <input name='password' type='password' placeholder='password' required>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/loggingin', async (req, res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            password: Joi.string().max(20).required(),
            email: Joi.string().email().required()
        });

    const { error } = schema.validate({ email, password });
    if (error) {
        const msg = error.details[0].message;
        return res.send(`<p>${msg}</p><a href="/login">Try again</a>`);
    }

    const user = await userCollection.findOne({ email });

    if (!user) {
        return res.send(`<p>Invalid email/password combination.</p><a href="/login">Try again</a>`);
    }

    const pass = await bcrypt.compare(password, user.password);

    if (!pass) {
        return res.send(`<p>Invalid email/password combination.</p><a href="/login">Try again</a>`);

    }

    req.session.username = user.username;
    req.session.email = user.email;
    req.session.authenticated = true;   

     req.session.save((err) => {       
        if (err) console.error(err);
        res.redirect('/members');
    });
});


app.get('/signup', (req, res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req, res) => {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;
    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required(),
            password: Joi.string().max(20).required(),
            email: Joi.string().email().required()
        });

    const { error } = schema.validate({ username, email, password });
    if (error) {
        const msg = error.details[0].message;
        return res.send(`<p>${msg}</p><a href="/signup">Try again</a>`);
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    req.session.username = username;
    req.session.authenticated = true;

    await userCollection.insertOne({ username: username, password: hashedPassword, email: email });
    console.log("Inserted user");

    console.log('mongoStore:', mongoStore);
    console.log('session id before save:', req.session.id);
    console.log('session data before save:', req.session);

    req.session.save((err) => {
        if (err) console.error('session save error:', err);
        console.log('session after save:', req.session);
        res.redirect('/members');
    });
});



app.get('/members', (req, res) => {
    console.log('members session id:', req.session.id);
    console.log('members session data:', req.session);
    console.log('isLoggedIn:', isLoggedIn(req));
    if (!isLoggedIn(req)) {
        return res.redirect('/');
    }
    const images = ['Transformers07.jpg','TF2SteelPoster.jpg','tf3logo.webp'];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    const html = `
        <body style="text-align:center;">
         Hello, ${req.session.username}! <br><br>
         <img src="/${randomImage}" alt="random image" width="300"><br><br>
         ${randomImage}
        <button onclick="window.location.href='/logout'">Logout</button><br><br>
        <body style="text-align:center;">
           
        `


    res.send(html);

});

app.get('/logout', (req, res) => {
    req.session.destroy();
   res.redirect('/');
});




app.use((req, res) => {
    res.status(404);
    res.send("Page not found - 404");
});
async function startServer() {
    try {
        await connectDB();

        app.listen(PORT, () => {
            console.log(`Server running on http://localhost:${PORT}`);
        });

    } catch (err) {
        console.error("Server failed to start:", err);
    }
}

startServer();
