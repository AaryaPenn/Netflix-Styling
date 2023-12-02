const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

// Temporary array to store user data
let users = [];

// Secret key for JWT (replace with a strong secret key in a real application)
const jwtSecret = 'your_secret_key';

// Middleware to parse JSON
app.use(bodyParser.json());

// Serve static files (HTML, CSS, images)
app.use(express.static('public'));

// Endpoint to handle user sign up
app.post('/signup', async (req, res) => {
    const { email, password } = req.body;

    // Check if the email already exists
    if (users.find(user => user.email === email)) {
        return res.status(400).json({ error: 'Email already exists' });
    }

    // Hash the password before storing it (use async function for bcrypt)
    const hashedPassword = await bcrypt.hash(password, 10);

    // Add the user to the array (in a real application, you'd use a database)
    users.push({ email, password: hashedPassword });

    return res.status(201).json({ success: true });
});

// Endpoint to handle user login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Find the user by email
    const user = users.find(user => user.email === email);

    // Check if the user exists
    if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare the provided password with the stored hashed password
    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
        return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate a JWT token for authentication (replace expiresIn with your preference)
    const token = jwt.sign({ email }, jwtSecret, { expiresIn: '1h' });

    return res.status(200).json({ token });
});

// Middleware to authenticate requests using JWT
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    jwt.verify(token, jwtSecret, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Forbidden' });
        }

        req.user = user;
        next();
    });
};

// Example protected endpoint
app.get('/profile', authenticateToken, (req, res) => {
    return res.status(200).json({ user: req.user });
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
