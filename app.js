const express = require('express');
const session = require('express-session'); 
const mysql = require("mysql")
const path = require("path")
const dotenv = require('dotenv')
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs")
const nodemailer = require('nodemailer');
const { check } = require('express-validator');
const saltRounds = 10;

dotenv.config({ path: './.env'})

const app = express();

const db = mysql.createConnection({
    host: process.env.DATABASE_HOST,
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    database: process.env.DATABASE
})

const publicDir = path.join(__dirname, './public')
const viewsDir = path.join(__dirname, './views')

// Expose the CSRF token to templates
app.use(session({
    secret: 'mysecretkeyisthissentenceanditisverylong!!!...',
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 3600000 // Set the maximum age of the cookie (in milliseconds), e.g., 1 hour
    }
}));

const authenticateUser = (req, res, next) => {
    if (req.session.user) {
        return next();
    }
    res.redirect('/login'); // Redirect unauthorized users to the login page
};

const checkLoggedIn = (req, res, next) => {
    if (req.session.user) {
        res.redirect('/dashboard'); // Redirect unauthorized users to the dashboard page
    }
    return next();
};

app.use(express.static(publicDir))
app.use(express.static(viewsDir))
app.use(express.urlencoded({extended: 'false'}))
app.use(express.json())

app.set('view engine', 'hbs')

db.connect((error) => {
    if(error) {
        console.log(error)
    } else {
        console.log("MySQL connected!")
    }
})

app.get("/", (req, res) => {
    const user = req.session.user; // Get user data from session

    // Pass the user data to the template
    res.render("index", { user });
});

app.get("/register", checkLoggedIn, (req, res) => {
    res.render("register")
})

app.get("/login", checkLoggedIn, (req, res) => {
    res.render("login", {
        message: '' // Provide an empty message by default
    });
})

app.get('/dashboard', authenticateUser, (req, res) => {
    // Access user data from req.session.user
    const user = req.session.user;
    res.render('dashboard', { user });
});

app.get('/forgot-password', (req, res) => {
    res.render('forgot-password');
});

app.get('/logout', (req, res) => {
    // Here, you can clear the user's session or perform any other necessary logout actions
    // For example, if you're using express-session for session management:
    req.session.destroy(err => {
        if (err) {
            console.error('Error destroying session:', err);
        }
        res.redirect('/');
    });
});

// Define a route for the profile page
app.get('/profile', authenticateUser, (req, res) => {
    const user = req.session.user; // Retrieve the user object from session

    if (!user) {
        // Redirect to login if user is not logged in
        return res.redirect('/login');
    }

    const userId = user.id; // Get the user's ID from the user object

    db.query('SELECT * FROM user WHERE id = ?', [userId], (err, result) => {
        if (err) {
            console.error('Error fetching user data:', err);
            res.status(500).send('Internal Server Error');
        } else {
            const userProfile = result[0]; // Fetch user's profile from the database
            console.log('Viewing profile...');
            res.render('profile', { user: userProfile }); // Render the profile page
        }
    });
});

function sendConfirmationEmail(email, token) {
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: 'rawdogmag@gmail.com',
            pass: 'gasxbtwljrytlaln'
        }
    });

    const mailOptions = {
        from: 'rawdogmag@gmail.com',
        to: email,
        subject: 'Confirm Your Email',
        html: `<p>Please click <a href="http://localhost:3000/confirm/${token}">here</a> to confirm your email.</p>`
    };

    transporter.sendMail(mailOptions, function(error, info){
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}

//

app.post("/auth/register", (req, res) => {
    const { name, email, password, password_confirm } = req.body;

    // Email format validation
    const emailPattern = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
    if (!emailPattern.test(email)) {
        return res.render('register', {
            message: 'Invalid Email'
        });
    }

    db.query('SELECT email FROM user WHERE email = ?', [email], async (error, result) => {
        if (error) {
            console.log(error);
        }

        if (result.length > 0) {
            return res.render('register', {
                message: 'This email is already in use'
            });
        } else if (password !== password_confirm) {
            return res.render('register', {
                message: 'Password Didn\'t Match!'
            });
        }

        const confirmationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        let hashedPassword = await bcrypt.hash(password, 8);

        console.log(hashedPassword);

        db.query('INSERT INTO user_pending SET ?', { name, email, password: hashedPassword, confirmation_token: confirmationToken }, (err, result) => {
            if (err) {
                console.log(err);
            } else {
                // Send confirmation email
                // Here, you would call a function to send the email containing the confirmation link
                // You might use a library like nodemailer for this purpose
                sendConfirmationEmail(email, confirmationToken);

                // Now, perform the database insertion here, within this callback
                db.query('INSERT INTO user SET ?', { name, email, password: hashedPassword }, (err, result) => {
                    if (err) {
                        console.log(err);
                    } else {
                        return res.render('register', {
                            message: 'Please check email to confirm and login!'
                        });
                    }
                });
            }
        });
    });
});

app.post("/auth/login", (req, res) => {
    const { email, password } = req.body;

    console.log('Attempting to log in:', email, password);

    db.query('SELECT * FROM user WHERE email = ?', [email], async (error, result) => {
        if (error) {
            console.log('Database query error:', error);
        } else if (result.length === 0) {
            console.log('User not found:', email);
            return res.render('login', {
                message: 'User not found'
            });
        } else {
            const user = result[0];
            const passwordMatch = await bcrypt.compare(password, user.password);

            console.log('Password match:', passwordMatch);

            if (!user.confirmed) {
                console.log('User email not confirmed:', email);
                return res.render('login', {
                    message: 'Please confirm your email before logging in'
                });
            }

            if (passwordMatch) {
                // Redirect to the dashboard after successful login
                req.session.user = user;
                return res.redirect('/dashboard');
            } else {
                console.log('Invalid password for user:', email);
                return res.render('login', {
                    message: 'Invalid password'
                });
            }
        }
    });
});


app.get('/confirm/:token', (req, res) => {
    const token = req.params.token;

    jwt.verify(token, process.env.JWT_SECRET, (error, decodedToken) => {
        if (error) {
            console.log('Token verification error:', error);
            return res.render('confirmation', { confirmed: false });
        } else {
            const userEmail = decodedToken.email;

            db.query('UPDATE user SET confirmed = ? WHERE email = ?', [true, userEmail], (err, result) => {
                if (err) {
                    console.log('Database update error:', err);
                    return res.render('confirmation', { confirmed: false });
                } else {
                    console.log('Email confirmed for:', userEmail);
                    return res.render('confirmation', { confirmed: true });
                }
            });
        }
    });
});

// Middleware to check if the user is authenticated
const authenticateToken = (req, res, next) => {
    const token = req.cookies.authToken; // Read the token from cookie (or session)
    if (token) {
        jwt.verify(token, process.env.JWT_SECRET, (error, decodedToken) => {
            if (error) {
                console.log('Token verification error:', error);
                res.redirect('/login'); // Redirect to login if token is invalid
            } else {
                req.userId = decodedToken.userId; // Store user ID in the request
                next(); // Continue to the next middleware
            }
        });
    } else {
        res.redirect('/login'); // Redirect to login if token is not present
    }
};

app.post("/forgot-password", (req, res) => {
    const { email } = req.body;

    // Generate a reset token
    const resetToken = jwt.sign({ email }, process.env.JWT_RESET_SECRET, { expiresIn: '1h' });

    // Store the reset token in the database
    db.query('UPDATE user SET reset_token = ? WHERE email = ?', [resetToken, email], (err, result) => {
        if (err) {
            console.log(err);
            // Handle the error appropriately, e.g., render an error page
            return res.render("error");
        }

        // Send reset email
        sendResetEmail(email, resetToken);

        // Render a page to inform the user that a reset link has been sent
        res.render("reset-link-sent");
    });
});

app.post('/reset-password', (req, res) => {
    const { newPassword, confirmPassword, resetToken } = req.body;

    // Verify that newPassword and confirmPassword match
    if (newPassword !== confirmPassword) {
        return res.render('reset-password-form', {
            resetToken,
            message: 'Passwords do not match'
        });
    }

    jwt.verify(resetToken, process.env.JWT_RESET_SECRET, (error, decodedToken) => {
        if (error) {
            return res.render('reset-password-form', {
                resetToken,
                message: 'Invalid or expired reset token'
            });
        }

        const userEmail = decodedToken.email;

        // Hash the new password before updating it in the database
        bcrypt.hash(newPassword, saltRounds, (err, hashedPassword) => {
            if (err) {
                return res.render('reset-password-form', {
                    resetToken,
                    message: 'Error updating password'
                });
            }
        
            // Update the user's password in the database
            db.query('UPDATE user SET password = ? WHERE email = ?', [hashedPassword, userEmail], (updateErr, updateRes) => {
                if (updateErr) {
                    return res.render('reset-password-form', {
                        resetToken,
                        message: 'Error updating password'
                    });
                }
        
                // Password updated successfully
                res.render('password-reset-success');
            });
        });
    });
});


app.get('/reset/:token', (req, res) => {
    const resetToken = req.params.token;

    // Here, you can implement logic to verify the reset token
    // For example, you can use jwt.verify to validate the token
    jwt.verify(resetToken, process.env.JWT_RESET_SECRET, (error, decodedToken) => {
        if (error) {
            console.log('Token verification error:', error);
            // Handle invalid or expired token here (e.g., redirect to an error page)
            res.redirect('/password-reset-error');
        } else {
            // Token is valid, render the password reset form
            res.render('reset-password-form', { resetToken });
        }
    });
});

function sendResetEmail(email, token) {
    const transporter = nodemailer.createTransport({
        service: 'Gmail',
        auth: {
            user: 'rawdogmag@gmail.com',
            pass: 'gasxbtwljrytlaln'
        }
    });

    const mailOptions = {
        from: 'rawdogmag@gmail.com',
        to: email,
        subject: 'Password Reset',
        html: `<p>Please click <a href="http://localhost:3000/reset/${token}">here</a> to reset your password.</p>`
    };

    transporter.sendMail(mailOptions, function(error, info) {
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
}

// Protected route that only logged-in users can access
app.get('/dashboard', authenticateToken, (req, res) => {
    // Access req.userId to fetch user data from the database
    db.query('SELECT * FROM user WHERE id = ?', [req.userId], (error, result) => {
        if (error) {
            console.log(error);
        } else {
            const user = result[0];
            res.render('dashboard', { user });
        }
    });
});


app.listen(3000, () => {
    console.log("server started on port 3000");
});
