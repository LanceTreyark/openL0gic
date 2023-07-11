// expressRoutes.js
// For Taking screenshots \/
const puppeteer = require('puppeteer');
const fsExtra = require('fs-extra');
// For Taking screenshots /\
const express = require('express');
const app = express();
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
//For email verification \/
const nodemailer = require('nodemailer');
// \/ For login and authentication logic
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
// \/ Require the dotenv package to read the .env file
const dotenv = require('dotenv');
/*
---------------------------------------------------------------------------------------
TODO:
Create HTML in /public for /user-portal

---------------------------------------------------------------------------------------
*/
// mail vfry \/
const transporter = nodemailer.createTransport({
  sendmail: true,
  newline: 'unix',
  path: '/usr/sbin/sendmail', // Path to the sendmail command
});

// \/ Set the path to your .env file
const envPath = path.resolve(__dirname, 'expressRoutes.env');

// Load the environment variables from the .env file
dotenv.config({ path: envPath });

// Access the environment variables
console.log(process.env.DB_USER);
console.log(process.env.DB_HOST);
//console.log(process.env.DB_DATABASE);
//console.log(process.env.DB_PASSWORD);


// Initialize session middleware (login and authentication)
app.use(session({
    // what is my secret key? \/
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false
  }));
  
// Initialize Passport and configure it to use the LocalStrategy for authentication  
app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(
  {
    usernameField: 'email',
    passwordField: 'password'
  },
  async (email, password, done) => {
    try {
      const query = {
        text: 'SELECT * FROM users WHERE email = $1',
        values: [email]
      };
      const result = await pool.query(query);
      const user = result.rows[0];
      
      if (!user) {
        return done(null, false, { message: 'Invalid email or password' });
      }

      const isPasswordMatch = await bcrypt.compare(password, user.password);
      if (!isPasswordMatch) {
        return done(null, false, { message: 'Invalid email or password' });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

// Serialize and deserialize user objects for session management:
passport.serializeUser((user, done) => {
    done(null, user.id);
  });
  
  passport.deserializeUser(async (id, done) => {
    try {
      const query = {
        text: 'SELECT * FROM users WHERE id = $1',
        values: [id]
      };
      const result = await pool.query(query);
      const user = result.rows[0];
      done(null, user);
    } catch (err) {
      done(err);
    }
  });


  
// EO BLock

// Set up body parser for handling POST requests
app.use(express.urlencoded({ extended: true }));

// Set up multer for handling file uploads
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const userDir = path.join(__dirname, 'uploads', req.user.id.toString());
    if (!fs.existsSync(userDir)) {
      fs.mkdirSync(userDir, { recursive: true });
    }
    cb(null, userDir);
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  },
});
const upload = multer({ storage: storage });

// PostgreSQL database credentials
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
  });

// Test the database connection and console.log the status
pool.connect((err) => {
  if (err) {
    console.error('Error connecting to database', err.stack);
  } else {
    console.log('Connected to database');
  }
});

// Serve the CSS file and HTML files
app.use(express.static(__dirname + '/public'));

// Serve the HTML form for creating user accounts
app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reg.html'));
});

//modified signuproute for email vfry:----------------------------
app.post('/signup', async (req, res) => {
  const { first_name, last_name, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const query = {
    text: 'INSERT INTO users (first_name, last_name, email, password) VALUES ($1, $2, $3, $4)',
    values: [first_name, last_name, email, hashedPassword],
  };
  try {
    const result = await pool.query(query);
    console.log('User created successfully:', result.rows[0]);

    // Send email verification link
    const verificationLink = 'http://forml0gic.com/verify/' + email; // Replace with your actual verification link
    const mailOptions = {
      from: 'service@forml0gic.com',
      to: email,
      subject: 'Email Verification',
      text: 'Please click the following link to verify your email: ' + verificationLink,
    };
    await transporter.sendMail(mailOptions);

    console.log('Email verification sent:', email);
    res.redirect('/');
  } catch (err) {
    console.error('Error creating user:', err);
    res.status(500).send('Error creating user');
  }
});


app.get('/verify/:email', async (req, res) => {
  const email = req.params.email;
  const query = {
    text: 'UPDATE users SET verified = true WHERE email = $1',
    values: [email],
  };
  try {
    const result = await pool.query(query);
    console.log('User verified:', result.rowCount > 0);
    res.send('Email verification successful!');
  } catch (err) {
    console.error('Error verifying user:', err);
    res.status(500).send('Error verifying user');
  }
});


// Serve the CSS file and HTML files out of the public dir.
app.use(express.static(__dirname + "/public"));




// HTML form for user login located in public dir.
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Implement the login route with Passport's authenticate method:
app.post('/login', (req, res, next) => {
    console.log('Login request received');
    passport.authenticate('local', (err, user, info) => {
      if (err) {
        console.error('Error during authentication:', err);
        return next(err);
      }
      if (!user) {
        console.log('Invalid email or password');
        return res.redirect('/login');
      }
      req.logIn(user, (err) => {
        if (err) {
          console.error('Error logging in:', err);
          return next(err);
        }
        console.log('User logged in:', user);
        return res.redirect('/user-portal');
      });
    })(req, res, next);
  });

// Serve the HTML page for the user portal (unprotected)
app.get('/userPortal', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'userPortal.html'));
  });
    

// Protect routes using authentication middleware
function authenticate(req, res, next) {
  // Implement the authentication middleware:
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
  // Authentication middleware logic...
}

// User portal route (protected)
app.get('/user-portal', authenticate, (req, res) => {
  // User portal logic...
  // Implement the user portal logic:
  //res.send('Welcome to the user portal!');
  res.sendFile(path.join(__dirname, 'public', 'user-portal.html'));
    
});

// For Taking screenshots \/
// For Taking screenshots \/
// For Taking screenshots \/


//Put your html files in that directory and the program will capture screenshots
// levelOneForms-  Proprietary forms level one directory. (basic stuff, no logic)
app.use('/levelOneForms', authenticate, express.static(path.join(__dirname, 'levelOneForms')));




// Function to take a screenshot of a web page and save it to a file
async function takeScreenshot(url, filePath) {
  const browser = await puppeteer.launch({
    executablePath: '/usr/bin/google-chrome-stable', // Replace with the correct path to your Chrome binary
    headless: 'new',
    args: ['-u'],
    fullPage: false,
    captureBeyondViewport: false,
  });

  const page = await browser.newPage();
  await page.goto(url);
  await page.screenshot({ path: filePath, fullPage: true });
  await browser.close();
}

// Route handler for updating the screenshots
app.post('/updateScreenshots', async (req, res) => {
  const htmlDirectoryPath = path.join(__dirname, 'levelOneForms');

  try {
    // Get the list of HTML files in the directory
    const files = await fsExtra.readdir(htmlDirectoryPath);

    // Iterate over each file
    for (const file of files) {
      // Check if the file is an HTML file
      if (file.endsWith('.html')) {
        // Construct the file paths
        const filePath = path.join(htmlDirectoryPath, file);
        const screenshotPath = path.join(htmlDirectoryPath, file.replace('.html', '.png'));

        // Take a screenshot of the HTML page and save it to a file
        try {
          await takeScreenshot(`file://${filePath}`, screenshotPath);
          console.log(`Screenshot updated for ${file}`);

          // Introduce a delay of 1 second (adjust as needed)
          await new Promise((resolve) => setTimeout(resolve, 1000));
        } catch (error) {
          console.error(`Error updating screenshot for ${file}:`, error);
        }
      }
    }

    res.send('Screenshots updated successfully');
  } catch (error) {
    console.error('Error updating screenshots:', error);
    res.status(500).send('Error updating screenshots');
  }
});


// For Taking screenshots /\

app.listen(3006, () => {
  console.log('Server listening on port 3006');
});
