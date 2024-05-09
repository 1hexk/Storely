const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const fs = require('fs');
const bcrypt = require('bcrypt');
const path = require('path');
const cors = require('cors');
const nodemailer = require('nodemailer');
const { google } = require('googleapis');
const redis = require('redis');
const session = require('express-session');


const app = express();
const port = 3000;

const validInvitationCodes = ['CSC489'];

const redisClient = redis.createClient({ url: 'redis://localhost:6379' });
redisClient.connect();


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors({
  origin: 'http://localhost:3000', 
  methods: ['GET', 'POST', 'DELETE'],
  credentials: true 
}));

app.use(session({
  secret: 'secret_key',
  resave: false,
  saveUninitialized: true
}));


const OAuth2 = google.auth.OAuth2;
const otpStore = new Map();  

function generateOTP() {
  const otp = Math.floor(100000 + Math.random() * 900000);  
  const expiry = Date.now() + 300000;  
  return { otp: otp.toString(), expiry };
}


const oauth2Client = new OAuth2(
  "510457036951-s23m3h2vnftu8bg8f9eeba9kq06v9jmd.apps.googleusercontent.com",
  "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", 
  "http://localhost:3000/oauth2callback/"
);

oauth2Client.setCredentials({
  refresh_token: "1//03Dx0uCOiYDrzCgYIARAAGAMSNwF-L9IrHaMmvkWyeLAyzt9dyKvcwIKRdWJ2iJ2AHYmnJ6jQ9wcdF3Gl6tV0K277jE1lJzSN7xI"
});

async function getAccessToken() {
  const { token } = await oauth2Client.getAccessToken();
  return token;
}

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    type: "OAuth2",
    user: "storelyotp@gmail.com",
    clientId: "510457036951-s23m3h2vnftu8bg8f9eeba9kq06v9jmd.apps.googleusercontent.com",
    clientSecret: "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",
    refreshToken: "1//03Dx0uCOiYDrzCgYIARAAGAMSNwF-L9IrHaMmvkWyeLAyzt9dyKvcwIKRdWJ2iJ2AHYmnJ6jQ9wcdF3Gl6tV0K277jE1lJzSN7xI",
    accessToken: getAccessToken,
  },
});


async function sendOTP(email, otpData) {
  const mailOptions = {
    from: 'storelyotp@gmail.com',
    to: email,
    subject: 'Storely OTP',
    text: `Thank you for using the Storely App! Do not share the following code with anyone: Your OTP is ${otpData.otp}`,
  };

  try {
    const result = await transporter.sendMail(mailOptions);
    console.log('Email sent successfully', result);
  } catch (error) {
    console.error('Failed to send email:', error);
  }
}



app.use(express.static(path.join(__dirname, 'public')));

function userKey(username) {
  return `user:${username}`;
}

function otpKey(email) {
  return `otp:${email}`;
}

async function saveUser(username, userData) {
  await redisClient.set(userKey(username), JSON.stringify(userData));
}

async function getUser(username) {
  const data = await redisClient.get(userKey(username));
  return data ? JSON.parse(data) : null;
}

async function saveOTP(email, otpData) {
  await redisClient.set(otpKey(email), JSON.stringify(otpData), { EX: 300 }); // 5 minutes expiry
}

async function getOTP(email) {
  const data = await redisClient.get(otpKey(email));
  return data ? JSON.parse(data) : null;
}

async function removeOTP(email) {
  await redisClient.del(otpKey(email));
}

async function authenticate(req, res, next) {
  console.log(req.session)
  console.log(req.session.user)
  if (req.session && req.session.user) {
    const user = await getUser(req.session.user);
    if (user && user.sessionVerified) {
      return next();
    } else {
      return res.status(403).send('Your email address has not been verified.');
    }
  } else {
    return res.sendStatus(401);  
  }
}

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    if (!req.session.user) {
      return cb(new Error('No session user available'), null);
    }
    const username = req.session.user;
    const userUploadsDir = `uploads/${username}/`; 
    fs.mkdir(userUploadsDir, { recursive: true }, (err) => {
      if (err) {
        return cb(err, null);
      }
      cb(null, userUploadsDir);
    });
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  }
});

const upload = multer({ storage: storage });

// Login route
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await getUser(username);
  if (user && bcrypt.compareSync(password, user.password)) {
    const otpData = generateOTP();
    await saveOTP(user.email, otpData);
    await sendOTP(user.email, otpData);
    res.json({ otpRequired: true });
  } else {
    res.status(400).json({ error: 'Invalid username or password' });
  }
});



app.get('/signup', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'signup.html'));
});

// Signup
app.post('/signup', async (req, res) => {
  const { username, password, email } = req.body;
  const invitationCode = req.body.invitationCode;

  if (!validInvitationCodes.includes(invitationCode)) {
    return res.status(400).send('Invalid invitation code.');
  }

  if (await getUser(username)) {
    return res.status(409).send('Username already taken');
  }

  const hash = await bcrypt.hash(password, 10);
  const user = { username, password: hash, email, sessionVerified: false };
  await saveUser(username, user);

  const otpData = generateOTP();
  await saveOTP(email, otpData);
  await sendOTP(email, otpData);
  res.json({ message: "OTP sent to your email. Please verify to complete registration." });
});

app.post('/verify-otp', async (req, res) => {
  let { email, otp, username } = req.body;
  console.log("Received body:", req.body);

  if (!email && username) {
    const user = await getUser(username);
    if (user) {
      email = user.email;
    } else {
      console.log(`No user found with username: ${username}`);
      return res.status(399).json({ error: 'Username not found.' });
    }
  }

  if (!email || !otp) {
    return res.status(400).json({ error: 'Email and OTP must be provided.' });
  }

  const storedOtpData = await getOTP(email);
  if (!storedOtpData || storedOtpData.otp !== otp || Date.now() >= storedOtpData.expiry) {
    console.log(`Invalid or expired OTP for email: ${email}, OTP Received: ${otp}`);
    return res.status(402).json({ error: 'Invalid or expired OTP.' });
  }

  const user = await getUser(username);
  if (!user) {
    console.log(`Failed to retrieve user data for username: ${username} after OTP verification`);
    return res.status(403).json({ error: 'No such user found.' });
  }

  user.sessionVerified = true;
  await saveUser(username, user);

  req.session.user = user.username;
  req.session.sessionVerified = true;

  await removeOTP(email);

  req.session.save(err => {
    if (err) {
      console.error('Session save error:', err);
      return res.status(500).send('Session save failed.');
    }
    res.json({ success: true, message: 'Verification successful', redirect: '/dashboard' });
  });
});

app.get('/api/files', authenticate, (req, res) => {
  const username = req.session.user; 
  const userUploadsDir = `uploads/${username}/`; 

  fs.access(userUploadsDir, fs.constants.F_OK, (err) => {
    if (err) {
      return res.json({ files: [] });
    }

    fs.readdir(userUploadsDir, (err, files) => {
      if (err) {
        console.log('Error reading files:', err);
        return res.status(500).send('Failed to load files');
      }
      res.json({ files }); 
    });
  });
});

app.get('/dashboard', authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});


app.get('/logout', async (req, res) => {
  if (req.session.user) {
    const user = await getUser(req.session.user);
    if (user) {
      user.sessionVerified = false;
      await saveUser(req.session.user, user); 
    }

    req.session.destroy((err) => {
      if (err) {
        console.log('Error destroying session:', err);
        return res.status(500).send('Could not log out, please try again');
      }
      res.redirect('/login?logged_out=true');
    });
  } else {
    req.session.destroy(() => {
      res.redirect('/login?logged_out=true');
    });
  }
});


app.post('/upload', authenticate, upload.single('file'), (req, res) => {
  if (req.file) {
    res.json({ success: true, message: 'File uploaded successfully' });
  } else {
    res.status(400).json({ success: false, message: 'No file uploaded' });
  }
});

app.get('/download/:filename', authenticate, (req, res) => {
  const { filename } = req.params;
  const username = req.session.user; 
  const userUploadsDir = `uploads/${username}/${filename}`;

  if (fs.existsSync(userUploadsDir)) {
    res.download(userUploadsDir);
  } else {
    res.status(404).send('File not found');
  }
});

app.delete('/delete/:filename', authenticate, (req, res) => {
  const { filename } = req.params;
  const username = req.session.user; 
  const userUploadsDir = `uploads/${username}/${filename}`;

  if (fs.existsSync(userUploadsDir)) {
    fs.unlinkSync(userUploadsDir);
    res.send('File deleted successfully');
  } else {
    res.status(404).send('File not found');
  }
});

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});