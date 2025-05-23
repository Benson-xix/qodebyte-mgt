
const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2'); 
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const dotenv = require('dotenv');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const axios = require('axios');
const sodium = require('libsodium-wrappers'); 
const cron = require('node-cron');
const router = express.Router();
const { body, validationResult } = require('express-validator');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');
dotenv.config();

const port = process.env.PORT || 3000;
const app = express();
app.use(cors());
const secretKey = uuidv4();




app.use(
    session({
      secret: secretKey,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 3600000, 
      },
    })
  );


  app.use(bodyParser.json());
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  const connection =  mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    maxIdle: 0,
    idleTimeout: 60000,
    enableKeepAlive: true,
  });


  const swaggerDefinition = {
    openapi: '3.0.0',
    info: {
      title: 'Project Management API',
      version: '1.0.0',
      description: 'API documentation for the Project Management system',
    },
    servers: [
      {
        url: 'https://qodebyte-mgt.onrender.com/', // Replace with your Render deployment URL after deployment
        description: 'Development server',
      },
    ],
  };
  
  // Swagger options
  const options = {
    swaggerDefinition,
    apis: [path.join(__dirname, 'index.js')],
  };
  
 
  const swaggerSpec = swaggerJsdoc(options);

  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

  app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
  
  const generateId = () => crypto.randomBytes(5).toString('hex');

  const storage = multer.diskStorage({
   destination: (req, file, cb) => {
     cb(null, path.join(__dirname, 'uploads')); 
   },
   filename: (req, file, cb) => {
     const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
     cb(null, `${file.fieldname}-${uniqueSuffix}${path.extname(file.originalname)}`);
   },
 });
 const upload = multer({ storage });

 const transporter = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    tls: {
      rejectUnauthorized: false,
    },
    debug: true,
  });


  app.get('/swagger.json', (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
  });


/** 
 * @swagger
 * https://qodebyte-mgt.onrender.com/register-admin:
 *   post:
 *     summary: Register a new admin
 *     description: Register a new admin account with email, username, and password
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: Email of the admin
 *                 example: admin@example.com
 *               username:
 *                 type: string
 *                 description: Username of the admin
 *                 example: adminuser
 *               password:
 *                 type: string
 *                 description: Password for the admin account
 *                 example: password123
 *               confirmPassword:
 *                 type: string
 *                 description: Confirmation of the password
 *                 example: password123
 *     responses:
 *       200:
 *         description: Admin registered successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                   example: Admin registered and OTP sent
 *       400:
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Error message
 *                   example: Passwords do not match
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Error message
 *                   example: Server error
 */

  app.post('/register-admin', async (req, res) => {
    const { email, username, password, confirmPassword } = req.body;
  
    if (password !== confirmPassword) {
      return res.status(400).json({ message: 'Passwords do not match' });
    }
  
    try {
      
      const emailCheckQuery = 'SELECT id FROM admin WHERE email = ?';
      connection.query(emailCheckQuery, [email], async (emailErr, emailResults) => {
        if (emailErr) {
          return res.status(500).json({ message: 'Error checking email', error: emailErr });
        }
  
        if (emailResults.length > 0) {
          return res.status(400).json({ message: 'Email already registered' });
        }
  
        const hashedPassword = await bcrypt.hash(password, 10);
  
        const query = `INSERT INTO admin (email, username, password, confirm_password) VALUES (?, ?, ?, ?)`;
        connection.query(query, [email, username, hashedPassword, hashedPassword], (err, result) => {
          if (err) {
            return res.status(500).json({ message: 'Error creating admin', error: err });
          }

          logActivity(
            'INSERT',
            'admin',
            `Registered a new admin with ID ${result.insertId} and email ${email}`,
            'Admin'
          );
  
          const otpCode = crypto.randomInt(100000, 999999).toString();
          const expirationTime = new Date(Date.now() + 5 * 60 * 1000);
  
          const otpQuery = `INSERT INTO register_otp (otp_code, inputed_email, expired) VALUES (?, ?, ?)`;
          connection.query(otpQuery, [otpCode, email, expirationTime], (otpErr) => {
            if (otpErr) {
              return res.status(500).json({ message: 'Error saving OTP', error: otpErr });
            }
  
            const mailOptions = {
              from: process.env.EMAIL_USER,
              to: process.env.EMAIL_USER,
              subject: 'Your OTP Code',
              text: `Your OTP code is: ${otpCode}. It will expire in 5 minutes.`,
            };
  
            transporter.sendMail(mailOptions, (mailErr, info) => {
              if (mailErr) {
                return res.status(500).json({ message: 'Error sending OTP', error: mailErr });
              }

              logActivity(
                'EMAIL',
                null,
                `Sent an email to ${mailOptions.to} with subject "${mailOptions.subject}"`,
                'System'
              );

          
  
              res.status(200).json({ message: 'Admin registered and OTP sent' });
            });
          });
        });
      });
    } catch (error) {
      res.status(500).json({ message: 'Server error', error });
    }
});


/** 
 * @swagger
 * https://qodebyte-mgt.onrender.com/verify-otp:
 *   post:
 *     summary: Verify OTP for admin registration
 *     description: Verify the OTP sent to the admin's email during registration
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: Email of the admin
 *                 example: admin@example.com
 *               otp:
 *                 type: string
 *                 description: OTP sent to the admin's email
 *                 example: 123456
 *     responses:
 *       200:
 *         description: OTP verified successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                   example: OTP verified successfully
 *       400:
 *         description: Invalid or expired OTP
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Invalid or expired OTP
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Server error
 */
  app.post('/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
  
    try {
      const query = `SELECT * FROM register_otp WHERE inputed_email = ? AND otp_code = ? AND expired > NOW()`;
      connection.query(query, [email, otp], (err, results) => {
        if (err) {
          logActivity('ERROR', 'register_otp', `Error verifying OTP for email ${email}`, 'System');
          return res.status(500).json({ message: 'Error verifying OTP', error: err });
        }

        
        if (results.length === 0) {
          logActivity('FAILED', 'register_otp', `Invalid or expired OTP for email ${email}`, 'System');
          return res.status(400).json({ message: 'Invalid or expired OTP' });
        }

        logActivity('VERIFY', 'register_otp', `OTP verified successfully for email ${email}`, 'System');

  
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Account Created',
          text: `The account associated with email ${email} has been successfully created.`,
        };
  
        transporter.sendMail(mailOptions, (mailErr, info) => {
          if (mailErr) {
            return res.status(500).json({ message: 'Error sending confirmation email', error: mailErr });
          }

          logActivity(
            'EMAIL',
            null,
            `Sent an email to ${mailOptions.to} with subject "${mailOptions.subject}"`,
            'System'
          );
  
          res.status(200).json({ message: 'OTP verified and account created' });
        });
      });
    } catch (error) {
      logActivity('ERROR', 'register_otp', `Server error while verifying OTP for email ${email}`, 'System');
      res.status(500).json({ message: 'Server error', error });
    }
  });

/**
 * @swagger 
 * https://qodebyte-mgt.onrender.com/admin_login:
 *   post:
 *     summary: Admin login
 *     description: Login for admin users
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: Admin email address
 *                 example: admin@example.com
 *               password:
 *                 type: string
 *                 description: Admin password
 *                 example: password123
 *     responses:
 *       200:
 *         description: Login successful, OTP sent to email
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                   example: Login successful, OTP sent to EMAIL_USER
 *       400:
 *         description: Invalid email or password
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Invalid email or password
 *       500:
 *         description: Server error
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Server error
 */
  app.post('/admin_login', async (req, res) => {
    const { email, password } = req.body;
  
    try {
 
      const query = `SELECT * FROM admin WHERE email = ?`;
      connection.query(query, [email], async (err, results) => {
        if (err) {
          logActivity('ERROR', 'admin', `Error checking admin credentials for email ${email}`, 'System');
          return res.status(500).json({ message: 'Error checking admin credentials', error: err });
        }
  
        if (results.length === 0) {
          logActivity('FAILED', 'admin', `Login attempt failed for email ${email} (email not found)`, 'System');
          return res.status(400).json({ message: 'Invalid email or password' });
        }
  
        const admin = results[0];
  
     
        const isPasswordValid = await bcrypt.compare(password, admin.password);
        if (!isPasswordValid) {
          logActivity('FAILED', 'admin', `Login attempt failed for email ${email} (invalid password)`, 'System');
          return res.status(400).json({ message: 'Invalid email or password' });
        }
  
        logActivity('LOGIN', 'admin', `Admin with email ${email} logged in successfully`, 'Admin');
  
        const otpCode = crypto.randomInt(100000, 999999).toString();
  
       
        const expirationTime = new Date(Date.now() + 5 * 60 * 1000);
  
      
        const otpQuery = `INSERT INTO register_otp (otp_code, inputed_email, expired) VALUES (?, ?, ?)`;
        connection.query(otpQuery, [otpCode, email, expirationTime], (otpErr) => {
          if (otpErr) {
            logActivity('ERROR', 'register_otp', `Error saving OTP for email ${email}`, 'System');
            return res.status(500).json({ message: 'Error saving OTP', error: otpErr });
          }
  
          logActivity('INSERT', 'register_otp', `Generated OTP for email ${email}`, 'System');
  
  
       
          const mailOptions = {
            from: process.env.EMAIL_USER,
            to: process.env.EMAIL_USER,
            subject: 'Login OTP Code',
            text: `Your login OTP code is: ${otpCode}. It will expire in 5 minutes.`,
          };
  
          transporter.sendMail(mailOptions, (mailErr, info) => {
            if (mailErr) {
              return res.status(500).json({ message: 'Error sending OTP', error: mailErr });
            }

            logActivity(
              'EMAIL',
              null,
              `Sent an email to ${mailOptions.to} with subject "${mailOptions.subject}"`,
              'System'
            );
  
            res.status(200).json({ message: 'Login successful, OTP sent to EMAIL_USER' });
          });
        });
      });
    } catch (error) {
      logActivity('ERROR', 'admin', `Server error during login for email ${email}`, 'System');
      res.status(500).json({ message: 'Server error', error });
    }
  });

  /** 
   * @swagger
   * https://qodebyte-mgt.onrender.com/verify-login-otp:
   *   post:
   *     summary: Verify OTP for login
   *     description: Verify the OTP sent to the user's email for login
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               email:
   *                 type: string
   *                 description: Email of the user
   *                 example: user@example.com
   *               otp:
   *                 type: string
   *                 description: OTP sent to the user's email
   *                 example: 123456
   *     responses:
   *       200:
   *         description: OTP verified successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: OTP verified successfully
   *       400:
   *         description: Invalid or expired OTP
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Invalid or expired OTP
   *       500:
   *         description: Server error
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Server error
   */
  
  app.post('/verify-login-otp', async (req, res) => {
    const { email, otp } = req.body;
  
    try {
     
      const query = `SELECT * FROM register_otp WHERE inputed_email = ? AND otp_code = ? AND expired > NOW()`;
      connection.query(query, [email, otp], (err, results) => {
        if (err) {
          logActivity('ERROR', 'register_otp', `Error verifying login OTP for email ${email}`, 'System');
          return res.status(500).json({ message: 'Error verifying OTP', error: err });
        }

        if (results.length === 0) {
        logActivity('FAILED', 'register_otp', `Invalid or expired login OTP for email ${email}`, 'System');
        return res.status(400).json({ message: 'Invalid or expired OTP' });
      }
  
      logActivity('VERIFY', 'register_otp', `Login OTP verified successfully for email ${email}`, 'System');
      res.status(200).json({ message: 'Login OTP verified, login successful' });
    });
    } catch (error) {
      logActivity('ERROR', 'register_otp', `Server error while verifying login OTP for email ${email}`, 'System');
    res.status(500).json({ message: 'Server error', error });
  }
  });

  
/** 
 * @swagger
 * https://qodebyte-mgt.onrender.com/admin:
 *   get:
 *     summary: Get all admin accounts
 *     description: Retrieve a list of all admin accounts
 *     responses:
 *       200:
 *         description: A list of admin accounts
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                     description: Admin ID
 *                     example: 1
 *                   email:
 *                     type: string
 *                     description: Email of the admin
 *                     example: admin@example.com
 *                   username:
 *                     type: string
 *                     description: Username of the admin
 *                     example: adminuser
 *                   created_at:
 *                     type: string
 *                     format: date-time
 *                     description: Timestamp of when the admin account was created
 *                     example: 2023-10-01T12:00:00Z
 *       500:
 *         description: Failed to fetch admin accounts
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Failed to fetch admin accounts
 */
  app.get('/admin', (req, res) => {
    const query = 'SELECT id, email, username, created_at FROM admin ORDER BY created_at DESC';
    
    connection.query(query, (err, results) => {
      if (err) {
        console.error('Error fetching admins:', err);
        return res.status(500).json({ error: 'Failed to fetch admin accounts' });
      }
      logActivity('READ', 'admin', 'Fetched all admin accounts', 'Admin');
      
      res.status(200).json(results);
    });
  });

  /**
   * @swagger
   * https://qodebyte-mgt.onrender.com/admin/{email}:
   *   get:
   *     summary: Get an admin account by email
   *     description: Retrieve an admin account by its email
   *     parameters:
   *       - in: path
   *         name: email
   *         required: true
   *         schema:
   *           type: string
   *         description: Email of the admin account to retrieve
   *     responses:
   *       200:
   *         description: Admin account fetched successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 id:
   *                   type: integer
   *                   description: Admin ID
   *                   example: 1
   *                 email:
   *                   type: string
   *                   description: Email of the admin
   *                   example: admin@example.com
   *                 username:
   *                   type: string
   *                   description: Username of the admin
   *                   example: adminuser
   *                 created_at:
   *                   type: string
   *                   format: date-time
   *                   description: Timestamp of when the admin account was created
   *                   example: 2023-10-01T12:00:00Z
   *       404:
   *         description: Admin account not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Admin account not found
   *       500:
   *         description: Failed to fetch admin account
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to fetch admin account
   */

  app.get('/admin/:email', (req, res) => {
    const { email } = req.params;
    
    const query = 'SELECT id, email, username, created_at FROM admin WHERE email = ?';
    
    connection.query(query, [email], (err, results) => {
      if (err) {
        console.error('Error fetching admin:', err);
        return res.status(500).json({ error: 'Failed to fetch admin account' });
      }
      
      if (results.length === 0) {
        return res.status(404).json({ error: 'Admin account not found' });
      }
      
      logActivity('READ', 'admin', `Fetched admin account with ID ${email}`, 'Admin');
      res.status(200).json(results[0]);
    });
  });

  /** 
   * @swagger
   * https://qodebyte-mgt.onrender.com/admin/{adminId}:
   *   get:
   *     summary: Get an admin account by ID
   *     description: Retrieve an admin account by its ID
   *     parameters:
   *       - in: path
   *         name: adminId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the admin account to retrieve
   *     responses:
   *       200:
   *         description: Admin account fetched successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 id:
   *                   type: integer
   *                   description: Admin ID
   *                   example: 1
   *                 email:
   *                   type: string
   *                   description: Email of the admin
   *                   example: admin@example.com
   *                 username:
   *                   type: string
   *                   description: Username of the admin
   *                   example: adminuser
   *                 created_at:
   *                   type: string
   *                   format: date-time
   *                   description: Timestamp of when the admin account was created
   *                   example: 2023-10-01T12:00:00Z
   *       404:
   *         description: Admin account not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Admin account not found
   *       500:
   *         description: Failed to fetch admin account
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to fetch admin account
   */
  
  app.get('/admin/:adminId', (req, res) => {
    const { adminId } = req.params;
    
    const query = 'SELECT id, email, username, created_at FROM admin WHERE id = ?';
    
    connection.query(query, [adminId], (err, results) => {
      if (err) {
        console.error('Error fetching admin:', err);
        return res.status(500).json({ error: 'Failed to fetch admin account' });
      }
      
      if (results.length === 0) {
        return res.status(404).json({ error: 'Admin account not found' });
      }
      
      logActivity('READ', 'admin', `Fetched admin account with ID ${adminId}`, 'Admin');
      res.status(200).json(results[0]);
    });
  });

/** 
 * @swagger
 * /admin/{adminId}:
 *   put:
 *     summary: Update an admin account
 *     description: Update the email, username, or password of an admin account
 *     parameters:
 *       - in: path
 *         name: adminId
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the admin account to update
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: New email for the admin account
 *               username:
 *                 type: string
 *                 description: New username for the admin account
 *               password:
 *                 type: string
 *                 description: New password for the admin account
 *     responses:
 *       200:
 *         description: Admin account updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                   example: Admin account updated successfully
 *       400:
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Email, Username, or Password must be provided for update
 *       404:
 *         description: Admin account not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Admin account not found
 *       500:
 *         description: Failed to update admin account
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Failed to update admin account
 */
  
  app.put('/admin/:adminId', (req, res) => {
    const { adminId } = req.params;
    const { email, password, username } = req.body;
  
    if (!email && !username && !password) {
      return res.status(400).json({ error: 'Email, Username, or Password must be provided for update' });
    }
  
    const checkAdminQuery = 'SELECT * FROM admin WHERE id = ?';
    connection.query(checkAdminQuery, [adminId], (checkErr, results) => {
      if (checkErr) {
        console.error('Error checking admin:', checkErr);
        return res.status(500).json({ error: 'Failed to verify admin account' });
      }
  
      if (results.length === 0) {
        return res.status(404).json({ error: 'Admin account not found' });
      }
  
      const currentAdmin = results[0];
      const updateFields = [];
      const updateValues = [];
      let changesMade = [];
  
      if (email) {
        const emailCheckQuery = 'SELECT id FROM admin WHERE email = ? AND id != ?';
        connection.query(emailCheckQuery, [email, adminId], (emailErr, emailResults) => {
          if (emailErr) {
            console.error('Error checking email:', emailErr);
            return res.status(500).json({ error: 'Failed to check email availability' });
          }
  
          if (emailResults.length > 0) {
            return res.status(400).json({ error: 'Email already in use by another admin' });
          }
  
          updateFields.push('email = ?');
          updateValues.push(email);
          changesMade.push(`Email changed from ${currentAdmin.email} to ${email}`);
  
          proceedWithUpdate();
        });
      } else {
        proceedWithUpdate();
      }
  
      function proceedWithUpdate() {
        if (username && username !== currentAdmin.username) {
          updateFields.push('username = ?');
          updateValues.push(username);
          changesMade.push(`Username changed from ${currentAdmin.username} to ${username}`);
        }
  
        if (password) {
          bcrypt.hash(password, 10, (hashErr, hashedPassword) => {
            if (hashErr) {
              console.error('Error hashing password:', hashErr);
              return res.status(500).json({ error: 'Failed to hash password' });
            }
  
            updateFields.push('password = ?');
            updateValues.push(hashedPassword);
            changesMade.push('Password was updated');
            
            completeUpdate();
          });
        } else {
          completeUpdate();
        }
      }
  
      function completeUpdate() {
        if (updateFields.length === 0) {
          return res.status(400).json({ error: 'No valid fields to update' });
        }
  
        const query = `UPDATE admin SET ${updateFields.join(', ')} WHERE id = ?`;
        updateValues.push(adminId);
  
        connection.query(query, updateValues, (updateErr) => {
          if (updateErr) {
            console.error('Error updating admin:', updateErr);
            return res.status(500).json({ error: 'Failed to update admin account' });
          }
  
         
          if (changesMade.length > 0) {
            const notificationEmail = email || currentAdmin.email;
            const mailOptions = {
              from: process.env.EMAIL_USER,
              to: notificationEmail,
              subject: 'Your Admin Account Has Been Updated',
              text: `The following changes were made to your account:\n\n${changesMade.join('\n')}\n\nIf you didn't make these changes, please contact support immediately.`
            };
  
            transporter.sendMail(mailOptions, (mailErr) => {
              if (mailErr) {
                console.error('Error sending notification email:', mailErr);
              
              }
              logActivity(
                'EMAIL',
                null,
                `Sent an email to ${mailOptions.to} with subject "${mailOptions.subject}"`,
                'System'
              );

              res.status(200).json({ message: 'Admin account updated successfully. Notification email sent.' });
            });
          } else {
            logActivity('UPDATE', 'admin', `Updated admin account with ID ${adminId}`, 'Admin');
            res.status(200).json({ message: 'Admin account updated successfully' });
          }
        });
      }
    });
});


/** 
 * @swagger
 * /admin/{adminId}:
 *   delete:
 *     summary: Delete an admin account
 *     description: Deletes an admin account by ID
 *     parameters:
 *       - in: path
 *         name: adminId
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the admin account to delete
 *     responses:
 *       200:
 *         description: Admin account deleted successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                   example: Admin account deleted successfully
 *       404:
 *         description: Admin account not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Admin account not found
 *       500:
 *         description: Failed to delete admin account
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Failed to delete admin account
 */

  app.delete('/admin/:adminId', (req, res) => {
    const { adminId } = req.params;
  

    const countQuery = 'SELECT COUNT(*) as count FROM admin';
    connection.query(countQuery, (countErr, countResults) => {
      if (countErr) {
        console.error('Error counting admins:', countErr);
        return res.status(500).json({ error: 'Failed to verify admin accounts' });
      }
  
      if (countResults[0].count <= 1) {
        return res.status(400).json({ error: 'Cannot delete the last admin account' });
      }
  
   
      const deleteQuery = 'DELETE FROM admin WHERE id = ?';
      connection.query(deleteQuery, [adminId], (deleteErr, results) => {
        if (deleteErr) {
          console.error('Error deleting admin:', deleteErr);
          return res.status(500).json({ error: 'Failed to delete admin account' });
        }
  
        if (results.affectedRows === 0) {
          return res.status(404).json({ error: 'Admin account not found' });
        }
  
        logActivity('DELETE', 'admin', `Deleted admin account with ID ${adminId}`, 'Admin');
        res.status(200).json({ message: 'Admin account deleted successfully' });
      });
    });
  });

/** 
 * @swagger
 * /forgot-password:
 *   post:
 *     summary: Request a password reset OTP
 *     description: Sends an OTP to the user's email for password reset
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *                 description: Email of the user requesting password reset
 *                 example: user@example.com
 *     responses:
 *       200:
 *         description: OTP sent successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                   example: OTP sent successfully
 *       400:
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Email is required
 *       404:
 *         description: Email not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Email not found
 *       500:
 *         description: Failed to send OTP
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Failed to send OTP
 */

  app.post('/forgot-password', (req, res) => {
    const { email } = req.body;
  
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
  
    
    const query = 'SELECT * FROM admin WHERE email = ?';
    connection.query(query, [email], (err, results) => {
      if (err) {
        logActivity('ERROR', 'admin', `Error checking email for forgot password: ${email}`, 'System');
        return res.status(500).json({ error: 'Failed to verify email' });
      }
  
      if (results.length === 0) {
        logActivity('FAILED', 'admin', `Forgot password attempt failed: Email not found (${email})`, 'System');
      return res.status(404).json({ error: 'Email not found' });
    }
  
      
      const otpCode = crypto.randomInt(100000, 999999).toString();
  
     
      const expirationTime = new Date(Date.now() + 5 * 60 * 1000);
  
     
      const otpQuery = `INSERT INTO register_otp (otp_code, inputed_email, expired) VALUES (?, ?, ?)`;
      connection.query(otpQuery, [otpCode, email, expirationTime], (otpErr) => {
        if (otpErr) {
          logActivity('ERROR', 'register_otp', `Error saving OTP for email: ${email}`, 'System');
        return res.status(500).json({ error: 'Failed to save OTP' });
      }
  
      
        const mailOptions = {
          from: process.env.EMAIL_USER,
          to: email,
          subject: 'Password Reset OTP',
          text: `Your OTP for password reset is: ${otpCode}. It will expire in 5 minutes.`,
        };
  
        transporter.sendMail(mailOptions, (mailErr, info) => {
          if (mailErr) {
            console.error('Error sending OTP:', mailErr);
            return res.status(500).json({ error: 'Failed to send OTP' });
          }

          logActivity(
            'EMAIL',
            null,
            `Sent an email to ${mailOptions.to} with subject "${mailOptions.subject}"`,
            'System'
          );
  
          res.status(200).json({ message: 'OTP sent successfully' });
        });
      });
    });
  });

  /** 
   * @swagger
   * /verify-forgot-password-otp:
   *   post:
   *     summary: Verify OTP for forgot password
   *     description: Verify the OTP sent to the user's email for password reset
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               email:
   *                 type: string
   *                 description: Email of the user
   *                 example: user@example.com
   *               otp:
   *                 type: string
   *                 description: OTP sent to the user's email
   *                 example: 123456
   *     responses:
   *       200:
   *         description: OTP verified successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: OTP verified successfully
   *       400:
   *         description: Invalid or expired OTP
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Invalid or expired OTP
   *       500:
   *         description: Server error
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Server error
   */

  app.post('/verify-forgot-password-otp', (req, res) => {
    const { email, otp } = req.body;
  
    if (!email || !otp) {
      return res.status(400).json({ error: 'Email and OTP are required' });
    }
  
    const query = `SELECT * FROM register_otp WHERE inputed_email = ? AND otp_code = ? AND expired > NOW()`;
    connection.query(query, [email, otp], (err, results) => {
      if (err) {
        logActivity('ERROR', 'register_otp', `Error verifying OTP for email: ${email}`, 'System');
        return res.status(500).json({ error: 'Failed to verify OTP' });
      }
  
      if (results.length === 0) {
        logActivity('FAILED', 'register_otp', `Invalid or expired OTP for email: ${email}`, 'System');
        return res.status(400).json({ error: 'Invalid or expired OTP' });
      }
  
      logActivity('VERIFY', 'register_otp', `OTP verified successfully for email: ${email}`, 'System');
      res.status(200).json({ message: 'OTP verified successfully' });
    });
  });

  /** 
   * @swagger
   * /create_project:
   *   post:
   *     summary: Create a new project
   *     description: Create a new project with the provided details
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               project_name:
   *                 type: string
   *                 description: Name of the project
   *                 example: Build a website
   *               description:
   *                 type: string
   *                 description: Description of the project
   *                 example: A project to build a responsive website
   *               start_date:
   *                 type: string
   *                 format: date
   *                 description: Start date of the project
   *                 example: 2023-01-01
   *               end_date:
   *                 type: string
   *                 format: date
   *                 description: End date of the project
   *                 example: 2023-12-31
   *               assigned_staff:
   *                 type: array
   *                 items:
   *                   type: string
   *                 description: List of assigned staff
   *                 example: ["John Doe", "Jane Smith"]
   *               project_manager:
   *                 type: string
   *                 description: Name of the project manager
   *                 example: Alice Johnson
   *               project_budget:
   *                 type: number
   *                 description: Budget of the project
   *                 example: 50000
   *               Priority:
   *                 type: string
   *                 description: Priority level of the project
   *                 example: High
   *               category:
   *                 type: string
   *                 description: Category of the project
   *                 example: IT
   *               cl_Name:
   *                 type: string
   *                 description: Client's name
   *                 example: Acme Corp
   *               cl_phone:
   *                 type: string
   *                 description: Client's phone number
   *                 example: +1234567890
   *               status:
   *                 type: string
   *                 description: Status of the project
   *                 example: pending
   *     responses:
   *       201:
   *         description: Project created successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: Project created successfully
   *                 projectId:
   *                   type: integer
   *                   description: ID of the created project
   *                   example: 1
   *       400:
   *         description: Bad request
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Project Name, Budget, and Category are required
   *       500:
   *         description: Failed to create project
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to create project
   */

  app.post('/create_project', (req, res) => {
    const {
      project_name,
      description,
      start_date,
      end_date,
      assigned_staff,
      project_manager,
      project_budget,
      Priority,
      category,
      cl_Name,
      cl_phone,
      status
    } = req.body;
  
    if (!project_name || !project_budget || !category) {
      return res.status(400).json({ error: 'Project Name, Budget, and Category are required' });
    }
  
    const assignedStaffJson = JSON.stringify(assigned_staff || []);
  
    const query = `
      INSERT INTO project (
        project_name, description, start_date, end_date, assigned_staff, 
        project_manager, project_budget, priority, category, client_name, client_phone, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
  
    const values = [
      project_name,
      description,
      start_date,
      end_date,
      assignedStaffJson,
      project_manager,
      project_budget,
      Priority,
      category,
      cl_Name,
      cl_phone,
      status || 'pending' 
    ];
  
    connection.query(query, values, (err, result) => {
      if (err) {
        logActivity('ERROR', 'project', `Error creating project: ${project_name}`, 'Admin');
        return res.status(500).json({ error: 'Failed to create project' });
      }
  
      logActivity('INSERT', 'project', `Created project: ${project_name} with ID ${result.insertId}`, 'Admin');
      res.status(201).json({ message: 'Project created successfully', projectId: result.insertId });
    });
});


/** 
 * @swagger
 * /project:
 *   get:
 *     summary: Get all projects
 *     description: Retrieve a list of all projects
 *     responses:
 *       200:
 *         description: A list of projects
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                     description: Project ID
 *                     example: 1
 *                   project_name:
 *                     type: string
 *                     description: Name of the project
 *                     example: Build a website
 *                   description:
 *                     type: string
 *                     description: Description of the project
 *                     example: A project to build a responsive website
 *                   start_date:
 *                     type: string
 *                     format: date
 *                     description: Start date of the project
 *                     example: 2023-01-01
 *                   end_date:
 *                     type: string
 *                     format: date
 *                     description: End date of the project
 *                     example: 2023-12-31
 *                   assigned_staff:
 *                     type: array
 *                     items:
 *                       type: string
 *                     description: List of assigned staff
 *                     example: ["John Doe", "Jane Smith"]
 *                   project_manager:
 *                     type: string
 *                     description: Name of the project manager
 *                     example: Alice Johnson
 *                   project_budget:
 *                     type: number
 *                     description: Budget of the project
 *                     example: 50000
 *                   Priority:
 *                     type: string
 *                     description: Priority level of the project
 *                     example: High
 *                   category:
 *                     type: string
 *                     description: Category of the project
 *                     example: IT
 *                   cl_Name:
 *                     type: string
 *                     description: Client's name
 *                     example: Acme Corp
 *                   cl_phone:
 *                     type: string
 *                     description: Client's phone number
 *                     example: +1234567890
 *                   status:
 *                     type: string
 *                     description: Status of the project
 *                     example: ongoing
 *       500:
 *         description: Failed to fetch projects
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Failed to fetch projects
 */

app.get('/project', (req, res) => {
  const query = 'SELECT * FROM project ORDER BY created_at DESC';

  connection.query(query, (err, results) => {
    if (err) {
      logActivity('ERROR', 'project', 'Error fetching all projects', 'System');
      return res.status(500).json({ error: 'Failed to fetch projects' });
    }

    logActivity('READ', 'project', 'Fetched all projects', 'Admin');
    res.status(200).json(results);
  });
});


/** 
 * @swagger
 * /project/{projectId}:
 *   get:
 *     summary: Get a project by ID
 *     description: Retrieve a project by its ID
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the project to retrieve
 *     responses:
 *       200:
 *         description: Project fetched successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   description: Project ID
 *                   example: 1
 *                 project_name:
 *                   type: string
 *                   description: Name of the project
 *                   example: Build a website
 *                 description:
 *                   type: string
 *                   description: Description of the project
 *                   example: A project to build a responsive website
 *                 start_date:
 *                   type: string
 *                   format: date
 *                   description: Start date of the project
 *                   example: 2023-01-01
 *                 end_date:
 *                   type: string
 *                   format: date
 *                   description: End date of the project
 *                   example: 2023-12-31
 *                 assigned_staff:
 *                   type: array
 *                   items:
 *                     type: string
 *                   description: List of assigned staff
 *                   example: ["John Doe", "Jane Smith"]
 *                 project_manager:
 *                   type: string
 *                   description: Name of the project manager
 *                   example: Alice Johnson
 *                 project_budget:
 *                   type: number
 *                   description: Budget of the project
 *                   example: 50000
 *                 Priority:
 *                   type: string
 *                   description: Priority level of the project
 *                   example: High
 *                 category:
 *                   type: string
 *                   description: Category of the project
 *                   example: IT
 *                 cl_Name:
 *                   type: string
 *                   description: Client's name
 *                   example: Acme Corp
 *                 cl_phone:
 *                   type: string
 *                   description: Client's phone number
 *                   example: +1234567890
 *                 status:
 *                   type: string
 *                   description: Status of the project
 *                   example: ongoing
 *       404:
 *         description: Project not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Project not found
 *       500:
 *         description: Failed to fetch project
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Failed to fetch project
 */

app.get('/project/:projectId', (req, res) => {
  const { projectId } = req.params;

  const query = 'SELECT * FROM project WHERE id = ?';

  connection.query(query, [projectId], (err, results) => {
    if (err) {
      logActivity('ERROR', 'project', `Error fetching project with ID ${projectId}`, 'System');
      return res.status(500).json({ error: 'Failed to fetch project' });
    }

    if (results.length === 0) {
      logActivity('FAILED', 'project', `Project not found with ID ${projectId}`, 'Admin');
      return res.status(404).json({ error: 'Project not found' });
    }

    logActivity('READ', 'project', `Fetched project with ID ${projectId}`, 'Admin');
    res.status(200).json(results[0]);
  });
});

/** 
 * @swagger
 * /project/{projectId}:
 *   patch:
 *     summary: Update a project
 *     description: Update the details of a project by its ID
 *     parameters:
 *       - in: path
 *         name: projectId
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the project to update
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               project_name:
 *                 type: string
 *                 description: Name of the project
 *               description:
 *                 type: string
 *                 description: Description of the project
 *               start_date:
 *                 type: string
 *                 format: date
 *                 description: Start date of the project
 *               end_date:
 *                 type: string
 *                 format: date
 *                 description: End date of the project
 *               assigned_staff:
 *                 type: array
 *                 items:
 *                   type: string
 *                 description: List of assigned staff
 *               project_manager:
 *                 type: string
 *                 description: Name of the project manager
 *               project_budget:
 *                 type: number
 *                 description: Budget of the project
 *               Priority:
 *                 type: string
 *                 description: Priority level of the project
 *               category:
 *                 type: string
 *                 description: Category of the project
 *               cl_Name:
 *                 type: string
 *                 description: Client's name
 *               cl_phone:
 *                 type: string
 *                 description: Client's phone number
 *               status:
 *                 type: string
 *                 description: Status of the project
 *     responses:
 *       200:
 *         description: Project updated successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   description: Success message
 *                   example: Project updated successfully
 *       400:
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: No fields to update
 *       404:
 *         description: Project not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Project not found
 *       500:
 *         description: Failed to update project
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Failed to update project
 */

  app.patch('/project/:projectId', (req, res) => {
    const { projectId } = req.params;
    const {
      project_name,
      description,
      start_date,
      end_date,
      assigned_staff,
      project_manager,
      project_budget,
      Priority,
      category,
      cl_Name,
      cl_phone,
      status
    } = req.body;
  
    const updateFields = [];
    const updateValues = [];
  
    if (project_name) {
      updateFields.push('project_name = ?');
      updateValues.push(project_name);
    }
    if (description) {
      updateFields.push('description = ?');
      updateValues.push(description);
    }
    if (start_date) {
      updateFields.push('start_date = ?');
      updateValues.push(start_date);
    }
    if (end_date) {
      updateFields.push('end_date = ?');
      updateValues.push(end_date);
    }
    if (assigned_staff) {
      updateFields.push('assigned_staff = ?');
      updateValues.push(JSON.stringify(assigned_staff));
    }
    if (project_manager) {
      updateFields.push('project_manager = ?');
      updateValues.push(project_manager);
    }
    if (project_budget) {
      updateFields.push('project_budget = ?');
      updateValues.push(project_budget);
    }
    if (Priority) {
      updateFields.push('priority = ?');
      updateValues.push(Priority);
    }
    if (category) {
      updateFields.push('category = ?');
      updateValues.push(category);
    }
    if (cl_Name) {
      updateFields.push('client_name = ?');
      updateValues.push(cl_Name);
    }
    if (cl_phone) {
      updateFields.push('client_phone = ?');
      updateValues.push(cl_phone);
    }
    if (status) {
      updateFields.push('status = ?');
      updateValues.push(status);
    }
  
    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }
  
    const query = `UPDATE project SET ${updateFields.join(', ')} WHERE id = ?`;
  updateValues.push(projectId);

  connection.query(query, updateValues, (err, result) => {
    if (err) {
      logActivity('ERROR', 'project', `Error updating project with ID ${projectId}`, 'Admin');
      return res.status(500).json({ error: 'Failed to update project' });
    }

    if (result.affectedRows === 0) {
      logActivity('FAILED', 'project', `Project not found with ID ${projectId}`, 'Admin');
      return res.status(404).json({ error: 'Project not found' });
    }

    logActivity('UPDATE', 'project', `Updated project with ID ${projectId}`, 'Admin');
    res.status(200).json({ message: 'Project updated successfully' });
  });
});


  /** 
   * @swagger
   * /project/{projectId}:
   *   delete:
   *     summary: Delete a project
   *     description: Delete a project by its ID
   *     parameters:
   *       - in: path
   *         name: projectId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the project to delete
   *     responses:
   *       200:
   *         description: Project deleted successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: Project deleted successfully
   *       404:
   *         description: Project not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Project not found
   *       500:
   *         description: Failed to delete project
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to delete project
   */

app.delete('/project/:projectId', (req, res) => {
  const { projectId } = req.params;

  const query = 'DELETE FROM project WHERE id = ?';

  connection.query(query, [projectId], (err, result) => {
    if (err) {
      logActivity('ERROR', 'project', `Error deleting project with ID ${projectId}`, 'Admin');
      return res.status(500).json({ error: 'Failed to delete project' });
    }

    if (result.affectedRows === 0) {
      logActivity('FAILED', 'project', `Project not found with ID ${projectId}`, 'Admin');
      return res.status(404).json({ error: 'Project not found' });
    }

    logActivity('DELETE', 'project', `Deleted project with ID ${projectId}`, 'Admin');
    res.status(200).json({ message: 'Project deleted successfully' });
  });
});

  /** 
   * @swagger
   * /project-stats:
   *   get:
   *     summary: Get project statistics
   *     description: Retrieve statistics about projects, including total, completed, ongoing, and overdue projects.
   *     responses:
   *       200:
   *         description: Project statistics retrieved successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 total_projects:
   *                   type: integer
   *                   description: Total number of projects
   *                   example: 100
   *                 completed_projects:
   *                   type: integer
   *                   description: Number of completed projects
   *                   example: 50
   *                 ongoing_projects:
   *                   type: integer
   *                   description: Number of ongoing projects
   *                   example: 30
   *                 overdue_projects:
   *                   type: integer
   *                   description: Number of overdue projects
   *                   example: 20
   *       500:
   *         description: Failed to fetch project statistics
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to fetch project statistics
   */

  app.get('/project-stats', (req, res) => {
    const totalProjectsQuery = 'SELECT COUNT(*) AS total_projects FROM project';
    const completedProjectsQuery = 'SELECT COUNT(*) AS completed_projects FROM project WHERE status = "completed"';
    const ongoingProjectsQuery = `
      SELECT COUNT(*) AS ongoing_projects 
      FROM project 
      WHERE status = "ongoing" AND start_date <= CURDATE() AND end_date >= CURDATE()
    `;
    const overdueProjectsQuery = `
      SELECT COUNT(*) AS overdue_projects 
      FROM project 
      WHERE status = "overdue" AND end_date < CURDATE()
    `;
  
    connection.query(
      `${totalProjectsQuery}; ${completedProjectsQuery}; ${ongoingProjectsQuery}; ${overdueProjectsQuery}`,
      (err, results) => {
        if (err) {
          console.error('Error fetching project stats:', err);
          logActivity('ERROR', 'project', 'Error fetching project stats', 'System');
          return res.status(500).json({ error: 'Failed to fetch project stats' });
        }
  
        const stats = {
          total_projects: results[0][0].total_projects,
          completed_projects: results[1][0].completed_projects,
          ongoing_projects: results[2][0].ongoing_projects,
          overdue_projects: results[3][0].overdue_projects,
        };

        logActivity('READ', 'project', 'Fetched project stats', 'Admin');
  
        res.status(200).json(stats);
      }
    );
  });


  cron.schedule('0 0 * * *', () => {
    console.log('Running daily project status update...');
  
    
    const updateToOngoingQuery = `
      UPDATE project 
      SET status = 'ongoing' 
      WHERE status = 'pending' AND start_date = CURDATE()
    `;
  
    connection.query(updateToOngoingQuery, (err, result) => {
      if (err) {
        console.error('Error updating projects to "ongoing":', err);
      } else {
        console.log(`Projects updated to "ongoing": ${result.affectedRows}`);
        logActivity(
          'CRON_JOB',
          'project',
          `Updated ${result.affectedRows} projects to "ongoing" status`,
          'System (Cron Job)'
        );
      }
    });
  
   
    const updateToOverdueQuery = `
      UPDATE project 
      SET status = 'overdue' 
      WHERE status = 'ongoing' AND end_date < CURDATE()
    `;
  
    connection.query(updateToOverdueQuery, (err, result) => {
      if (err) {
        console.error('Error updating projects to "overdue":', err);
      } else {
        console.log(`Projects updated to "overdue": ${result.affectedRows}`);
        logActivity(
          'CRON_JOB',
          'project',
          `Updated ${result.affectedRows} projects to "overdue" status`,
          'System (Cron Job)'
        );
      }
    });
  });


  /**   
   * @swagger
   * /create_staff:
   *   post:
   *     summary: Create a new staff member
   *     description: Create a new staff member with the provided details
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               first_name:
   *                 type: string
   *                 description: First name of the staff member
   *                 example: John
   *               last_name:
   *                 type: string
   *                 description: Last name of the staff member
   *                 example: Doe
   *               email:
   *                 type: string
   *                 description: Email of the staff member
   *                 example: john.doe@example.com
   *               address:
   *                 type: string
   *                 description: Address of the staff member
   *                 example: 123 Main St
   *               phone:
   *                 type: string
   *                 description: Phone number of the staff member
   *                 example: +1234567890
   *               job_role:
   *                 type: string
   *                 description: Job role of the staff member
   *                 example: Software Engineer
   *               salary:
   *                 type: number
   *                 description: Salary of the staff member
   *                 example: 50000
   *               working_days:
   *                 type: array
   *                 items:
   *                   type: string
   *                 description: Working days of the staff member
   *                 example: ["Monday", "Tuesday"]
   *               skills:
   *                 type: array
   *                 items:
   *                   type: string
   *                 description: Skills of the staff member
   *                 example: ["JavaScript", "Node.js"]
   *     responses:
   *       201:
   *         description: Staff created successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: Staff created successfully
   *                 staffId:
   *                   type: integer
   *                   description: ID of the created staff member
   *                   example: 1
   *       400:
   *         description: Bad request
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: First Name, Last Name, and Email are required
   *       500:
   *         description: Failed to create staff
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to create staff
   */
  app.post('/create_staff', (req, res) => {
    const {
      first_name,
      last_name,
      email,
      address,
      phone,
      job_role,
      salary,
      working_days,
      skills,
    } = req.body;
  
    if (!first_name || !last_name || !email) {
      return res.status(400).json({ error: 'First Name, Last Name, and Email are required' });
    }
  
    const workingDaysJson = JSON.stringify(working_days || []);
    const skillsJson = JSON.stringify(skills || []);
    const documentIdsJson = JSON.stringify([]);
  
    const query = `
      INSERT INTO staffs (
        first_name, last_name, email, address, phone, job_role, salary, working_days, 
        skills, document_ids
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
  
    const values = [
      first_name,
      last_name,
      email,
      address,
      phone,
      job_role,
      salary,
      workingDaysJson,
      skillsJson,
      documentIdsJson,
    ];
  
    connection.query(query, values, (err, result) => {
      if (err) {
        console.error('Error creating staff:', err);
        return res.status(500).json({ error: 'Failed to create staff' });
      }

      logActivity(
        'INSERT',
        'staffs',
        `Created a new staff with ID ${result.insertId} and email ${email}`,
        'Admin'
      );
  
      res.status(201).json({ message: 'Staff created successfully', staffId: result.insertId });
    });
  });

  /**   
   * @swagger
   * /staffs:
   *   get:
   *     summary: Get all staff members
   *     description: Retrieve a list of all staff members
   *     responses:
   *       200:
   *         description: A list of staff members
   *         content:
   *           application/json:
   *             schema:
   *               type: array
   *               items:
   *                 type: object
   *                 properties:
   *                   id:
   *                     type: integer
   *                     description: Staff ID
   *                     example: 1
   *                   first_name:
   *                     type: string
   *                     description: First name of the staff member
   *                     example: John
   *                   last_name:
   *                     type: string
   *                     description: Last name of the staff member
   *                     example: Doe
   *                   email:
   *                     type: string
   *                     description: Email of the staff member
   *                     example: john.doe@example.com
   *                   address:
   *                     type: string
   *                     description: Address of the staff member
   *                     example: 123 Main St
   *                   phone:
   *                     type: string
   *                     description: Phone number of the staff member
   *                     example: +1234567890
   *                   job_role:
   *                     type: string
   *                     description: Job role of the staff member
   *                     example: Software Engineer
   *                   salary:
   *                     type: number
   *                     description: Salary of the staff member
   *                     example: 50000
   *                   working_days:
   *                     type: array
   *                     items:
   *                       type: string
   *                     description: Working days of the staff member
   *                     example: ["Monday", "Tuesday"]
   *                   skills:
   *                     type: array
   *                     items:
   *                       type: string
   *                     description: Skills of the staff member
   *                     example: ["JavaScript", "Node.js"]
   *                   document_ids:
   *                     type: array
   *                     items:
   *                       type: integer
   *                     description: IDs of documents associated with the staff member
   *                     example: [1, 2, 3]
   *       500:
   *         description: Failed to fetch staff members
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to fetch staff members
   */

  app.get('/staffs', (req, res) => {
    const query = 'SELECT * FROM staffs ORDER BY created_at DESC';
  
    connection.query(query, (err, results) => {
      if (err) {
        console.error('Error fetching staff:', err);
        logActivity('ERROR', 'staffs', 'Error fetching all staff', 'System');
        return res.status(500).json({ error: 'Failed to fetch staff' });
      }
  
      const staffWithParsedData = results.map(staff => ({
        ...staff,
        working_days: JSON.parse(staff.working_days || '[]'),
        skills: JSON.parse(staff.skills || '[]'),
        document_ids: JSON.parse(staff.document_ids || '[]')
      }));

      logActivity('READ', 'staffs', 'Fetched all staff', 'Admin');
      res.status(200).json(staffWithParsedData);
    });
  });
  /**   
   * @swagger
   * /staffs/{staffId}:
   *   get:
   *     summary: Get a specific staff member
   *     description: Retrieve details of a specific staff member by ID
   *     parameters:
   *       - in: path
   *         name: staffId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the staff member to retrieve
   *     responses:
   *       200:
   *         description: Staff member fetched successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 id:
   *                   type: integer
   *                   description: Staff ID
   *                   example: 1
   *                 first_name:
   *                   type: string
   *                   description: First name of the staff member
   *                   example: John
   *                 last_name:
   *                   type: string
   *                   description: Last name of the staff member
   *                   example: Doe
   *                 email:
   *                   type: string
   *                   description: Email of the staff member
   *                   example: john.doe@example.com
   *                 address:
   *                   type: string
   *                   description: Address of the staff member
   *                   example: 123 Main St
   *                 phone:
   *                   type: string
   *                   description: Phone number of the staff member
   *                   example: +1234567890
   *                 job_role:
   *                   type: string
   *                   description: Job role of the staff member
   *                   example: Software Engineer
   *                 salary:
   *                   type: number
   *                   description: Salary of the staff member
   *                   example: 50000
   *                 working_days:
   *                   type: array
   *                   items:
   *                     type: string
   *                   description: Working days of the staff member
   *                   example: ["Monday", "Tuesday"]
   *                 skills:
   *                   type: array
   *                   items:
   *                     type: string
   *                   description: Skills of the staff member
   *                   example: ["JavaScript", "Node.js"]
   *                 document_ids:
   *                   type: array
   *                   items:
   *                     type: integer
   *                   description: IDs of documents associated with the staff member
   *                   example: [1, 2, 3]
   *       404:
   *         description: Staff member not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Staff not found
   *       500:
   *         description: Failed to fetch staff member
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to fetch staff member
   */

  app.get('/staffs/:staffId', (req, res) => {
    const { staffId } = req.params;
  
    const query = 'SELECT * FROM staffs WHERE id = ?';
  
    connection.query(query, [staffId], (err, results) => {
      if (err) {
        console.error('Error fetching staff:', err);
        logActivity('ERROR', 'staffs', `Error fetching staff with ID ${staffId}`, 'System');
        return res.status(500).json({ error: 'Failed to fetch staff' });
      }
  
      if (results.length === 0) {
        logActivity('FAILED', 'staffs', `Staff not found with ID ${staffId}`, 'Admin');
        return res.status(404).json({ error: 'Staff not found' });
      }
  
      const staff = results[0];
      const staffWithParsedData = {
        ...staff,
        working_days: JSON.parse(staff.working_days || '[]'),
        skills: JSON.parse(staff.skills || '[]'),
        document_ids: JSON.parse(staff.document_ids || '[]')
      };

      logActivity('READ', 'staffs', `Fetched staff with ID ${staffId}`, 'Admin');
      res.status(200).json(staffWithParsedData);
    });
  });

    /**   
     * @swagger
     * /staffs/{staffId}:
     *   patch:
     *     summary: Update a specific staff member
     *     description: Update a specific staff member's details
     *     parameters:
     *       - in: path
     *         name: staffId
     *         required: true
     *         schema:
     *           type: integer
     *         description: ID of the staff member to update
     *     requestBody:
     *       required: true
     *       content:
     *         application/json:
     *           schema:
     *             type: object
     *             properties:
     *               first_name:
     *                 type: string
     *                 description: First name of the staff member
     *               last_name:
     *                 type: string
     *                 description: Last name of the staff member
     *               email:
     *                 type: string
     *                 description: Email of the staff member
     *               address:
     *                 type: string
     *                 description: Address of the staff member
     *               phone:
     *                 type: string
     *                 description: Phone number of the staff member
     *               job_role:
     *                 type: string
     *                 description: Job role of the staff member
     *               salary:
     *                 type: number
     *                 description: Salary of the staff member
     *               working_days:
     *                 type: array
     *                 items:
     *                   type: string
     *                 description: Working days of the staff member
     *               skills:
     *                 type: array
     *                 items:
     *                   type: string
     *                 description: Skills of the staff member
     *     responses:
     *       200:
     *         description: Staff updated successfully
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 message:
     *                   type: string
     *                   description: Success message
     *                   example: Staff updated successfully
     *       400:
     *         description: Bad request
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 error:
     *                   type: string
     *                   description: Error message
     *                   example: No fields to update
     *       404:
     *         description: Staff not found
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 error:
     *                   type: string
     *                   description: Error message
     *                   example: Staff not found
     *       500:
     *         description: Failed to update staff
     *         content:
     *           application/json:
     *             schema:
     *               type: object
     *               properties:
     *                 error:
     *                   type: string
     *                   description: Error message
     *                   example: Failed to update staff
     */

  app.patch('/staffs/:staffId', (req, res) => {
    const { staffId } = req.params;
    const {
      first_name,
      last_name,
      email,
      address,
      phone,
      job_role,
      salary,
      working_days,
      skills,
    } = req.body;
  
    const updateFields = [];
    const updateValues = [];
  
    if (first_name) {
      updateFields.push('first_name = ?');
      updateValues.push(first_name);
    }
    if (last_name) {
      updateFields.push('last_name = ?');
      updateValues.push(last_name);
    }
    if (email) {
      updateFields.push('email = ?');
      updateValues.push(email);
    }
    if (address) {
      updateFields.push('address = ?');
      updateValues.push(address);
    }
    if (phone) {
      updateFields.push('phone = ?');
      updateValues.push(phone);
    }
    if (job_role) {
      updateFields.push('job_role = ?');
      updateValues.push(job_role);
    }
    if (salary) {
      updateFields.push('salary = ?');
      updateValues.push(salary);
    }
    if (working_days) {
      updateFields.push('working_days = ?');
      updateValues.push(JSON.stringify(working_days));
    }
    if (skills) {
      updateFields.push('skills = ?');
      updateValues.push(JSON.stringify(skills));
    }
  
    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }
  
    const query = `UPDATE staffs SET ${updateFields.join(', ')} WHERE id = ?`;
    updateValues.push(staffId);
  
    connection.query(query, updateValues, (err, result) => {
      if (err) {
        console.error('Error updating staff:', err);
        logActivity('ERROR', 'staffs', `Error updating staff with ID ${staffId}`, 'Admin');
        return res.status(500).json({ error: 'Failed to update staff' });
      }
  
      if (result.affectedRows === 0) {
        logActivity('FAILED', 'staffs', `Staff not found with ID ${staffId}`, 'Admin');
        return res.status(404).json({ error: 'Staff not found' });
      }

      logActivity('UPDATE', 'staffs', `Updated staff with ID ${staffId}`, 'Admin');
      res.status(200).json({ message: 'Staff updated successfully' });
    });
  });


  /**   
   * @swagger
   * /upload_document/{staffId}:
   *   post:
   *     summary: Upload a document for a specific staff member
   *     description: Upload a document for a specific staff member
   *     parameters:
   *       - in: path
   *         name: staffId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the staff member
   *     requestBody:
   *       required: true
   *       content:
   *         multipart/form-data:
   *           schema:
   *             type: object
   *             properties:
   *               document:
   *                 type: string
   *                 format: binary
   *                 description: The document file to upload
   *     responses:
   *       201:
   *         description: Document uploaded successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: Document uploaded successfully
   *                 documentId:
   *                   type: integer
   *                   description: ID of the uploaded document
   *                   example: 1
   *       400:
   *         description: Bad request
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Document file is required
   *       500:
   *         description: Failed to upload document
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to upload document
   */

  app.post('/upload_document/:staffId', upload.single('document'), (req, res) => {
    const { staffId } = req.params;
    const documentName = req.file.originalname;
    const documentPath = req.file.path;
  
    const query = `
      INSERT INTO staff_documents (staff_id, document_name, document_path) 
      VALUES (?, ?, ?)
    `;
  
    connection.query(query, [staffId, documentName, documentPath], (err, result) => {
      if (err) {
        console.error('Error uploading document:', err);
        logActivity('ERROR', 'staff_documents', `Error uploading document for staff ID ${staffId}`, 'Admin');
        return res.status(500).json({ error: 'Failed to upload document' });
      }
  
      const updateStaffQuery = `
        UPDATE staffs 
        SET no_of_documents_uploaded = no_of_documents_uploaded + 1, 
            document_ids = JSON_ARRAY_APPEND(document_ids, '$', ?) 
        WHERE id = ?
      `;
  
      connection.query(updateStaffQuery, [result.insertId, staffId], (updateErr) => {
        if (updateErr) {
          console.error('Error updating staff document info:', updateErr);
          logActivity('ERROR', 'staffs', `Error updating document info for staff ID ${staffId}`, 'Admin');
          return res.status(500).json({ error: 'Failed to update staff document info' });
        }

        logActivity('INSERT', 'staff_documents', `Uploaded document for staff ID ${staffId}`, 'Admin');
        res.status(201).json({ message: 'Document uploaded successfully', documentId: result.insertId });
      });
    });
  });


  /**   
   * @swagger
   * /staffs/{staffId}/documents:
   *   get:
   *     summary: Get all documents for a specific staff member
   *     description: Retrieve all documents associated with a specific staff member
   *     parameters:
   *       - in: path
   *         name: staffId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the staff member
   *     responses:
   *       200:
   *         description: A list of documents for the staff member
   *         content:
   *           application/json:
   *             schema:
   *               type: array
   *               items:
   *                 type: object
   *                 properties:
   *                   id:
   *                     type: integer
   *                     description: Document ID
   *                     example: 1
   *                   staff_id:
   *                     type: integer
   *                     description: ID of the staff member
   *                     example: 123
   *                   document_name:
   *                     type: string
   *                     description: Name of the document
   *                     example: Resume.pdf
   *                   document_path:
   *                     type: string
   *                     description: Path to the document
   *                     example: /uploads/documents/Resume.pdf
   *                   uploaded_at:
   *                     type: string
   *                     format: date-time
   *                     description: Timestamp of when the document was uploaded
   *                     example: 2023-10-01T12:00:00Z
   *       404:
   *         description: Staff not found or no documents available
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Staff not found or no documents available
   *       500:
   *         description: Failed to fetch documents
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to fetch documents
   */

  app.get('/staffs/:staffId/documents', (req, res) => {
    const { staffId } = req.params;
  
    const query = 'SELECT * FROM staff_documents WHERE staff_id = ? ORDER BY uploaded_at DESC';
  
    connection.query(query, [staffId], (err, results) => {
      if (err) {
        console.error('Error fetching documents:', err);
        logActivity('ERROR', 'staff_documents', `Error fetching documents for staff ID ${staffId}`, 'Admin');
        return res.status(500).json({ error: 'Failed to fetch documents' });
      }

      logActivity('READ', 'staff_documents', `Fetched documents for staff ID ${staffId}`, 'Admin');
      res.status(200).json(results);
    });
  });

  /**   
   * @swagger
   * /staffs/{staffId}/documents/{documentId}:
   *   get:
   *     summary: Get a specific document for a specific staff member
   *     description: Retrieve a specific document associated with a specific staff member
   *     parameters:
   *       - in: path
   *         name: staffId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the staff member
   *       - in: path
   *         name: documentId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the document to retrieve
   *     responses:
   *       200:
   *         description: Document fetched successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 id:
   *                   type: integer
   *                   description: Document ID
   *                   example: 1
   *                 staff_id:
   *                   type: integer
   *                   description: ID of the staff member
   *                   example: 123
   *                 document_name:
   *                   type: string
   *                   description: Name of the document
   *                   example: Resume.pdf
   *                 document_path:
   *                   type: string
   *                   description: Path to the document
   *                   example: /uploads/documents/Resume.pdf
   *                 uploaded_at:
   *                   type: string
   *                   format: date-time
   *                   description: Timestamp of when the document was uploaded
   *                   example: 2023-10-01T12:00:00Z
   *       404:
   *         description: Document not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Document not found
   *       500:
   *         description: Failed to fetch document
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to fetch document
   */

  app.get('/staffs/:staffId/documents/:documentId', (req, res) => {
    const { staffId, documentId } = req.params;
  
    const query = 'SELECT * FROM staff_documents WHERE id = ? AND staff_id = ?';
  
    connection.query(query, [documentId, staffId], (err, results) => {
      if (err) {
        console.error('Error fetching document:', err);
        logActivity('ERROR', 'staff_documents', `Error fetching document ID ${documentId} for staff ID ${staffId}`, 'Admin');
        return res.status(500).json({ error: 'Failed to fetch document' });
      }
  
      if (results.length === 0) {
        logActivity('FAILED', 'staff_documents', `Document not found with ID ${documentId} for staff ID ${staffId}`, 'Admin');
        return res.status(404).json({ error: 'Document not found' });
      }

      logActivity('READ', 'staff_documents', `Fetched document ID ${documentId} for staff ID ${staffId}`, 'Admin');
      res.status(200).json(results[0]);
    });
  });

  /**   
   * @swagger
   * /staffs/{staffId}/documents/{documentId}:
   *   patch:
   *     summary: Update a document for a specific staff member
   *     description: Update a document associated with a specific staff member
   *     parameters:
   *       - in: path
   *         name: staffId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the staff member
   *       - in: path
   *         name: documentId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the document to update
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               document_name:
   *                 type: string
   *                 description: New name for the document
   *                 example: Updated Document Name
   *     responses:
   *       200:
   *         description: Document updated successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: Document updated successfully
   *       400:
   *         description: Bad request
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Document name is required
   *       404:
   *         description: Document not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Document not found
   *       500:
   *         description: Failed to update document
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to update document
   */

  app.patch('/staffs/:staffId/documents/:documentId', (req, res) => {
    const { staffId, documentId } = req.params;
    const { document_name } = req.body;
  
    if (!document_name) {
      return res.status(400).json({ error: 'Document name is required' });
    }
  
    const query = 'UPDATE staff_documents SET document_name = ? WHERE id = ? AND staff_id = ?';
  
    connection.query(query, [document_name, documentId, staffId], (err, result) => {
      if (err) {
        console.error('Error updating document:', err);
        logActivity('ERROR', 'staff_documents', `Error updating document ID ${documentId} for staff ID ${staffId}`, 'Admin');
        return res.status(500).json({ error: 'Failed to update document' });
      }
  
      if (result.affectedRows === 0) {
        logActivity('FAILED', 'staff_documents', `Document not found with ID ${documentId} for staff ID ${staffId}`, 'Admin');
        return res.status(404).json({ error: 'Document not found' });
      }

      logActivity('UPDATE', 'staff_documents', `Updated document ID ${documentId} for staff ID ${staffId}`, 'Admin');
      res.status(200).json({ message: 'Document updated successfully' });
    });
  });


  /**   
   * @swagger
   * /staffs/{staffId}/documents/{documentId}:
   *   delete:
   *     summary: Delete a document for a specific staff member
   *     description: Delete a document associated with a specific staff member
   *     parameters:
   *       - in: path
   *         name: staffId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the staff member
   *       - in: path
   *         name: documentId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the document to delete
   *     responses:
   *       200:
   *         description: Document deleted successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: Document deleted successfully
   *       404:
   *         description: Document not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Document not found
   *       500:
   *         description: Failed to delete document
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to delete document
   */

  app.delete('/staffs/:staffId/documents/:documentId', (req, res) => {
    const { staffId, documentId } = req.params;
  
    const updateStaffQuery = `
      UPDATE staffs 
      SET no_of_documents_uploaded = no_of_documents_uploaded - 1,
          document_ids = JSON_REMOVE(
            document_ids, 
            JSON_UNQUOTE(
              JSON_SEARCH(document_ids, 'one', ?)
            )
          )
      WHERE id = ? AND JSON_CONTAINS(document_ids, JSON_ARRAY(?))
    `;
  
    connection.query(updateStaffQuery, [documentId, staffId, documentId], (updateErr, updateResult) => {
      if (updateErr) {
        console.error('Error updating staff document references:', updateErr);
        logActivity('ERROR', 'staffs', `Error updating document references for staff ID ${staffId}`, 'Admin');
        return res.status(500).json({ error: 'Failed to update staff document references' });
      }
  
      const deleteQuery = 'DELETE FROM staff_documents WHERE id = ? AND staff_id = ?';
      
      connection.query(deleteQuery, [documentId, staffId], (deleteErr, deleteResult) => {
        if (deleteErr) {
          console.error('Error deleting document:', deleteErr);
          logActivity('ERROR', 'staff_documents', `Error deleting document ID ${documentId} for staff ID ${staffId}`, 'Admin');
          return res.status(500).json({ error: 'Failed to delete document' });
        }
  
        if (deleteResult.affectedRows === 0) {
          logActivity('FAILED', 'staff_documents', `Document not found with ID ${documentId} for staff ID ${staffId}`, 'Admin');
          return res.status(404).json({ error: 'Document not found' });
        }

        logActivity('DELETE', 'staff_documents', `Deleted document ID ${documentId} for staff ID ${staffId}`, 'Admin');
        res.status(200).json({ message: 'Document deleted successfully' });
      });
    });
  });

  /**   
   * @swagger
   * /staffs/{staffId}/documents/{documentId}/download:
   *   get:
   *     summary: Download a document for a specific staff member
   *     description: Download a document associated with a specific staff member
   *     parameters:
   *       - in: path
   *         name: staffId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the staff member
   *       - in: path
   *         name: documentId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the document to download
   *     responses:
   *       200:
   *         description: Document downloaded successfully
   *         content:
   *           application/octet-stream:
   *             schema:
   *               type: string
   *               format: binary
   *       404:
   *         description: Document not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Document not found
   *       500:
   *         description: Failed to download document
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to download document
   */

  app.get('/staffs/:staffId/documents/:documentId/download', (req, res) => {
    const { staffId, documentId } = req.params;
  
    const query = 'SELECT document_path FROM staff_documents WHERE id = ? AND staff_id = ?';
  
    connection.query(query, [documentId, staffId], (err, results) => {
      if (err || results.length === 0) {
        logActivity('FAILED', 'staff_documents', `Document not found with ID ${documentId} for staff ID ${staffId}`, 'Admin');
        return res.status(404).json({ error: 'Document not found' });
      }
  
      const filePath = results[0].document_path;
      logActivity('DOWNLOAD', 'staff_documents', `Downloaded document ID ${documentId} for staff ID ${staffId}`, 'Admin');
      res.download(filePath);
    });
  });

  app.post('/expense', (req, res) => {
    const { amount, expense_category, description } = req.body;
  
    if (!amount || !expense_category || !description) {
      return res.status(400).json({ error: 'Amount, Expense Category, and Description are required' });
    }
  
    const query = `
      INSERT INTO expense (expense_description, amount, expense_category) 
      VALUES (?, ?, ?)
    `;
  
    const values = [description, amount, expense_category];
  
    connection.query(query, values, (err, result) => {
      if (err) {
        console.error('Error creating expense:', err);
        logActivity('ERROR', 'expense', `Error creating expense: ${description}`, 'Admin');
        return res.status(500).json({ error: 'Failed to create expense' });
      }

      logActivity('INSERT', 'expense', `Created expense with ID ${result.insertId}`, 'Admin');
      res.status(201).json({ message: 'Expense created successfully', expenseId: result.insertId });
    });
  });


  /**   
   * @swagger
   * /expense:
   *   get:
   *     summary: Get all expense records
   *     description: Retrieve all expense records
   *     responses:
   *       200:
   *         description: A list of expense records
   *         content:
   *           application/json:
   *             schema:
   *               type: array
   *               items:
   *                 type: object
   *                 properties:
   *                   id:
   *                     type: integer
   *                     description: Expense ID
   *                     example: 1
   *                   expense_description:
   *                     type: string
   *                     description: Description of the expense
   *                     example: Purchased office chairs
   *                   amount:
   *                     type: number
   *                     description: Amount of the expense
   *                     example: 500.00
   *                   expense_category:
   *                     type: string
   *                     description: Category of the expense
   *                     example: Office Supplies
   *                   status:
   *                     type: string
   *                     description: Status of the expense
   *                     example: Approved
   *                   created_at:
   *                     type: string
   *                     format: date-time
   *                     description: Timestamp of when the expense was created
   *                     example: 2023-10-01T12:00:00Z
   *       500:
   *         description: Failed to fetch expenses
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to fetch expenses
   */

  app.get('/expense', (req, res) => {
    const query = 'SELECT * FROM expense ORDER BY created_at DESC';
  
    connection.query(query, (err, results) => {
      if (err) {
        console.error('Error fetching expenses:', err);
        logActivity('ERROR', 'expense', 'Error fetching all expenses', 'System');
        return res.status(500).json({ error: 'Failed to fetch expenses' });
      }

      logActivity('READ', 'expense', 'Fetched all expenses', 'Admin');
      res.status(200).json(results);
    });
  });


  /**   
   * @swagger
   * /expense/{expenseId}:
   *   get:
   *     summary: Get an expense record by ID
   *     description: Retrieve an expense record by its ID
   *     parameters:
   *       - in: path
   *         name: expenseId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the expense record to fetch
   *     responses:
   *       200:
   *         description: Expense fetched successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 id:
   *                   type: integer
   *                   description: Expense ID
   *                   example: 1
   *                 expense_description:
   *                   type: string
   *                   description: Description of the expense
   *                   example: Purchased office chairs
   *                 amount:
   *                   type: number
   *                   description: Amount of the expense
   *                   example: 500.00
   *                 expense_category:
   *                   type: string
   *                   description: Category of the expense
   *                   example: Office Supplies
   *                 status:
   *                   type: string
   *                   description: Status of the expense
   *                   example: Approved
   *                 created_at:
   *                   type: string
   *                   format: date-time
   *                   description: Timestamp of when the expense was created
   *                   example: 2023-10-01T12:00:00Z
   *       404:
   *         description: Expense not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Expense not found
   *       500:
   *         description: Failed to fetch expense
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to fetch expense
   */
  app.get('/expense/:expenseId', (req, res) => {
    const { expenseId } = req.params;
  
    const query = 'SELECT * FROM expense WHERE id = ?';
  
    connection.query(query, [expenseId], (err, results) => {
      if (err) {
        console.error('Error fetching expense:', err);
        logActivity('ERROR', 'expense', `Error fetching expense with ID ${expenseId}`, 'Admin');
        return res.status(500).json({ error: 'Failed to fetch expense' });
      }
  
      if (results.length === 0) {
        logActivity('FAILED', 'expense', `Expense not found with ID ${expenseId}`, 'Admin');
        return res.status(404).json({ error: 'Expense not found' });
      }

      logActivity('READ', 'expense', `Fetched expense with ID ${expenseId}`, 'Admin');
      res.status(200).json(results[0]);
    });
  });

  /**   
   * @swagger
   * /expense/{expenseId}:
   *   patch:
   *     summary: Update an expense record
   *     description: Update an expense record by its ID
   *     parameters:
   *       - in: path
   *         name: expenseId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the expense record to update
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               amount:
   *                 type: number
   *                 description: Amount of the expense
   *                 example: 500.00
   *               expense_category:
   *                 type: string
   *                 description: Category of the expense
   *                 example: Office Supplies
   *               description:
   *                 type: string
   *                 description: Description of the expense
   *                 example: Purchased office chairs
   *               status:
   *                 type: string
   *                 description: Status of the expense
   *                 example: Approved
   *     responses:
   *       200:
   *         description: Expense updated successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: Expense updated successfully
   *       400:
   *         description: Bad request
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: No fields to update
   *       404:
   *         description: Expense not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Expense not found
   *       500:
   *         description: Failed to update expense
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to update expense
   */
  app.patch('/expense/:expenseId', (req, res) => {
    const { expenseId } = req.params;
    const { amount, expense_category, description, status } = req.body;
  
    const updateFields = [];
    const updateValues = [];
  
    if (amount) {
      updateFields.push('amount = ?');
      updateValues.push(amount);
    }
    if (expense_category) {
      updateFields.push('expense_category = ?');
      updateValues.push(expense_category);
    }
    if (description) {
      updateFields.push('expense_description = ?');
      updateValues.push(description);
    }
    if (status) {
      updateFields.push('status = ?');
      updateValues.push(status);
    }
  
    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }
  
    const query = `UPDATE expense SET ${updateFields.join(', ')} WHERE id = ?`;
    updateValues.push(expenseId);
  
    connection.query(query, updateValues, (err, result) => {
      if (err) {
        console.error('Error updating expense:', err);
        logActivity('ERROR', 'expense', `Error updating expense with ID ${expenseId}`, 'Admin');
        return res.status(500).json({ error: 'Failed to update expense' });
      }
  
      if (result.affectedRows === 0) {
        logActivity('FAILED', 'expense', `Expense not found with ID ${expenseId}`, 'Admin');
        return res.status(404).json({ error: 'Expense not found' });
      }

      logActivity('UPDATE', 'expense', `Updated expense with ID ${expenseId}`, 'Admin');
      res.status(200).json({ message: 'Expense updated successfully' });
    });
  });


  /**   
   * @swagger
   * /expense/{expenseId}:
   *   delete:
   *     summary: Delete an expense record
   *     description: Delete an expense record by its ID
   *     parameters:
   *       - in: path
   *         name: expenseId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the expense record to delete
   *     responses:
   *       200:
   *         description: Expense deleted successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: Expense deleted successfully
   *       404:
   *         description: Expense not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Expense not found
   *       500:
   *         description: Failed to delete expense
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to delete expense
   */
  app.delete('/expense/:expenseId', (req, res) => {
    const { expenseId } = req.params;
  
    const query = 'DELETE FROM expense WHERE id = ?';
  
    connection.query(query, [expenseId], (err, result) => {
      if (err) {
        console.error('Error deleting expense:', err);
        logActivity('ERROR', 'expense', `Error deleting expense with ID ${expenseId}`, 'Admin');
        return res.status(500).json({ error: 'Failed to delete expense' });
      }
  
      if (result.affectedRows === 0) {
        logActivity('FAILED', 'expense', `Expense not found with ID ${expenseId}`, 'Admin');
        return res.status(404).json({ error: 'Expense not found' });
      }

      logActivity('DELETE', 'expense', `Deleted expense with ID ${expenseId}`, 'Admin');
      res.status(200).json({ message: 'Expense deleted successfully' });
    });
  });


  /**   
   * @swagger
   * /revenue:  
   *   post:
   *     summary: Create a new revenue record
   *     description: Add a new revenue record to the database
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               customer_name:
   *                 type: string
   *                 description: Name of the customer
   *                 example: John Doe
   *               service_type:
   *                 type: string
   *                 description: Type of service provided
   *                 example: Consulting
   *               amount:
   *                 type: number
   *                 description: Amount of revenue
   *                 example: 1000.00
   *               revenue_description:
   *                 type: string
   *                 description: Description of the revenue
   *                 example: Monthly consulting fee
   *               method_of_payment:
   *                 type: string
   *                 description: Method of payment
   *                 example: Credit Card
   *     responses:
   *       201:
   *         description: Revenue created successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: Revenue created successfully
   *                 revenueId:
   *                   type: integer
   *                   description: ID of the created revenue record
   *                   example: 1
   *       400:
   *         description: Bad request
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Customer Name, Service Type, Amount, and Method of Payment are required
   *       500:
   *         description: Failed to create revenue
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to create revenue
   */
  app.post('/revenue', (req, res) => {
    const { customer_name, service_type, amount, revenue_description, method_of_payment } = req.body;
  
    
    if (!customer_name || !service_type || !amount || !method_of_payment) {
      return res.status(400).json({ error: 'Customer Name, Service Type, Amount, and Method of Payment are required' });
    }
  
    const query = `
      INSERT INTO revenue (customer_name, service_type, amount, revenue_description, method_of_payment) 
      VALUES (?, ?, ?, ?, ?)
    `;
  
    const values = [customer_name, service_type, amount, revenue_description, method_of_payment];
  
    connection.query(query, values, (err, result) => {
      if (err) {
        console.error('Error creating revenue:', err);
        return res.status(500).json({ error: 'Failed to create revenue' });
      }

      logActivity(
        'INSERT',
        'revenue',
        `Added a new revenue record with ID ${result.insertId}`,
        'Admin'
      );
  
      res.status(201).json({ message: 'Revenue created successfully', revenueId: result.insertId });
    });
  });
  /**
   * @swagger
   * /revenue:
   *   get:
   *     summary: Get all revenue records
   *     description: Retrieve a list of all revenue records
   *     responses:
   *       200:
   *         description: A list of revenue records
   *         content:
   *           application/json:
   *             schema:
   *               type: array
   *               items:
   *                 type: object
   *                 properties:
   *                   id:
   *                     type: integer
   *                     description: Revenue ID
   *                     example: 1
   *                   customer_name:
   *                     type: string
   *                     description: Name of the customer
   *                     example: John Doe
   *                   service_type:
   *                     type: string
   *                     description: Type of service provided
   *                     example: Consulting
   *                   amount:
   *                     type: number
   *                     description: Amount of revenue
   *                     example: 1000.00
   *                   revenue_description:
   *                     type: string
   *                     description: Description of the revenue
   *                     example: Monthly consulting fee
   *                   method_of_payment:
   *                     type: string
   *                     description: Method of payment
   *                     example: Credit Card
   *                   status:
   *                     type: string
   *                     description: Status of the revenue
   *                     example: Paid
   *                   created_at:
   *                     type: string
   *                     format: date-time
   *                     description: Timestamp of when the revenue was created
   *                     example: 2023-10-01T12:00:00Z
   *       500:
   *         description: Failed to fetch revenues
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to fetch revenues
   */

  app.get('/revenue', (req, res) => {
    const query = 'SELECT * FROM revenue ORDER BY created_at DESC';
  
    connection.query(query, (err, results) => {
      if (err) {
        console.error('Error fetching revenues:', err);
        logActivity('ERROR', 'revenue', 'Error fetching all revenues', 'System');
        return res.status(500).json({ error: 'Failed to fetch revenues' });
      }

      logActivity('READ', 'revenue', 'Fetched all revenues', 'Admin');
      res.status(200).json(results);
    });
  });
/**
 * @swagger
 * /revenue/{revenueId}:
 *   get:
 *     summary: Get a revenue record by ID
 *     description: Fetch a revenue record by its ID
 *     parameters:
 *       - in: path
 *         name: revenueId
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the revenue record to fetch
 *     responses:
 *       200:
 *         description: Revenue fetched successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   description: Revenue ID
 *                   example: 1
 *                 customer_name:
 *                   type: string
 *                   description: Name of the customer
 *                   example: John Doe
 *                 service_type:
 *                   type: string
 *                   description: Type of service provided
 *                   example: Consulting
 *                 amount:
 *                   type: number
 *                   description: Amount of revenue
 *                   example: 1000.00
 *                 revenue_description:
 *                   type: string
 *                   description: Description of the revenue
 *                   example: Monthly consulting fee
 *                 method_of_payment:
 *                   type: string
 *                   description: Method of payment
 *                   example: Credit Card
 *                 status:
 *                   type: string
 *                   description: Status of the revenue
 *                   example: Paid
 *                 created_at:
 *                   type: string
 *                   format: date-time
 *                   description: Timestamp of when the revenue was created
 *                   example: 2023-10-01T12:00:00Z
 *       400:
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Revenue not found
 *       404:
 *         description: Revenue not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Revenue not found
 *       500:
 *         description: Failed to fetch revenue
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Failed to fetch revenue
 */

  app.get('/revenue/:revenueId', (req, res) => {
    const { revenueId } = req.params;
  
    const query = 'SELECT * FROM revenue WHERE id = ?';
  
    connection.query(query, [revenueId], (err, results) => {
      if (err) {
        console.error('Error fetching revenue:', err);
        logActivity('ERROR', 'revenue', `Error fetching revenue with ID ${revenueId}`, 'Admin');
        return res.status(500).json({ error: 'Failed to fetch revenue' });
      }
  
      if (results.length === 0) {
        logActivity('FAILED', 'revenue', `Revenue not found with ID ${revenueId}`, 'Admin');
        return res.status(404).json({ error: 'Revenue not found' });
      }

      logActivity('READ', 'revenue', `Fetched revenue with ID ${revenueId}`, 'Admin');
      res.status(200).json(results[0]);
    });
  });

  /** 
   * @swagger
   * /revenue/{revenueId}:
   *   patch:
   *     summary: Update a revenue record
   *     description: Update a revenue record by its ID
   *     parameters:
   *       - in: path
   *         name: revenueId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the revenue record to update
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             properties:
   *               customer_name:
   *                 type: string
   *                 description: Name of the customer
   *               service_type:
   *                 type: string
   *                 description: Type of service provided
   *               amount:
   *                 type: number
   *                 description: Amount of revenue
   *               revenue_description:
   *                 type: string
   *                 description: Description of the revenue
   *               method_of_payment:
   *                 type: string
   *                 description: Method of payment
   *               status:
   *                 type: string
   *                 description: Status of the revenue
   *     responses:
   *       200:
   *         description: Revenue updated successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: Revenue updated successfully
   *       400:
   *         description: Bad request
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: No fields to update
   *       404:
   *         description: Revenue not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Revenue not found
   *       500:
   *         description: Failed to update revenue
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to update revenue
   */

  app.patch('/revenue/:revenueId', (req, res) => {
    const { revenueId } = req.params;
    const { customer_name, service_type, amount, revenue_description, method_of_payment, status } = req.body;
  
    const updateFields = [];
    const updateValues = [];
  
    if (customer_name) {
      updateFields.push('customer_name = ?');
      updateValues.push(customer_name);
    }
    if (service_type) {
      updateFields.push('service_type = ?');
      updateValues.push(service_type);
    }
    if (amount) {
      updateFields.push('amount = ?');
      updateValues.push(amount);
    }
    if (revenue_description) {
      updateFields.push('revenue_description = ?');
      updateValues.push(revenue_description);
    }
    if (method_of_payment) {
      updateFields.push('method_of_payment = ?');
      updateValues.push(method_of_payment);
    }
    if (status) {
      updateFields.push('status = ?');
      updateValues.push(status);
    }
  
    if (updateFields.length === 0) {
      return res.status(400).json({ error: 'No fields to update' });
    }
  
    const query = `UPDATE revenue SET ${updateFields.join(', ')} WHERE id = ?`;
    updateValues.push(revenueId);
  
    connection.query(query, updateValues, (err, result) => {
      if (err) {
        console.error('Error updating revenue:', err);
        logActivity('ERROR', 'revenue', `Error updating revenue with ID ${revenueId}`, 'Admin');
        return res.status(500).json({ error: 'Failed to update revenue' });
      }
  
      if (result.affectedRows === 0) {
        logActivity('FAILED', 'revenue', `Revenue not found with ID ${revenueId}`, 'Admin');
        return res.status(404).json({ error: 'Revenue not found' });
      }

      logActivity('UPDATE', 'revenue', `Updated revenue with ID ${revenueId}`, 'Admin');
      res.status(200).json({ message: 'Revenue updated successfully' });
    });
  });

  /** 
   * @swagger
   * /revenue/{revenueId}:
   *   delete:
   *     summary: Delete a revenue record
   *     description: Delete a revenue record by its ID
   *     parameters:
   *       - in: path
   *         name: revenueId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the revenue record to delete
   *     responses:
   *       200:
   *         description: Revenue deleted successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: Revenue deleted successfully
   *       404:
   *         description: Revenue not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Revenue not found
   *       500:
   *         description: Failed to delete revenue
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to delete revenue
   */

  app.delete('/revenue/:revenueId', (req, res) => {
    const { revenueId } = req.params;
  
    const query = 'DELETE FROM revenue WHERE id = ?';
  
    connection.query(query, [revenueId], (err, result) => {
      if (err) {
        console.error('Error deleting revenue:', err);
        logActivity('ERROR', 'revenue', `Error deleting revenue with ID ${revenueId}`, 'Admin');
        return res.status(500).json({ error: 'Failed to delete revenue' });
      }
  
      if (result.affectedRows === 0) {
        logActivity('FAILED', 'revenue', `Revenue not found with ID ${revenueId}`, 'Admin');
        return res.status(404).json({ error: 'Revenue not found' });
      }

      logActivity('DELETE', 'revenue', `Deleted revenue with ID ${revenueId}`, 'Admin');
      res.status(200).json({ message: 'Revenue deleted successfully' });
    });
  });

/**
 * @swagger
 * /finance-stats:
 *   get:
 *     summary: Fetch finance statistics
 *     description: Retrieve total revenue, total expense, and net profit with optional filters for month and year.
 *     parameters:
 *       - in: query
 *         name: month
 *         schema:
 *           type: integer
 *         description: Filter by month (1-12)
 *       - in: query
 *         name: year
 *         schema:
 *           type: integer
 *         description: Filter by year
 *     responses:
 *       200:
 *         description: Finance statistics
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 total_revenue:
 *                   type: number
 *                 total_expense:
 *                   type: number
 *                 net_profit:
 *                   type: number
 *                 graph_data:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       month:
 *                         type: string
 *                         description: Month name
 *                       total_revenue:
 *                         type: number
 *                         description: Total revenue for the month
 *                       total_expense:
 *                         type: number
 *                         description: Total expense for the month
 *       500:
 *         description: Failed to fetch finance stats
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Failed to fetch finance stats
 *       400:
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Month and year are required
 */
app.get('/finance-stats', (req, res) => {
  const { month, year } = req.query;

  let revenueWhere = '';
  let expenseWhere = '';
  const filters = [];
  if (month) filters.push(`MONTH(created_at) = ${mysql.escape(month)}`);
  if (year) filters.push(`YEAR(created_at) = ${mysql.escape(year)}`);
  if (filters.length > 0) {
    const whereClause = ` WHERE ${filters.join(' AND ')}`;
    revenueWhere = whereClause;
    expenseWhere = whereClause;
  }

  const totalRevenueQuery = `SELECT SUM(amount) AS total_revenue FROM revenue${revenueWhere}`;
  const totalExpenseQuery = `SELECT SUM(amount) AS total_expense FROM expense${expenseWhere}`;
const graphQuery = `
  SELECT 
    YEAR(created_at) AS year,
    MONTH(created_at) AS month_number,
    MONTHNAME(created_at) AS month,
    SUM(CASE WHEN table_name = 'revenue' THEN amount ELSE 0 END) AS total_revenue,
    SUM(CASE WHEN table_name = 'expense' THEN amount ELSE 0 END) AS total_expense
  FROM (
    SELECT 'revenue' AS table_name, amount, created_at FROM revenue
    UNION ALL
    SELECT 'expense' AS table_name, amount, created_at FROM expense
  ) AS combined
  GROUP BY year, month_number, month
  ORDER BY year, month_number
`;
 connection.query(totalRevenueQuery, (err, revenueResults) => {
  if (err) {
   console.error('Error fetching total revenue:', err);
      logActivity('ERROR', 'finance', 'Error fetching total revenue', 'System');
      return res.status(500).json({ error: 'Failed to fetch finance stats' });
    }
  connection.query(totalExpenseQuery, (err, expenseResults) => {
    if (err) {
      console.error('Error fetching total expense:', err);
        logActivity('ERROR', 'finance', 'Error fetching total expense', 'System');
        return res.status(500).json({ error: 'Failed to fetch finance stats' });
      }
    connection.query(graphQuery, (err, graphResults) => {
      if (err) {
        console.error('Error fetching graph data:', err);
          logActivity('ERROR', 'finance', 'Error fetching graph data', 'System');
          return res.status(500).json({ error: 'Failed to fetch finance stats' });
        }
      try {
        const totalRevenue = (revenueResults[0] && revenueResults[0].total_revenue) || 0;
        const totalExpense = (expenseResults[0] && expenseResults[0].total_expense) || 0;
        const netProfit = totalRevenue - totalExpense;
        logActivity('READ', 'finance', 'Fetched finance stats', 'Admin');
          res.status(200).json({
            total_revenue: totalRevenue,
            total_expense: totalExpense,
            net_profit: netProfit,
            graph_data: graphResults,
          });
      } catch (e) {
        console.error('Error processing finance stats:', e);
        res.status(500).json({ error: 'Failed to process finance stats' });
      }
    });
  });
});
});




  function logActivity(activityType, tableName, description, performedBy = 'System') {
    const query = `
      INSERT INTO recent_activity (activity_type, table_name, description, performed_by) 
      VALUES (?, ?, ?, ?)
    `;
    const values = [activityType, tableName, description, performedBy];
  
    connection.query(query, values, (err) => {
      if (err) {
        console.error('Error logging activity:', err);
      }
    });
  }


  /**
 * @swagger
 * /recent_activity:
 *   get:
 *     summary: Fetch all recent activities
 *     description: Retrieve a list of all recent activities with optional filters for month and year.
 *     parameters:
 *       - in: query
 *         name: month
 *         schema:
 *           type: integer
 *         description: Filter by month (1-12)
 *       - in: query
 *         name: year
 *         schema:
 *           type: integer
 *         description: Filter by year
 *     responses:
 *       200:
 *         description: A list of recent activities
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   activity_type:
 *                     type: string
 *                   table_name:
 *                     type: string
 *                   description:
 *                     type: string
 *                   performed_by:
 *                     type: string
 *                   created_at:
 *                     type: string
 *                     format: date-time
 *       500:
 *         description: Failed to fetch recent activities
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Failed to fetch recent activities
 *       400:
 *         description: Bad request
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Month and year are required
 */

  app.get('/recent_activity', (req, res) => {
    const { month, year } = req.query;
  
    let query = 'SELECT * FROM recent_activity';
    const filters = [];
  
    if (month) {
      filters.push(`MONTH(created_at) = ${mysql.escape(month)}`);
    }
    if (year) {
      filters.push(`YEAR(created_at) = ${mysql.escape(year)}`);
    }
  
    if (filters.length > 0) {
      query += ` WHERE ${filters.join(' AND ')}`;
    }
  
    query += ' ORDER BY created_at DESC';
  
    connection.query(query, (err, results) => {
      if (err) {
        console.error('Error fetching recent activities:', err);
        return res.status(500).json({ error: 'Failed to fetch recent activities' });
      }
  
      res.status(200).json(results);
    });
  });


/** 
 * @swagger
 * /recent_activity/{activityId}:
 *   get:
 *     summary: Get a recent activity record by ID
 *     description: Fetch a recent activity record by its ID
 *     parameters:
 *       - in: path
 *         name: activityId
 *         required: true
 *         schema:
 *           type: integer
 *         description: ID of the recent activity record to fetch
 *     responses:
 *       200:
 *         description: Recent activity fetched successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   description: Activity ID
 *                   example: 1
 *                 activity_type:
 *                   type: string
 *                   description: Type of activity
 *                   example: INSERT
 *                 table_name:
 *                   type: string
 *                   description: Name of the table affected
 *                   example: admin
 *                 description:
 *                   type: string
 *                   description: Description of the activity
 *                   example: Created a new admin account
 *                 performed_by:
 *                   type: string
 *                   description: Who performed the activity
 *                   example: Admin
 *                 created_at:
 *                   type: string
 *                   format: date-time
 *                   description: Timestamp of the activity
 *                   example: 2023-10-01T12:00:00Z
 *       404:
 *         description: Recent activity not found
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Recent activity not found
 *       500:
 *         description: Failed to fetch recent activity
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 error:
 *                   type: string
 *                   description: Error message
 *                   example: Failed to fetch recent activity
 */
  app.get('/recent_activity/:activityId', (req, res) => {
    const { activityId } = req.params;
  
    const query = 'SELECT * FROM recent_activity WHERE id = ?';
  
    connection.query(query, [activityId], (err, results) => {
      if (err) {
        console.error('Error fetching recent activity:', err);
        return res.status(500).json({ error: 'Failed to fetch recent activity' });
      }
  
      if (results.length === 0) {
        return res.status(404).json({ error: 'Recent activity not found' });
      }
  
      res.status(200).json(results[0]);
    });
  });


  /** 
   * @swagger
   * /recent_activity/{activityId}:
   *   delete:
   *     summary: Delete a recent activity record
   *     description: Delete a recent activity record by its ID
   *     parameters:
   *       - in: path
   *         name: activityId
   *         required: true
   *         schema:
   *           type: integer
   *         description: ID of the recent activity record to delete
   *     responses:
   *       200:
   *         description: Recent activity deleted successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Success message
   *                   example: Recent activity deleted successfully
   *       404:
   *         description: Recent activity not found
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Recent activity not found
   *       500:
   *         description: Failed to delete recent activity
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 error:
   *                   type: string
   *                   description: Error message
   *                   example: Failed to delete recent activity
   */
  app.delete('/recent_activity/:activityId', (req, res) => {
    const { activityId } = req.params;
    const query = 'DELETE FROM recent_activity WHERE id = ?';
  
    connection.query(query, [activityId], (err, result) => {
      if (err) {
        console.error('Error deleting recent activity:', err);
        return res.status(500).json({ error: 'Failed to delete recent activity' });
      }
  
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: 'Recent activity not found' });
      }
  
      res.status(200).json({ message: 'Recent activity deleted successfully' });
    });
  })


  /**
   * @swagger
   * /:
   *   get:
   *     summary: Welcome message
   *     description: Returns a welcome message for the API
   *     responses:
   *       200:
   *         description: Welcome message returned successfully
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 message:
   *                   type: string
   *                   description: Welcome message
   *                   example: Welcome to the Project Management API
   */
  app.get('/', (req, res) => {
    res.send('Welcome to the Project Management API');
  });





  app.listen(port, () => {
    console.log(`Server is started at http://localhost:${port}`);
  });
