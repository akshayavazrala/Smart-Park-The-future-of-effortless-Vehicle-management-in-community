const express = require('express');
const mysql = require('mysql');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 5000;

// Configure email transporter (for password reset)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'your-email@gmail.com',
    pass: 'your-email-password'
  }
});

app.use(bodyParser.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'Uploads')));

// Ensure uploads directory exists
if (!fs.existsSync('./Uploads')) {
  fs.mkdirSync('./Uploads');
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'Uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
    if (allowedTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only PDF, JPG, and PNG are allowed.'));
    }
  }
});

// Replace your current db connection with:
const db = mysql.createPool({
  connectionLimit: 10,
  host: 'localhost',
  user: 'root',
  password: '2444',
  database: 'vehicle_registration',
  waitForConnections: true,
  queueLimit: 0
});

// Add error handling
db.on('error', (err) => {
  console.error('Database error:', err);
  if (err.code === 'PROTOCOL_CONNECTION_LOST') {
    // Reconnect if connection is lost
    initializeDatabase();
  } else {
    throw err;
  }
});

function initializeDatabase() {
  // Create useradmin table
  const createUserTable = `
    CREATE TABLE IF NOT EXISTS useradmin (
      id INT AUTO_INCREMENT PRIMARY KEY,
      firstName VARCHAR(50) NOT NULL,
      lastName VARCHAR(50) NOT NULL,
      ownerEmail VARCHAR(100) NOT NULL,
      username VARCHAR(50) NOT NULL UNIQUE,
      password VARCHAR(255) NOT NULL,
      ownerPhone VARCHAR(15) NOT NULL,
      aadhar VARCHAR(20) NOT NULL,
      ownerAddress TEXT NOT NULL,
      role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
      resetToken VARCHAR(255),
      resetTokenExpires DATETIME,
      lat DECIMAL(10, 8),
      lng DECIMAL(11, 8),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`;
  
  db.query(createUserTable, (err) => {
    if (err) console.error('Error creating useradmin table:', err);
    
    // Create vehicles table with ON DELETE CASCADE
    const createVehiclesTable = `
      CREATE TABLE IF NOT EXISTS vehicles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        vehicle_type VARCHAR(50) NOT NULL,
        manufacturer VARCHAR(50) NOT NULL,
        model VARCHAR(50) NOT NULL,
        year INT NOT NULL,
        seating_capacity INT NOT NULL,
        color VARCHAR(30) NOT NULL,
        engine_number VARCHAR(50) NOT NULL,
        chassis_number VARCHAR(50) NOT NULL,
        fuel_type VARCHAR(30) NOT NULL,
        purchase_date DATE NOT NULL,
        registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        special_number VARCHAR(20),
        aadhar_doc_path VARCHAR(255),
        insurance_doc_path VARCHAR(255),
        purchase_doc_path VARCHAR(255),
        license_doc_path VARCHAR(255),
        FOREIGN KEY (user_id) REFERENCES useradmin(id) ON DELETE CASCADE
      )`;
    
    db.query(createVehiclesTable, (err) => {
      if (err) console.error('Error creating vehicles table:', err);
      
      // Create parking_locations table
      const createLocationsTable = `
        CREATE TABLE IF NOT EXISTS parking_locations (
          id VARCHAR(20) PRIMARY KEY,
          name VARCHAR(100) NOT NULL,
          address TEXT NOT NULL,
          lat DECIMAL(10, 8) NOT NULL,
          lng DECIMAL(11, 8) NOT NULL,
          timings VARCHAR(50) NOT NULL,
          capacity VARCHAR(50) NOT NULL,
          pricing TEXT NOT NULL,
          landmarks TEXT,
          metro_info TEXT,
          bus_info TEXT
        )`;
      
      db.query(createLocationsTable, (err) => {
        if (err) console.error('Error creating parking_locations table:', err);
        
        // Create parking_bookings table
        const createBookingsTable = `
          CREATE TABLE IF NOT EXISTS parking_bookings (
            id INT AUTO_INCREMENT PRIMARY KEY,
            booking_id VARCHAR(20) NOT NULL,
            user_id INT NOT NULL,
            location_id VARCHAR(20),
            slot_number VARCHAR(20) NOT NULL,
            basement_level VARCHAR(10) NOT NULL,
            vehicle_type VARCHAR(10) NOT NULL,
            booking_time DATETIME NOT NULL,
            duration DECIMAL(5,2) NOT NULL,
            total_price DECIMAL(10,2) NOT NULL,
            status VARCHAR(20) NOT NULL,
            destination VARCHAR(255),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES useradmin(id),
            FOREIGN KEY (location_id) REFERENCES parking_locations(id)
          )`;
        
        db.query(createBookingsTable, (err) => {
          if (err) console.error('Error creating parking_bookings table:', err);
          
          // Create parking_slots table
          const createSlotsTable = `
            CREATE TABLE IF NOT EXISTS parking_slots (
              id INT AUTO_INCREMENT PRIMARY KEY,
              slot_number VARCHAR(20) NOT NULL,
              basement_level VARCHAR(10) NOT NULL,
              vehicle_type VARCHAR(10) NOT NULL,
              status VARCHAR(20) NOT NULL DEFAULT 'available',
              price_per_hour DECIMAL(5,2) NOT NULL
            )`;
          
          db.query(createSlotsTable, (err) => {
            if (err) console.error('Error creating parking_slots table:', err);
            
            // Create password_reset_tokens table
            const createResetTokensTable = `
              CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                token VARCHAR(255) NOT NULL,
                expires_at DATETIME NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (user_id) REFERENCES useradmin(id)
              )`;
            
            db.query(createResetTokensTable, (err) => {
              if (err) console.error('Error creating password_reset_tokens table:', err);
              initializeParkingSlots();
            });
          });
        });
      });
    });
  });
}

function initializeParkingSlots() {
  const checkQuery = 'SELECT COUNT(*) as count FROM parking_slots';
  db.query(checkQuery, (err, results) => {
    if (err) {
      console.error('Error checking parking slots:', err);
      return;
    }
    
    if (results[0].count === 0) {
      console.log('Creating initial parking slots...');
      
      const slots = [];
      const vehicleTypes = ['bike', 'car', 'heavy'];
      const basements = ['B1', 'B2', 'B3'];
      
      basements.forEach(basement => {
        vehicleTypes.forEach(vehicle => {
          const slotCount = vehicle === 'bike' ? 20 : vehicle === 'car' ? 15 : 10;
          const basePrice = vehicle === 'bike' ? 2 : vehicle === 'car' ? 5 : 10;
          
          for (let i = 1; i <= slotCount; i++) {
            const slotNumber = `${basement}-${vehicle.charAt(0)}${i.toString().padStart(2, '0')}`;
            slots.push([
              slotNumber,
              basement,
              vehicle,
              'available',
              basePrice + (Math.random() * 2)
            ]);
          }
        });
      });
      
      const insertQuery = 'INSERT INTO parking_slots (slot_number, basement_level, vehicle_type, status, price_per_hour) VALUES ?';
      db.query(insertQuery, [slots], (err) => {
        if (err) console.error('Error creating parking slots:', err);
        else console.log('Created initial parking slots');
      });
    }
  });
}

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split('Bearer ')[1];
  if (!token) {
    return res.status(401).json({ success: false, message: 'Unauthorized: No token provided' });
  }
  
  const query = 'SELECT * FROM useradmin WHERE id = ?';
  db.query(query, [token], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    if (results.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid session' });
    }
    req.user = results[0];
    next();
  });
}

// User registration
app.post('/register', (req, res) => {
  const { firstName, lastName, ownerEmail, username, password, ownerPhone, aadhar, ownerAddress } = req.body;

  if (!firstName || !lastName || !ownerEmail || !username || !password || !ownerPhone || !aadhar || !ownerAddress) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const checkQuery = 'SELECT * FROM useradmin WHERE username = ? OR ownerEmail = ?';
  
  db.query(checkQuery, [username, ownerEmail], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    if (results.length > 0) {
      return res.status(409).json({ success: false, message: 'Username or email already exists' });
    }

    const insertQuery = `
      INSERT INTO useradmin 
      (firstName, lastName, ownerEmail, username, password, ownerPhone, aadhar, ownerAddress, role)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'user')
    `;

    db.query(insertQuery, [firstName, lastName, ownerEmail, username, hashedPassword, ownerPhone, aadhar, ownerAddress],
      (err, results) => {
        if (err) {
          console.error('Error inserting user:', err);
          return res.status(500).json({ success: false, message: 'Registration failed' });
        }
        res.status(201).json({ success: true, message: 'Registration successful', userId: results.insertId });
      }
    );
  });
});

// User login
app.post('/login', (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ success: false, message: 'Username, password, and role are required' });
  }

  const query = 'SELECT * FROM useradmin WHERE username = ? AND role = ?';
  db.query(query, [username, role], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid username or role' });
    }

    const user = results[0];
    
    if (!bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ success: false, message: 'Invalid password' });
    }

    res.json({
      success: true,
      message: 'Login successful',
      token: user.id.toString(),
      role: user.role,
      user: {
        id: user.id,
        username: user.username,
        email: user.ownerEmail,
        firstName: user.firstName,
        lastName: user.lastName
      }
    });
  });
});

// Password reset request
app.post('/request-password-reset', (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ success: false, message: 'Email is required' });
  }

  const userQuery = 'SELECT * FROM useradmin WHERE ownerEmail = ?';
  db.query(userQuery, [email], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Email not found' });
    }

    const user = results[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000); // 1 hour from now

    const tokenQuery = 'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)';
    db.query(tokenQuery, [user.id, token, expiresAt], (err) => {
      if (err) {
        console.error('Error storing reset token:', err);
        return res.status(500).json({ success: false, message: 'Error generating reset token' });
      }

      const resetLink = `http://localhost:3000/reset-password?token=${token}`;
      const mailOptions = {
        from: 'your-email@gmail.com',
        to: user.ownerEmail,
        subject: 'Password Reset Request',
        html: `
          <p>You requested a password reset for your account.</p>
          <p>Click this link to reset your password: <a href="${resetLink}">${resetLink}</a></p>
          <p>This link will expire in 1 hour.</p>
        `
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.error('Error sending email:', error);
          return res.status(500).json({ 
            success: false, 
            message: 'Error sending reset email',
            token: token // For development
          });
        }

        res.json({ 
          success: true, 
          message: 'Password reset link sent to your email',
          token: token // For development
        });
      });
    });
  });
});

// Verify reset token
app.post('/verify-reset-token', (req, res) => {
  const { token } = req.body;
  
  if (!token) {
    return res.status(400).json({ success: false, message: 'Token is required' });
  }

  const tokenQuery = `
    SELECT t.*, u.username, u.ownerEmail 
    FROM password_reset_tokens t
    JOIN useradmin u ON t.user_id = u.id
    WHERE t.token = ? AND t.used = FALSE AND t.expires_at > NOW()
  `;
  
  db.query(tokenQuery, [token], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    }

    res.json({ 
      success: true, 
      message: 'Token is valid',
      user: {
        username: results[0].username,
        email: results[0].ownerEmail
      }
    });
  });
});

// Reset password
app.post('/reset-password', (req, res) => {
  const { token, newPassword } = req.body;
  
  if (!token || !newPassword) {
    return res.status(400).json({ success: false, message: 'Token and new password are required' });
  }

  const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!strongRegex.test(newPassword)) {
    return res.status(400).json({ 
      success: false, 
      message: 'Password must be at least 8 characters with uppercase, lowercase, number, and special character' 
    });
  }

  const tokenQuery = `
    SELECT t.*, u.id as user_id 
    FROM password_reset_tokens t
    JOIN useradmin u ON t.user_id = u.id
    WHERE t.token = ? AND t.used = FALSE AND t.expires_at > NOW()
  `;
  
  db.query(tokenQuery, [token], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    }

    const tokenRecord = results[0];
    const hashedPassword = bcrypt.hashSync(newPassword, 10);

    db.beginTransaction(err => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Transaction error' });
      }

      const updateQuery = 'UPDATE useradmin SET password = ? WHERE id = ?';
      db.query(updateQuery, [hashedPassword, tokenRecord.user_id], (err) => {
        if (err) {
          return db.rollback(() => {
            res.status(500).json({ success: false, message: 'Error updating password' });
          });
        }

        const markTokenQuery = 'UPDATE password_reset_tokens SET used = TRUE WHERE id = ?';
        db.query(markTokenQuery, [tokenRecord.id], (err) => {
          if (err) {
            return db.rollback(() => {
              res.status(500).json({ success: false, message: 'Error updating token' });
            });
          }

          db.commit(err => {
            if (err) {
              return db.rollback(() => {
                res.status(500).json({ success: false, message: 'Commit error' });
              });
            }

            res.json({ success: true, message: 'Password updated successfully' });
          });
        });
      });
    });
  });
});

// Change password (for logged-in users)
app.post('/change-password', authenticate, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ success: false, message: 'Current and new password are required' });
  }

  const strongRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!strongRegex.test(newPassword)) {
    return res.status(400).json({ 
      success: false, 
      message: 'Password must be at least 8 characters with uppercase, lowercase, number, and special character' 
    });
  }

  if (!bcrypt.compareSync(currentPassword, req.user.password)) {
    return res.status(401).json({ success: false, message: 'Current password is incorrect' });
  }

  const hashedPassword = bcrypt.hashSync(newPassword, 10);
  const updateQuery = 'UPDATE useradmin SET password = ? WHERE id = ?';
  
  db.query(updateQuery, [hashedPassword, req.user.id], (err) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Error updating password' });
    }

    res.json({ success: true, message: 'Password changed successfully' });
  });
});

// Vehicle Registration
app.post('/register-vehicle', authenticate, upload.fields([
  { name: 'aadharDoc', maxCount: 1 },
  { name: 'insuranceDoc', maxCount: 1 },
  { name: 'purchaseDoc', maxCount: 1 },
  { name: 'licenseDoc', maxCount: 1 }
]), (req, res) => {
  const {
    vehicleType,
    manufacturer,
    model,
    year,
    seatingCapacity,
    color,
    engineNumber,
    chassisNumber,
    fuelType,
    purchaseDate,
    specialNumber
  } = req.body;

  // Add strict validation for purchaseDate
  if (!purchaseDate || isNaN(new Date(purchaseDate).getTime())) {
    return res.status(400).json({ 
      success: false, 
      message: 'Invalid purchase date format' 
    });
  }
  // Validate required fields
  if (!vehicleType || !manufacturer || !model || !year || !seatingCapacity || 
      !color || !engineNumber || !chassisNumber || !fuelType || !purchaseDate) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  // Process file paths
  const aadharDocPath = path.join('Uploads', req.files.aadharDoc[0].filename).replace(/\\/g, '/');
  const insuranceDocPath = path.join('Uploads', req.files.insuranceDoc[0].filename).replace(/\\/g, '/');
  const purchaseDocPath = path.join('Uploads', req.files.purchaseDoc[0].filename).replace(/\\/g, '/');
  const licenseDocPath = path.join('Uploads', req.files.licenseDoc[0].filename).replace(/\\/g, '/');

  const query = `
  INSERT INTO vehicles (
    user_id, vehicle_type, manufacturer, model, year, seating_capacity, color,
    engine_number, chassis_number, fuel_type, purchase_date, special_number,
    aadhar_doc_path, insurance_doc_path, purchase_doc_path, license_doc_path
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`;

  db.query(query, [
    req.user.id, 
    vehicleType, 
    manufacturer, 
    model, 
    year, 
    seatingCapacity, 
    color,
    engineNumber, 
    chassisNumber, 
    fuelType, 
    purchaseDate, 
    specialNumber || null,
    aadharDocPath, 
    insuranceDocPath, 
    purchaseDocPath, 
    licenseDocPath
  ], (err, results) => {
    if (err) {
      console.error('Error registering vehicle:', err);
      
      // Clean up uploaded files if registration failed
      [aadharDocPath, insuranceDocPath, purchaseDocPath, licenseDocPath].forEach(file => {
        fs.unlink(path.join(__dirname, file), () => {});
      });
      
      return res.status(500).json({ 
        success: false, 
        message: 'Vehicle registration failed: ' + err.message,
        errorDetails: err // Include more error details for debugging
      });
    }

    res.json({ 
      success: true, 
      message: 'Vehicle registered successfully',
      vehicleId: results.insertId
    });
  });
});

// Get all vehicles for a user
// Updated Get all vehicles for a user endpoint
// Get all vehicles for a user
app.get('/user-vehicles', async (req, res) => {
  try {
    // Get token from header
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }

    // Verify token is valid user ID
    const [user] = await db.query('SELECT id FROM useradmin WHERE id = ?', [token]);
    if (!user) {
      return res.status(401).json({ success: false, message: 'Invalid token' });
    }

    // Get vehicles
    const [vehicles] = await db.query(`
      SELECT * FROM vehicles 
      WHERE user_id = ?
      ORDER BY registration_date DESC
    `, [user.id]);

    res.json({
      success: true,
      vehicles: vehicles || []
    });

  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Server error',
      error: error.message 
    });
  }
});

// Get vehicle details
app.get('/vehicle-details', authenticate, (req, res) => {
  const vehicleId = req.query.id;
  
  if (!vehicleId) {
    return res.status(400).json({ success: false, message: 'Vehicle ID is required' });
  }
  
  const query = 'SELECT * FROM vehicles WHERE id = ? AND user_id = ?';
  db.query(query, [vehicleId, req.user.id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Vehicle not found' });
    }
    
    res.json(results[0]);
  });
});

// Delete vehicle
app.delete('/delete-vehicle', authenticate, (req, res) => {
  const vehicleId = req.query.id;
  
  if (!vehicleId) {
    return res.status(400).json({ success: false, message: 'Vehicle ID is required' });
  }
  
  const getQuery = 'SELECT * FROM vehicles WHERE id = ? AND user_id = ?';
  db.query(getQuery, [vehicleId, req.user.id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Vehicle not found or unauthorized' });
    }
    
    const vehicle = results[0];
    
    const deleteQuery = 'DELETE FROM vehicles WHERE id = ?';
    db.query(deleteQuery, [vehicleId], (err) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }
      
      const documents = [
        vehicle.aadhar_doc_path,
        vehicle.insurance_doc_path,
        vehicle.purchase_doc_path,
        vehicle.license_doc_path
      ];
      
      documents.forEach(docPath => {
        if (docPath) {
          const fullPath = path.join(__dirname, docPath);
          fs.unlink(fullPath, err => {
            if (err) console.error('Error deleting file:', err);
          });
        }
      });
      
      res.json({ success: true, message: 'Vehicle deleted successfully' });
    });
  });
});

// Root endpoint
app.get('/', (req, res) => {
  res.send('SmartPark Parking Management System API');
});

// Get user bookings with filtering and sorting
app.get('/user-bookings/:userId', (req, res) => {
  const userId = req.params.userId;
  const { vehicle, days, search, sort = 'booking_time', order = 'DESC' } = req.query;

  // Validate sort field to prevent SQL injection
  const validSortFields = ['booking_id', 'location_name', 'slot_number', 'vehicle_type', 'booking_time', 'status'];
  if (!validSortFields.includes(sort)) {
    return res.status(400).json({ success: false, message: 'Invalid sort field' });
  }

  // Validate order
  const validOrders = ['ASC', 'DESC'];
  if (!validOrders.includes(order.toUpperCase())) {
    return res.status(400).json({ success: false, message: 'Invalid sort order' });
  }

  let query = `
    SELECT 
      b.booking_id,
      b.location_id,
      b.location_name,
      b.location_address,
      b.slot_number,
      b.basement_level,
      b.vehicle_type,
      b.booking_time,
      b.booking_end_time,
      b.duration,
      b.total_price,
      b.status,
      b.payment_status,
      b.destination,
      l.lat,
      l.lng
    FROM parking_bookings b
    LEFT JOIN parking_locations l ON b.location_id = l.id
    WHERE b.user_id = ?
  `;
  
  const params = [userId];
  
  // Add filters
  if (vehicle && vehicle !== 'all') {
    query += ' AND b.vehicle_type = ?';
    params.push(vehicle);
  }
  
  if (days && days !== 'all') {
    query += ' AND b.booking_time >= DATE_SUB(NOW(), INTERVAL ? DAY)';
    params.push(parseInt(days));
  }
  
  if (search) {
    query += ' AND (b.location_name LIKE ? OR b.booking_id LIKE ? OR b.slot_number LIKE ?)';
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }
  
  // Add sorting
  query += ` ORDER BY ${sort} ${order}`;
  
  db.query(query, params, (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    
    res.json({ 
      success: true, 
      bookings: results.map(booking => ({
        ...booking,
        booking_time: new Date(booking.booking_time).toISOString(),
        booking_end_time: booking.booking_end_time ? new Date(booking.booking_end_time).toISOString() : null
      }))
    });
  });
});

// Cancel a booking
app.post('/cancel-booking', authenticate, (req, res) => {
  const { bookingId } = req.body;
  
  if (!bookingId) {
    return res.status(400).json({ success: false, message: 'Booking ID is required' });
  }
  
  // First verify the booking belongs to the user
  const verifyQuery = 'SELECT * FROM parking_bookings WHERE booking_id = ? AND user_id = ?';
  db.query(verifyQuery, [bookingId, req.user.id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Booking not found or unauthorized' });
    }
    
    const booking = results[0];
    
    if (booking.status !== 'booked') {
      return res.status(400).json({ success: false, message: 'Only active bookings can be cancelled' });
    }
    
    // Start transaction
    db.beginTransaction(err => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Transaction error' });
      }
      
      // Update booking status
      const updateBookingQuery = `
        UPDATE parking_bookings 
        SET status = 'cancelled', booking_end_time = NOW() 
        WHERE booking_id = ?
      `;
      
      db.query(updateBookingQuery, [bookingId], (err) => {
        if (err) {
          return db.rollback(() => {
            res.status(500).json({ success: false, message: 'Error updating booking' });
          });
        }
        
        // Update slot status
        const updateSlotQuery = `
          UPDATE parking_slots 
          SET status = 'available' 
          WHERE slot_number = ? AND basement_level = ?
        `;
        
        db.query(updateSlotQuery, [booking.slot_number, booking.basement_level], (err) => {
          if (err) {
            return db.rollback(() => {
              res.status(500).json({ success: false, message: 'Error updating slot' });
            });
          }
          
          // If payment was made, process refund
          if (booking.payment_status === 'paid') {
            // In a real app, you would integrate with payment gateway here
            const updatePaymentQuery = `
              UPDATE parking_bookings 
              SET payment_status = 'refunded' 
              WHERE booking_id = ?
            `;
            
            db.query(updatePaymentQuery, [bookingId], (err) => {
              if (err) {
                return db.rollback(() => {
                  res.status(500).json({ success: false, message: 'Error updating payment status' });
                });
              }
              
              db.commit(err => {
                if (err) {
                  return db.rollback(() => {
                    res.status(500).json({ success: false, message: 'Commit error' });
                  });
                }
                
                res.json({ success: true, message: 'Booking cancelled and refund processed' });
              });
            });
          } else {
            db.commit(err => {
              if (err) {
                return db.rollback(() => {
                  res.status(500).json({ success: false, message: 'Commit error' });
                });
              }
              
              res.json({ success: true, message: 'Booking cancelled successfully' });
            });
          }
        });
      });
    });
  });
});

// Create a new parking booking
app.post('/create-booking', authenticate, (req, res) => {
  const {
    locationId,
    slotNumber,
    basementLevel,
    vehicleType,
    bookingTime,
    duration,
    destination
  } = req.body;

  // Validate required fields
  if (!locationId || !slotNumber || !basementLevel || !vehicleType || !bookingTime || !duration) {
    return res.status(400).json({ success: false, message: 'Missing required fields' });
  }

  // Calculate total price (in a real app, you'd query the slot price)
  const pricePerHour = vehicleType === 'bike' ? 2 : 
                      vehicleType === 'car' ? 5 : 10;
  const totalPrice = pricePerHour * duration;

  // Generate booking ID
  const bookingId = 'BK-' + Math.random().toString(36).substr(2, 8).toUpperCase();

  // First check if slot is available
  const checkSlotQuery = `
    SELECT status FROM parking_slots 
    WHERE slot_number = ? AND basement_level = ? AND vehicle_type = ?
  `;
  
  db.query(checkSlotQuery, [slotNumber, basementLevel, vehicleType], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Slot not found' });
    }

    if (results[0].status !== 'available') {
      return res.status(400).json({ success: false, message: 'Slot is not available' });
    }

    // Start transaction
    db.beginTransaction(err => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Transaction error' });
      }

      // Get location details
      const locationQuery = 'SELECT name, address FROM parking_locations WHERE id = ?';
      db.query(locationQuery, [locationId], (err, locationResults) => {
        if (err) {
          return db.rollback(() => {
            res.status(500).json({ success: false, message: 'Error fetching location' });
          });
        }

        if (locationResults.length === 0) {
          return db.rollback(() => {
            res.status(404).json({ success: false, message: 'Location not found' });
          });
        }

        const location = locationResults[0];

        // Insert booking
        const insertQuery = `
          INSERT INTO parking_bookings (
            booking_id, user_id, location_id, location_name, location_address,
            slot_number, basement_level, vehicle_type, booking_time, duration,
            total_price, status, destination
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'booked', ?)
        `;

        db.query(insertQuery, [
          bookingId,
          req.user.id,
          locationId,
          location.name,
          location.address,
          slotNumber,
          basementLevel,
          vehicleType,
          new Date(bookingTime),
          duration,
          totalPrice,
          destination || null
        ], (err, results) => {
          if (err) {
            return db.rollback(() => {
              console.error('Error creating booking:', err);
              res.status(500).json({ success: false, message: 'Error creating booking' });
            });
          }

          // Update slot status
          const updateSlotQuery = `
            UPDATE parking_slots 
            SET status = 'reserved' 
            WHERE slot_number = ? AND basement_level = ? AND vehicle_type = ?
          `;

          db.query(updateSlotQuery, [slotNumber, basementLevel, vehicleType], (err) => {
            if (err) {
              return db.rollback(() => {
                res.status(500).json({ success: false, message: 'Error updating slot status' });
              });
            }

            // Commit transaction
            db.commit(err => {
              if (err) {
                return db.rollback(() => {
                  res.status(500).json({ success: false, message: 'Commit error' });
                });
              }

              res.json({ 
                success: true, 
                message: 'Booking created successfully',
                bookingId,
                totalPrice
              });
            });
          });
        });
      });
    });
  });
});

// Complete a booking (when user leaves)
app.post('/complete-booking', authenticate, (req, res) => {
  const { bookingId } = req.body;

  if (!bookingId) {
    return res.status(400).json({ success: false, message: 'Booking ID is required' });
  }

  // First verify the booking belongs to the user
  const verifyQuery = `
    SELECT b.*, s.vehicle_type 
    FROM parking_bookings b
    JOIN parking_slots s ON b.slot_number = s.slot_number AND b.basement_level = s.basement_level
    WHERE b.booking_id = ? AND b.user_id = ?
  `;
  
  db.query(verifyQuery, [bookingId, req.user.id], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Booking not found or unauthorized' });
    }

    const booking = results[0];

    // Start transaction
    db.beginTransaction(err => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Transaction error' });
      }

      // Update booking status
      const updateBookingQuery = `
        UPDATE parking_bookings 
        SET status = 'completed', booking_end_time = NOW() 
        WHERE booking_id = ?
      `;
      
      db.query(updateBookingQuery, [bookingId], (err) => {
        if (err) {
          return db.rollback(() => {
            res.status(500).json({ success: false, message: 'Error updating booking' });
          });
        }

        // Update slot status
        const updateSlotQuery = `
          UPDATE parking_slots 
          SET status = 'available' 
          WHERE slot_number = ? AND basement_level = ? AND vehicle_type = ?
        `;
        
        db.query(updateSlotQuery, [booking.slot_number, booking.basement_level, booking.vehicle_type], (err) => {
          if (err) {
            return db.rollback(() => {
              res.status(500).json({ success: false, message: 'Error updating slot' });
            });
          }

          db.commit(err => {
            if (err) {
              return db.rollback(() => {
                res.status(500).json({ success: false, message: 'Commit error' });
              });
            }

            res.json({ success: true, message: 'Booking completed successfully' });
          });
        });
      });
    });
  });
});

// Add this to your existing server.js
app.post('/save-parking-booking', async (req, res) => {
  const { 
    userId, 
    location, 
    slot, 
    vehicleType, 
    duration, 
    arrivalTime, 
    price 
  } = req.body;

  // Validation
  if (!userId || !location || !slot || !vehicleType || !duration || !arrivalTime || !price) {
    return res.status(400).json({ success: false, message: "Missing required fields" });
  }

  // Generate booking ID
  const bookingId = 'BK-' + Math.random().toString(36).substr(2, 8).toUpperCase();

  try {
    // Get location details (assuming you have a locations table)
    const [locationData] = await db.query(
      'SELECT name, address FROM parking_locations WHERE id = ?', 
      [location]
    );

    if (!locationData || locationData.length === 0) {
      return res.status(404).json({ success: false, message: "Location not found" });
    }

    // Insert booking with all required fields
    await db.query(`
      INSERT INTO parking_bookings (
        booking_id, user_id, location_id, location_name, location_address,
        slot_number, vehicle_type, booking_time, duration, total_price, status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'booked')
    `, [
      bookingId,
      userId,
      location,
      locationData[0].name,
      locationData[0].address,
      slot,
      vehicleType,
      new Date(arrivalTime),
      duration,
      price
    ]);

    res.json({ 
      success: true, 
      bookingId,
      message: "Booking saved successfully"
    });
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ 
      success: false, 
      message: "Failed to save booking",
      error: err.message 
    });
  }
});

app.get('/get-booking-history/:userId', async (req, res) => {
  const { userId } = req.params;
  const { limit = 10, offset = 0 } = req.query;

  try {
    const [bookings] = await db.query(`
      SELECT 
        booking_id as bookingId,
        location_name as location,
        slot_number as slot,
        vehicle_type as vehicleType,
        booking_time as bookingTime,
        duration,
        total_price as totalPrice,
        status
      FROM parking_bookings
      WHERE user_id = ?
      ORDER BY booking_time DESC
      LIMIT ? OFFSET ?
    `, [userId, parseInt(limit), parseInt(offset)]);

    res.json({
      success: true,
      bookings: bookings.map(booking => ({
        ...booking,
        bookingTime: new Date(booking.bookingTime).toISOString()
      }))
    });
  } catch (err) {
    console.error("Database error:", err);
    res.status(500).json({ 
      success: false, 
      message: "Failed to fetch booking history" 
    });
  }
});

// Admin Dashboard Stats
// Admin Dashboard Stats - Updated version
app.get('/admin/stats', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  Promise.all([
      new Promise((resolve, reject) => {
          db.query('SELECT COUNT(*) as count FROM vehicles', (err, results) => {
              if (err) reject(err);
              else resolve(results[0].count);
          });
      }),
      new Promise((resolve, reject) => {
          db.query('SELECT COUNT(*) as count FROM useradmin WHERE role = "user"', (err, results) => {
              if (err) reject(err);
              else resolve(results[0].count);
          });
      }),
      new Promise((resolve, reject) => {
          db.query('SELECT IFNULL(SUM(total_price), 0) as total FROM parking_bookings WHERE status = "completed"', (err, results) => {
              if (err) reject(err);
              else resolve(results[0].total);
          });
      }),
      new Promise((resolve, reject) => {
          db.query(`
              SELECT b.*, u.username, u.ownerEmail 
              FROM parking_bookings b
              JOIN useradmin u ON b.user_id = u.id
              ORDER BY b.booking_time DESC LIMIT 5
          `, (err, results) => {
              if (err) reject(err);
              else resolve(results);
          });
      }),
      new Promise((resolve, reject) => {
          db.query('SELECT COUNT(*) as count FROM parking_bookings WHERE status = "booked"', (err, results) => {
              if (err) reject(err);
              else resolve(results[0].count);
          });
      })
  ])
  .then(([totalVehicles, totalUsers, totalRevenue, recentBookings, activeBookings]) => {
      res.json({
          success: true,
          stats: { totalVehicles, totalUsers, totalRevenue, activeBookings },
          recentBookings
      });
  })
  .catch(err => {
      console.error('Admin stats error:', err);
      res.status(500).json({ success: false, message: 'Database error' });
  });
});
// Admin - Get All Users
app.get('/admin/users', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  const { page = 1, limit = 10, search = '' } = req.query;
  const offset = (page - 1) * limit;

  let query = 'SELECT id, firstName, lastName, ownerEmail, username, ownerPhone, role, created_at FROM useradmin';
  let countQuery = 'SELECT COUNT(*) as total FROM useradmin';
  const params = [];
  const countParams = [];

  if (search) {
    query += ' WHERE username LIKE ? OR ownerEmail LIKE ? OR firstName LIKE ? OR lastName LIKE ?';
    countQuery += ' WHERE username LIKE ? OR ownerEmail LIKE ? OR firstName LIKE ? OR lastName LIKE ?';
    const searchParam = `%${search}%`;
    params.push(searchParam, searchParam, searchParam, searchParam);
    countParams.push(searchParam, searchParam, searchParam, searchParam);
  }

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), offset);

  db.query(countQuery, countParams, (err, countResult) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    db.query(query, params, (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      res.json({
        success: true,
        users: results.map(user => ({
          ...user,
          created_at: new Date(user.created_at).toISOString()
        })),
        total: countResult[0].total,
        page: parseInt(page),
        limit: parseInt(limit)
      });
    });
  });
});

// Admin - Get All Vehicles
app.get('/admin/vehicles', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  const { page = 1, limit = 10, search = '' } = req.query;
  const offset = (page - 1) * limit;

  let query = `
    SELECT v.*, u.username, u.ownerEmail, u.firstName, u.lastName 
    FROM vehicles v
    JOIN useradmin u ON v.user_id = u.id
  `;
  let countQuery = 'SELECT COUNT(*) as total FROM vehicles';
  const params = [];
  const countParams = [];

  if (search) {
    query += ' WHERE v.vehicle_type LIKE ? OR v.manufacturer LIKE ? OR v.model LIKE ? OR u.username LIKE ?';
    countQuery += ' WHERE vehicle_type LIKE ? OR manufacturer LIKE ? OR model LIKE ?';
    const searchParam = `%${search}%`;
    params.push(searchParam, searchParam, searchParam, searchParam);
    countParams.push(searchParam, searchParam, searchParam);
  }

  query += ' ORDER BY v.registration_date DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), offset);

  db.query(countQuery, countParams, (err, countResult) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    db.query(query, params, (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      res.json({
        success: true,
        vehicles: results.map(vehicle => ({
          ...vehicle,
          registration_date: new Date(vehicle.registration_date).toISOString(),
          purchase_date: new Date(vehicle.purchase_date).toISOString()
        })),
        total: countResult[0].total,
        page: parseInt(page),
        limit: parseInt(limit)
      });
    });
  });
});

// Admin - Get All Bookings
app.get('/admin/bookings', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  const { page = 1, limit = 10, status = '', search = '' } = req.query;
  const offset = (page - 1) * limit;

  let query = `
    SELECT b.*, u.username, u.ownerEmail 
    FROM parking_bookings b
    JOIN useradmin u ON b.user_id = u.id
  `;
  let countQuery = 'SELECT COUNT(*) as total FROM parking_bookings';
  const params = [];
  const countParams = [];

  const whereClauses = [];
  if (status) {
    whereClauses.push('b.status = ?');
    params.push(status);
    countParams.push(status);
  }
  if (search) {
    whereClauses.push('(b.booking_id LIKE ? OR u.username LIKE ? OR b.location_name LIKE ?)');
    const searchParam = `%${search}%`;
    params.push(searchParam, searchParam, searchParam);
    countParams.push(searchParam, searchParam, searchParam);
  }

  if (whereClauses.length > 0) {
    query += ' WHERE ' + whereClauses.join(' AND ');
    countQuery += ' WHERE ' + whereClauses.join(' AND ').replace(/b\./g, '');
  }

  query += ' ORDER BY b.booking_time DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), offset);

  db.query(countQuery, countParams, (err, countResult) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    db.query(query, params, (err, results) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      res.json({
        success: true,
        bookings: results.map(booking => ({
          ...booking,
          booking_time: new Date(booking.booking_time).toISOString(),
          booking_end_time: booking.booking_end_time ? new Date(booking.booking_end_time).toISOString() : null
        })),
        total: countResult[0].total,
        page: parseInt(page),
        limit: parseInt(limit)
      });
    });
  });
});

// Enhanced Admin Dashboard Stats Endpoint
app.get('/admin/dashboard', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  // Get time ranges for analytics
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const weekAgo = new Date();
  weekAgo.setDate(weekAgo.getDate() - 7);
  const monthAgo = new Date();
  monthAgo.setMonth(monthAgo.getMonth() - 1);

  Promise.all([
    // Basic counts
    db.query('SELECT COUNT(*) as count FROM vehicles'),
    db.query('SELECT COUNT(*) as count FROM useradmin WHERE role = "user"'),
    db.query('SELECT IFNULL(SUM(total_price), 0) as total FROM parking_bookings WHERE status = "completed"'),
    db.query('SELECT COUNT(*) as count FROM parking_bookings WHERE status = "booked"'),
    
    // Recent activities
    db.query(`
      SELECT b.*, u.username, u.ownerEmail, u.firstName, u.lastName 
      FROM parking_bookings b
      JOIN useradmin u ON b.user_id = u.id
      ORDER BY b.booking_time DESC LIMIT 10
    `),
    
    // Recent users
    db.query(`
      SELECT id, firstName, lastName, ownerEmail, username, created_at 
      FROM useradmin 
      WHERE role = 'user'
      ORDER BY created_at DESC LIMIT 5
    `),
    
    // Recent vehicles
    db.query(`
      SELECT v.*, u.username, u.ownerEmail 
      FROM vehicles v
      JOIN useradmin u ON v.user_id = u.id
      ORDER BY v.registration_date DESC LIMIT 5
    `),
    
    // Revenue analytics
    db.query(`
      SELECT 
        DATE(booking_time) as date,
        SUM(total_price) as daily_revenue,
        COUNT(*) as bookings_count
      FROM parking_bookings
      WHERE status = 'completed' AND booking_time >= ?
      GROUP BY DATE(booking_time)
      ORDER BY date DESC
      LIMIT 30
    `, [monthAgo]),
    
    // Vehicle type distribution
    db.query(`
      SELECT 
        vehicle_type,
        COUNT(*) as count
      FROM vehicles
      GROUP BY vehicle_type
    `),
    
    // User registration trends
    db.query(`
      SELECT 
        DATE(created_at) as date,
        COUNT(*) as registrations
      FROM useradmin
      WHERE role = 'user' AND created_at >= ?
      GROUP BY DATE(created_at)
      ORDER BY date DESC
      LIMIT 30
    `, [monthAgo])
  ])
  .then(([
    [vehicles], [users], [revenue], [activeBookings],
    recentBookings, recentUsers, recentVehicles,
    revenueTrends, vehicleDistribution, userTrends
  ]) => {
    res.json({
      success: true,
      stats: {
        totalVehicles: vehicles[0].count,
        totalUsers: users[0].count,
        totalRevenue: revenue[0].total,
        activeBookings: activeBookings[0].count
      },
      recentActivities: recentBookings,
      recentUsers: recentUsers.map(user => ({
        ...user,
        created_at: new Date(user.created_at).toISOString()
      })),
      recentVehicles: recentVehicles.map(vehicle => ({
        ...vehicle,
        registration_date: new Date(vehicle.registration_date).toISOString(),
        purchase_date: new Date(vehicle.purchase_date).toISOString()
      })),
      analytics: {
        revenueTrends: revenueTrends.map(item => ({
          date: item.date.toISOString().split('T')[0],
          revenue: item.daily_revenue,
          bookings: item.bookings_count
        })),
        vehicleDistribution: vehicleDistribution.reduce((acc, curr) => {
          acc[curr.vehicle_type] = curr.count;
          return acc;
        }, {}),
        userTrends: userTrends.map(item => ({
          date: item.date.toISOString().split('T')[0],
          registrations: item.registrations
        }))
      }
    });
  })
  .catch(err => {
    console.error('Admin dashboard error:', err);
    res.status(500).json({ success: false, message: 'Database error' });
  });
});

// Admin - Cancel Booking
app.post('/admin/cancel-booking', authenticate, (req, res) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  }

  const { bookingId } = req.body;
  
  if (!bookingId) {
    return res.status(400).json({ success: false, message: 'Booking ID is required' });
  }
  
  // First get the booking details
  const verifyQuery = 'SELECT * FROM parking_bookings WHERE booking_id = ?';
  db.query(verifyQuery, [bookingId], (err, results) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Booking not found' });
    }
    
    const booking = results[0];
    
    if (booking.status !== 'booked') {
      return res.status(400).json({ success: false, message: 'Only active bookings can be cancelled' });
    }
    
    // Start transaction
    db.beginTransaction(err => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Transaction error' });
      }
      
      // Update booking status
      const updateBookingQuery = `
        UPDATE parking_bookings 
        SET status = 'cancelled', booking_end_time = NOW() 
        WHERE booking_id = ?
      `;
      
      db.query(updateBookingQuery, [bookingId], (err) => {
        if (err) {
          return db.rollback(() => {
            res.status(500).json({ success: false, message: 'Error updating booking' });
          });
        }
        
        // Update slot status
        const updateSlotQuery = `
          UPDATE parking_slots 
          SET status = 'available' 
          WHERE slot_number = ? AND basement_level = ? AND vehicle_type = ?
        `;
        
        db.query(updateSlotQuery, [booking.slot_number, booking.basement_level, booking.vehicle_type], (err) => {
          if (err) {
            return db.rollback(() => {
              res.status(500).json({ success: false, message: 'Error updating slot' });
            });
          }
          
          // If payment was made, process refund
          if (booking.payment_status === 'paid') {
            // In a real app, you would integrate with payment gateway here
            const updatePaymentQuery = `
              UPDATE parking_bookings 
              SET payment_status = 'refunded' 
              WHERE booking_id = ?
            `;
            
            db.query(updatePaymentQuery, [bookingId], (err) => {
              if (err) {
                return db.rollback(() => {
                  res.status(500).json({ success: false, message: 'Error updating payment status' });
                });
              }
              
              db.commit(err => {
                if (err) {
                  return db.rollback(() => {
                    res.status(500).json({ success: false, message: 'Commit error' });
                  });
                }
                
                res.json({ success: true, message: 'Booking cancelled and refund processed' });
              });
            });
          } else {
            db.commit(err => {
              if (err) {
                return db.rollback(() => {
                  res.status(500).json({ success: false, message: 'Commit error' });
                });
              }
              
              res.json({ success: true, message: 'Booking cancelled successfully' });
            });
          }
        });
      });
    });
  });
});

// Get user profile data
app.get('/user-profile', authenticate, (req, res) => {
  // Get user details
  const userQuery = 'SELECT firstName, lastName, ownerEmail, ownerPhone FROM useradmin WHERE id = ?';
  db.query(userQuery, [req.user.id], (err, userResults) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ success: false, message: 'Database error' });
    }

    if (userResults.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    // Get user's vehicles (just the first one for the vehicle number)
    const vehicleQuery = 'SELECT id FROM vehicles WHERE user_id = ? LIMIT 1';
    db.query(vehicleQuery, [req.user.id], (err, vehicleResults) => {
      if (err) {
        console.error('Database error:', err);
        return res.status(500).json({ success: false, message: 'Database error' });
      }

      const user = userResults[0];
      const response = {
        success: true,
        profile: {
          name: `${user.firstName} ${user.lastName}`,
          email: user.ownerEmail,
          phone: user.ownerPhone,
          vehicleNo: vehicleResults.length > 0 ? `VEH-${vehicleResults[0].id}` : 'No vehicle registered'
        }
      };

      res.json(response);
    });
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
