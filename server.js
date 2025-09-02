const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads')); // Serve uploaded files

// MongoDB connection
mongoose.connect('mongodb://localhost:27018/farm2market', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Could not connect to MongoDB:', err));

// Configure multer for image upload
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads/'); // Directory to store uploaded files
  },
  filename: function (req, file, cb) {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname)); // Generate unique filename
  }
});

const fileFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image/')) {
    cb(null, true);
  } else {
    cb(new Error('Not an image! Please upload an image.'), false);
  }
};

const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB size limit
  }
});

// User Schema
const userSchema = new mongoose.Schema({
  username: { 
    type: String, 
    required: true,
    trim: true
  },
  email: { 
    type: String, 
    required: true, 
    unique: true,
    trim: true,
    lowercase: true
  },
  password: { 
    type: String, 
    required: true 
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', userSchema);

// Crop Schema
const cropSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  postType: {
    type: String,
    enum: ['sell', 'rent', 'inquiry'],
    required: true
  },
  category: {
    type: String,
    required: true
  },
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    required: true,
    trim: true
  },
  quantity: {
    type: Number,
    required: true,
    min: 0
  },
  quantityType: {
    type: String,
    required: true
  },
  price: {
    type: Number,
    required: true,
    min: 0
  },
  priceType: {
    type: String,
    required: true
  },
  availableFrom: {
    type: Date,
    required: true
  },
  mobileNo: {
    type: String,
    required: true,
    trim: true
  },
  address: {
    type: String,
    required: true,
    trim: true
  },
  state: {
    type: String,
    required: true
  },
  district: {
    type: String,
    required: true
  },
  subDistrict: String,
  village: String,
  imageUrl: String, // Optional image field
  status: {
    type: String,
    enum: ['active', 'sold', 'expired'],
    default: 'active'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

// Update the updatedAt timestamp before saving
cropSchema.pre('save', function(next) {
  this.updatedAt = Date.now();
  next();
});

const Crop = mongoose.model('Crop', cropSchema);

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided.' });
  }

  jwt.verify(token, 'your_jwt_secret', (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Auth Routes
app.post('/api/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({
      username,
      email,
      password: hashedPassword,
    });

    await user.save();

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      'your_jwt_secret',
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: 'All fields are required' });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      'your_jwt_secret',
      { expiresIn: '24h' }
    );

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in' });
  }
});

// Define allowed values for certain fields
const allowedCategories = ['vegetable', 'fruit', 'grain', 'herb'];
const allowedQuantityTypes = ['liter', 'kg', 'box'];
const allowedPriceTypes = ['liter', 'kg', 'box'];
const allowedStates = ['Maharashtra', 'Karnataka', 'Uttar Pradesh', 'Tamil Nadu']; // Example states
const allowedDistricts = ['Pune', 'Mumbai', 'Nagpur', 'Jalgaon', 'Nashik', 'Latur', 'Dhule', 'Jalna']; // Example districts
const postTypes = ['sell', 'rent', 'inquiry'];
const statusTypes = ['active', 'sold', 'expired'];


app.post('/api/crops/add', authenticateToken, upload.single('image'), async (req, res) => {
  try {
    let requestData;
    if (req.is('multipart/form-data')) {
      // Handle file upload
      requestData = {
        ...req.body,
        imageUrl: req.file ? `/uploads/${req.file.filename}` : null
      };
    } else {
      // Handle JSON request with URL
      requestData = req.body;
    }

    // Validate required fields
    const { postType, category, title, description, quantity, quantityType, 
            price, priceType, availableFrom, mobileNo, address, state, district } = requestData;

    if (!postType || !category || !title || !description || !quantity || 
        !quantityType || !price || !priceType || !availableFrom || 
        !mobileNo || !address || !state || !district) {
      return res.status(400).json({ message: 'All required fields must be provided' });
    }

    // Validate the allowed options
    if (!allowedCategories.includes(category)) {
      return res.status(400).json({ message: 'Invalid category' });
    }
    if (!allowedQuantityTypes.includes(quantityType)) {
      return res.status(400).json({ message: 'Invalid quantity type' });
    }
    if (!allowedPriceTypes.includes(priceType)) {
      return res.status(400).json({ message: 'Invalid price type' });
    }
    if (!allowedStates.includes(state)) {
      return res.status(400).json({ message: 'Invalid state' });
    }
    if (!allowedDistricts.includes(district)) {
      return res.status(400).json({ message: 'Invalid district' });
    }

    const crop = new Crop({
      ...requestData,
      userId: req.user.userId
    });

    await crop.save();

    res.status(201).json({
      message: 'Crop added successfully',
      crop
    });
  } catch (error) {
    console.error('Error adding crop:', error.message);
    res.status(500).json({
      message: 'Error adding crop',
      error: error.message
    });
  }
});


app.get('/api/crops', async (req, res) => {
  try {
    const { state, district, category, postType } = req.query;
    const filter = { status: 'active' };

    if (state) filter.state = state;
    if (district) filter.district = district;
    if (category) filter.category = category;
    if (postType) filter.postType = postType;

    const crops = await Crop.find(filter)
      .sort({ createdAt: -1 })
      .populate('userId', 'username email');

    res.json(crops);
  } catch (error) {
    res.status(500).json({
      message: 'Error fetching crops',
      error: error.message
    });
  }
});

app.patch('/api/crops/:id', authenticateToken, async (req, res) => {
  try {
    const crop = await Crop.findOne({
      _id: req.params.id,
      userId: req.user.userId
    });

    if (!crop) {
      return res.status(404).json({ message: 'Crop not found or unauthorized' });
    }

    Object.assign(crop, req.body);
    await crop.save();

    res.json({
      message: 'Crop updated successfully',
      crop
    });
  } catch (error) {
    res.status(500).json({
      message: 'Error updating crop',
      error: error.message
    });
  }
});

app.delete('/api/crops/:id', authenticateToken, async (req, res) => {
  try {
    const crop = await Crop.findOneAndDelete({
      _id: req.params.id,
      userId: req.user.userId
    });

    if (!crop) {
      return res.status(404).json({ message: 'Crop not found or unauthorized' });
    }

    res.json({ message: 'Crop deleted successfully' });
  } catch (error) {
    res.status(500).json({
      message: 'Error deleting crop',
      error: error.message
    });
  }
});

const PORT = 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});




