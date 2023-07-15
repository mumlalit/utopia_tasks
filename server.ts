// Utopia Backend Task
import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import mongoose from 'mongoose';

// Define MongoDB models and schemas
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
});

const User = mongoose.model('User', UserSchema);

// Create Express application
const app = express();
app.use(express.json());

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});


// Signup endpoint
app.post('/signup', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    // Check if the email is already registered
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create a new user
    const newUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint
app.post('/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    // Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare the password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate access token and refresh token
    const accessToken = jwt.sign({ userId: user._id }, 'secret', { expiresIn: '120s' });
    const refreshToken = jwt.sign({ userId: user._id }, 'refreshSecret');

    res.status(200).json({ accessToken, refreshToken });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Middleware to verify the access token
const verifyAccessToken = (req: Request, res: Response, next: Function) => {
  const accessToken = req.headers.authorization?.split(' ')[1];

  if (!accessToken) {
    return res.status(401).json({ error: 'Access token not provided' });
  }

  try {
    const decoded = jwt.verify(accessToken, 'secret');
    req.userId = decoded.userId;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid access token' });
  }
};

// Protected resource endpoint
app.get('/protected', verifyAccessToken, (req: Request, res: Response) => {
  res.status(200).json({ message: 'Protected resource accessed successfully' });
});

// Delete user endpoint
app.delete('/user', verifyAccessToken, async (req: Request, res: Response) => {
  try {
    const userId = req.userId;

    // Delete the user
    await User.findByIdAndRemove(userId);

    res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Refresh token endpoint
app.post('/refresh', (req: Request, res: Response) => {
  const refreshToken = req.body.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token not provided' });
  }

  try {
    const decoded = jwt.verify(refreshToken, 'refreshSecret');
    const accessToken = jwt.sign({ userId: decoded.userId }, 'secret', { expiresIn: '120s' });

    res.status(200).json({ accessToken });
  } catch (error) {
    return res.status(403).json({ error: 'Invalid refresh token' });
  }
});

// Start the server
app.listen(3000, () => {
  console.log('Server listening on port 3000');
});
