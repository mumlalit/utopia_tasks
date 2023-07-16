import { Request, Response, Router } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import config from '../config';
import User, { IUser } from '../models/User';

const router: Router = Router();

router.post('/signup', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser: IUser = new User({ email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    console.error('Error during signup:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const accessToken = jwt.sign({ userId: user._id }, config.jwtSecret, {
      expiresIn: config.jwtExpiration,
    });

    const refreshToken = jwt.sign({ userId: user._id }, config.jwtSecret, {
      expiresIn: config.refreshTokenExpiration,
    });

    res.json({ accessToken, refreshToken });
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

router.post('/refresh-token', (req: Request, res: Response) => {
  const refreshToken = req.body.refreshToken;

  try {
    const decoded = jwt.verify(refreshToken, config.jwtSecret) as {
      userId: string;
    };

    const accessToken = jwt.sign({ userId: decoded.userId }, config.jwtSecret, {
      expiresIn: config.jwtExpiration,
    });

    res.json({ accessToken });
  } catch (error) {
    console.error('Error during token refresh:', error);
    res.status(401).json({ error: 'Invalid refresh token' });
  }
});

export default router;
