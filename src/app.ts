import express, { Application, Request, Response } from 'express';
import mongoose, { ConnectOptions } from 'mongoose';
import config from './config';
import authRoutes from './routes/auth';
import { authenticateToken } from './middleware/auth';

const app: Application = express();
const port = 3000;

app.use(express.json());

// Connect to MongoDB
const mongooseOptions: ConnectOptions = {
  useCreateIndex: true,
  useNewUrlParser: true,
  useUnifiedTopology: true,
}as any;

mongoose
  .connect(config.mongoURI, mongooseOptions)
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch((error) => {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  });

// Routes
app.use('/auth', authRoutes);

// Protected route
app.get('/protected', authenticateToken, (req: Request, res: Response) => {
  res.json({ message: 'Protected route accessed successfully' });
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
