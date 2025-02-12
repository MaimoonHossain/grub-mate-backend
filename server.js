const express = require('express');
const connectDB = require('./config/db');
const dotenv = require('dotenv');
const cors = require('cors');

dotenv.config();
connectDB();

const app = express();

app.use(express.json());
app.use(cors());

app.use('/api/auth', require('./routes/authRoutes'));

app.get('/', (req, res) => res.send('GrubMate API Running 🚀'));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT} 🚀`));
