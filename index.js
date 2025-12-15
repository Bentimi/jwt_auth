const express = require('express');
const app = express();
const morgan = require('morgan');
const connectDB = require('./src/config/db');
require('dotenv').config();

const userRoutes = require('./src/routes/user.routes')

const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(morgan('dev'));



app.get('/', (req, res) => {
    res.send('Authentication Service is Running');
})

app.use('/users', userRoutes)


app.listen(PORT, () => {
    connectDB();
    console.log(`Server is running  on http://localhost:${PORT}`);
})