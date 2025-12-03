const express = require('express');


const cors = require('cors');
const mongoose = require('mongoose');

const app=express();
app.get('/', (req, res) => {
  res.send('Hello World!');
});

PORT=5000;
app.listen(5000, () => {
  console.log("Server running on http://localhost:5000");
});


