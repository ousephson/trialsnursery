const express = require('express');
const path = require('path');
const app = express();
const port = 3001;

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'app/app.html'));
});

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});