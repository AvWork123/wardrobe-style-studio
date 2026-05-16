const express = require('express');
const path = require('path');

const app = express();

app.use(express.static(path.join(__dirname, 'public')));

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'wardrobe.html'));
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`\n✦ Style Studio running at http://localhost:${PORT}`);
  console.log(`   Press Ctrl+C to stop.\n`);
});
