const express = require('express');
const app = express();
const port = process.env.PORT || 8080;
const appName = process.env.APP_NAME || 'Default App';
const appVersion = process.env.APP_VERSION || '1.0.0';

app.get('/', (req, res) => {
  res.send(`Hello from ${appName} v${appVersion}!`);
});

app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

app.listen(port, '0.0.0.0', () => {
  console.log(`${appName} v${appVersion} listening on port ${port}`);
});