import { createApp } from './app.js';
import { appConfig } from './config.js';

const app = createApp();

app.listen(appConfig.port, () => {
  console.log(`Phish Hunter API listening on http://localhost:${appConfig.port}`);
});