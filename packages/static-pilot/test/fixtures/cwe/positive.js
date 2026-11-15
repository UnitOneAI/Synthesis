import { exec } from 'node:child_process';
const options = { rejectUnauthorized: false };
exec(`echo ${userInput}`);
