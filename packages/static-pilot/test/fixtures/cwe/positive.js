import { exec } from 'node:child_process';
const options = { rejectUnauthorized: false };
exec(`echo ${userInput}`);
localStorage.setItem('access_token', token);
document.body.innerHTML = location.hash;
