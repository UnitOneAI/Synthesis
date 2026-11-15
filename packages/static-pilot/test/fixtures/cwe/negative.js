import { execFile } from 'node:child_process';
const options = { rejectUnauthorized: true };
execFile('echo', [userInput]);
