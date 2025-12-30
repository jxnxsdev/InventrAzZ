import colors from 'colors';
import path from 'path';
import fs from 'fs';

let logPath: string = '';
let logFile: string = '';
let logs: string[] = [];
let fsFile: fs.WriteStream | null = null;

async function openFileStream(): Promise<void> {
  try {
    if (!logPath || !logFile) {
      throw new Error('Log path or log file name is not defined.');
    }

    const filePath = path.join(logPath, logFile);

    if (fsFile) {
      fsFile.close();
    }

    fsFile = fs.createWriteStream(filePath, { flags: 'a' });
  } catch (err) {
    console.error(
      colors.red(
        `[Logger Error] Failed to open file stream: ${(err as Error).message}`
      )
    );
  }
}

async function writeLog(msg: string): Promise<void> {
  try {
    if (!fsFile) {
      await openFileStream();
    }

    if (fsFile) {
      fsFile.write(`${msg}\n`);
    } else {
      throw new Error('File stream is not available.');
    }
  } catch (err) {
    console.error(
      colors.red(
        `[Logger Error] Failed to write log: ${(err as Error).message}`
      )
    );
  }
}

async function generateFileName(): Promise<string> {
  const date = new Date();
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}_${String(date.getHours()).padStart(2, '0')}-${String(date.getMinutes()).padStart(2, '0')}.log`;
}

export async function init(logFilePath: string): Promise<void> {
  try {
    if (!fs.existsSync(logFilePath)) {
      fs.mkdirSync(logFilePath, { recursive: true });
    }

    logPath = logFilePath;
    logFile = await generateFileName();

    await openFileStream();

    const time = new Date().toLocaleTimeString();
    const msg = `[${time}] Logger initialized`;

    console.log(colors.green(msg));
    logs.push(msg);
    await writeLog(msg);
  } catch (err) {
    console.error(
      colors.red(
        `[Logger Error] Failed to initialize logger: ${(err as Error).message}`
      )
    );
  }
}

export async function close(): Promise<void> {
  try {
    if (fsFile) {
      fsFile.close();
    }
  } catch (err) {
    console.error(
      colors.red(
        `[Logger Error] Failed to close logger: ${(err as Error).message}`
      )
    );
  }
}

export async function info(msg: string): Promise<void> {
  const time = new Date().toLocaleTimeString();
  const formattedMsg = `[${time}] INFO: ${msg}`;

  try {
    console.log(colors.green(formattedMsg));
    logs.push(formattedMsg);
    await writeLog(formattedMsg);
  } catch (err) {
    console.error(
      colors.red(
        `[Logger Error] Failed to log info message: ${(err as Error).message}`
      )
    );
  }
}

export async function error(msg: string): Promise<void> {
  const time = new Date().toLocaleTimeString();
  const formattedMsg = `[${time}] ERROR: ${msg}`;

  try {
    console.error(colors.red(formattedMsg));
    logs.push(formattedMsg);
    await writeLog(formattedMsg);
  } catch (err) {
    console.error(
      colors.red(
        `[Logger Error] Failed to log error message: ${(err as Error).message}`
      )
    );
  }
}
