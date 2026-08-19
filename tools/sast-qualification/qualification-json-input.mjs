import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { resolve } from 'node:path';

export async function readQualificationJson(path, maximumBytes, label) {
  const absolute = resolve(path);
  const before = await lstat(absolute, { bigint: true });
  if (
    !before.isFile() ||
    before.isSymbolicLink() ||
    before.nlink !== 1n ||
    before.size < 1n ||
    before.size > BigInt(maximumBytes)
  ) {
    throw new Error(`${label} is not a bounded single-link regular file`);
  }
  const canonicalBefore = await realpath(absolute);
  let handle;
  try {
    handle = await open(absolute, constants.O_RDONLY | noFollowFlag());
    const opened = await handle.stat({ bigint: true });
    if (!sameFile(before, opened)) throw new Error(`${label} changed before read`);
    const buffer = Buffer.alloc(Number(opened.size));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead !== buffer.length) throw new Error(`${label} was not read completely`);
    const openedAfter = await handle.stat({ bigint: true });
    const after = await lstat(absolute, { bigint: true });
    const canonicalAfter = await realpath(absolute);
    if (
      !sameFile(opened, openedAfter) ||
      !sameFile(before, after) ||
      canonicalAfter !== canonicalBefore
    ) {
      throw new Error(`${label} changed during read`);
    }
    const text = decodeCanonicalText(buffer, label);
    let value;
    try {
      value = JSON.parse(text);
    } catch {
      throw new Error(`${label} is not valid JSON`);
    }
    return Object.freeze({ path: canonicalBefore, text, value });
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

export function parseExactArguments(argv, specification) {
  const result = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (
      typeof name !== 'string' ||
      !Object.prototype.hasOwnProperty.call(specification, name) ||
      typeof value !== 'string' ||
      value.length === 0 ||
      Object.prototype.hasOwnProperty.call(result, name)
    ) {
      throw new Error('invalid or duplicate qualification tool argument');
    }
    result[name] = value;
  }
  for (const [name, required] of Object.entries(specification)) {
    if (required && !Object.prototype.hasOwnProperty.call(result, name)) {
      throw new Error(`missing required qualification tool argument: ${name}`);
    }
  }
  return Object.freeze(result);
}

function decodeCanonicalText(buffer, label) {
  if (
    buffer.length >= 3 &&
    buffer[0] === 0xef &&
    buffer[1] === 0xbb &&
    buffer[2] === 0xbf
  ) {
    throw new Error(`${label} must not contain a BOM`);
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    throw new Error(`${label} must be canonical UTF-8`);
  }
  if (
    text.includes('\u0000') ||
    text.includes('\r') ||
    !text.endsWith('\n') ||
    text !== text.normalize('NFC') ||
    Buffer.from(text, 'utf8').compare(buffer) !== 0
  ) {
    throw new Error(`${label} must use canonical NFC UTF-8 with LF and a final newline`);
  }
  return text;
}

function noFollowFlag() {
  return typeof constants.O_NOFOLLOW === 'number' ? constants.O_NOFOLLOW : 0;
}

function sameFile(left, right) {
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode &&
    left.nlink === right.nlink &&
    left.size === right.size &&
    left.mtimeNs === right.mtimeNs &&
    left.ctimeNs === right.ctimeNs
  );
}
