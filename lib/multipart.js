'use strict';

/**
 * Minimal, dependency-free `multipart/form-data` parser for Node's http server.
 *
 * Handles text fields and file parts (with filename and content-type).
 * The whole request body is buffered by the caller (acceptable for this project).
 */

const CRLF = Buffer.from('\r\n');

/**
 * Parse a multipart body.
 * @param {Buffer} body
 * @param {string} boundary
 * @returns {Array<{name: string, filename?: string, contentType?: string, value: Buffer}>}
 */
function parseMultipart(body, boundary) {
  const parts = [];
  const delimiter = Buffer.from('--' + boundary);
  let pos = 0;

  while (true) {
    // Find the next delimiter
    const delimStart = body.indexOf(delimiter, pos);
    if (delimStart === -1) break;

    let headerEnd = body.indexOf(CRLF + CRLF, delimStart + delimiter.length);
    if (headerEnd === -1) break;

    // Check for closing delimiter "--boundary--"
    const afterDelim = delimStart + delimiter.length;
    if (body[afterDelim] === 0x2d && body[afterDelim + 1] === 0x2d) {
      break; // end of multipart
    }

    const headerBlock = body.subarray(afterDelim + 2, headerEnd).toString('utf8'); // skip CRLF after boundary
    const dataStart = headerEnd + 4; // skip CRLF CRLF

    // Find the next delimiter to locate the end of this part's data
    const nextDelim = body.indexOf(delimiter, dataStart);
    if (nextDelim === -1) break;

    // Data ends at CRLF before the next delimiter
    let dataEnd = nextDelim;
    if (dataEnd >= 2 && body[dataEnd - 2] === 0x0d && body[dataEnd - 1] === 0x0a) {
      dataEnd -= 2;
    }

    // Parse headers
    const part = { name: null, value: body.subarray(dataStart, dataEnd) };
    const contentDisposition = /content-disposition:\s*([^\r\n]+)/i.exec(headerBlock);
    if (contentDisposition) {
      const nameMatch = /name="([^"]*)"/i.exec(contentDisposition[1]);
      if (nameMatch) part.name = nameMatch[1];
      const filenameMatch = /filename="([^"]*)"/i.exec(contentDisposition[1]);
      if (filenameMatch) part.filename = filenameMatch[1];
    }
    const contentType = /content-type:\s*([^\r\n]+)/i.exec(headerBlock);
    if (contentType) part.contentType = contentType[1].trim();

    parts.push(part);
    pos = nextDelim;
  }

  return parts;
}

module.exports = { parseMultipart };
