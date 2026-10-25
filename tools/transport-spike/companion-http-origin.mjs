// Draft0.5 client-side byte helpers only; no DNS, socket, authorization or HTTP parser.
import { inspect } from 'node:util';
import { CompanionProtocolError } from './companion-protocol-codec.mjs';
export const HTTP_ORIGIN_CAPABILITY = 'tcp-http-origin-connect';
export const HTTP_ORIGIN_PROXY_MODE = 'http-origin-connect';
const acknowledgement = Buffer.from('HTTP/1.1 200 Connection Established\r\n\r\n', 'ascii');
const invalid = () => { throw new CompanionProtocolError('invalid_message'); };
export function encodeHttpOriginPreface(address, port = 80) {
  try {
  if (!(address instanceof Uint8Array) || ![4, 16].includes(address.byteLength) || port !== 80) invalid();
  const copy = Buffer.from(address);
  const host = copy.length === 4 ? [...copy].join('.') : '[' + Array.from({ length: 8 }, (_, index) => copy.readUInt16BE(index * 2).toString(16)).join(':') + ']';
  return Buffer.from(`CONNECT ${host}:80 HTTP/1.1\r\nHost: ${host}:80\r\n\r\n`, 'ascii');
  } catch { invalid(); }
}
export const httpOriginAcknowledgementBytes = () => Buffer.from(acknowledgement);
export class HttpOriginAcknowledgement {
  #offset = 0; #failed = false;
  get complete() { return !this.#failed && this.#offset === acknowledgement.length; }
  accept(bytes, start = 0, length) {
    if (this.#failed) invalid();
    const reject = () => { this.#failed = true; invalid(); };
    try {
    if (length === undefined) length = bytes?.byteLength - start;
    if (!(bytes instanceof Uint8Array) || !Number.isSafeInteger(start) || !Number.isSafeInteger(length) ||
        start < 0 || length < 0 || start > bytes.byteLength || length > bytes.byteLength - start) reject();
    const count = Math.min(length, acknowledgement.length - this.#offset);
    for (let index = 0; index < count; index++) {
      if (bytes[start + index] !== acknowledgement[this.#offset]) reject();
      this.#offset++;
    }
    return count;
    } catch { reject(); }
  }
  toString() { return `HttpOriginAcknowledgement(complete=${this.complete}, failed=${this.#failed})`; }
  toJSON() { return { complete: this.complete, failed: this.#failed }; }
  [inspect.custom]() { return this.toString(); }
}
