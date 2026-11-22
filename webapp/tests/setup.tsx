// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

import {webcrypto} from 'node:crypto';
import {TextDecoder, TextEncoder} from 'node:util';

import '@testing-library/jest-dom';

// jsdom doesn't support pseudo-element styles and logs an error whenever user-event asks for one.
const getComputedStyle = window.getComputedStyle.bind(window);
window.getComputedStyle = (element: Element) => getComputedStyle(element);

// jsdom has no WebCrypto subtle API or TextEncoder; use Node's, which implement the same standards.
Object.defineProperty(globalThis, 'crypto', {value: webcrypto});
Object.assign(globalThis, {TextEncoder, TextDecoder});

// jsdom's Blob lacks arrayBuffer(); read it through FileReader, which jsdom does implement.
if (!Blob.prototype.arrayBuffer) {
    Blob.prototype.arrayBuffer = function arrayBuffer(this: Blob) {
        return new Promise<ArrayBuffer>((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = () => resolve(reader.result as ArrayBuffer);
            reader.onerror = () => reject(reader.error);
            reader.readAsArrayBuffer(this);
        });
    };
}
