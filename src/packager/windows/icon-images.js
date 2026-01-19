import {readAsArrayBuffer} from '../../common/readers';
import {Data} from '@shockpkg/resedit';

const toUint8Array = (data) => {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (data && data.buffer instanceof ArrayBuffer) {
    return new Uint8Array(data.buffer, data.byteOffset || 0, data.byteLength || data.buffer.byteLength);
  }
  throw new TypeError('Unsupported binary input');
};

const imageFromPngBytes = (pngBytes) => new Promise((resolve, reject) => {
  const url = URL.createObjectURL(new Blob([pngBytes], {type: 'image/png'}));
  const image = new Image();
  const cleanup = () => {
    image.onload = null;
    image.onerror = null;
    URL.revokeObjectURL(url);
  };
  image.onload = () => {
    cleanup();
    resolve(image);
  };
  image.onerror = () => {
    cleanup();
    reject(new Error('Cannot load icon'));
  };
  image.src = url;
});

const renderPngAtSize = (image, size) => new Promise((resolve, reject) => {
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');
  if (!ctx) {
    reject(new Error('Cannot get rendering context for icon resizing'));
    return;
  }
  canvas.width = size;
  canvas.height = size;
  ctx.clearRect(0, 0, size, size);
  if (typeof ctx.imageSmoothingEnabled === 'boolean') {
    ctx.imageSmoothingEnabled = true;
  }
  if (typeof ctx.imageSmoothingQuality === 'string') {
    ctx.imageSmoothingQuality = 'high';
  }
  ctx.drawImage(image, 0, 0, size, size);
  canvas.toBlob((blob) => {
    if (!blob) {
      reject(new Error('Cannot encode resized icon'));
      return;
    }
    resolve(blob);
  }, 'image/png');
});

export const createWindowsIconPngList = async (basePngData, sizes = [256, 128, 64, 48, 32, 16]) => {
  const baseBytes = toUint8Array(basePngData);
  const image = await imageFromPngBytes(baseBytes);
  const results = [];
  for (const size of sizes) {
    const blob = await renderPngAtSize(image, size);
    const bytes = await readAsArrayBuffer(blob);
    results.push(new Uint8Array(bytes));
  }
  return results;
};

export const createWindowsIconRawItemList = async (basePngData, sizes = [256, 128, 64, 48, 32, 16]) => {
  const pngs = await createWindowsIconPngList(basePngData, sizes);
  const results = [];
  for (let i = 0; i < pngs.length; i++) {
    const size = sizes[i] | 0;
    results.push(Data.RawIconItem.from(pngs[i], size || 256, size || 256, 32));
  }
  return results;
};
