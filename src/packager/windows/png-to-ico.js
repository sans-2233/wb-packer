import {createWindowsIconPngList} from './icon-images';

export const pngToIco = async (basePngData, sizes = [256, 128, 64, 48, 32, 16]) => {
  const pngs = await createWindowsIconPngList(basePngData, sizes);
  const count = pngs.length;
  const headerSize = 6 + (count * 16);
  let imageOffset = headerSize;
  let totalSize = headerSize;
  for (const png of pngs) totalSize += png.byteLength;

  const out = new Uint8Array(totalSize);
  const dv = new DataView(out.buffer);
  dv.setUint16(0, 0, true);
  dv.setUint16(2, 1, true);
  dv.setUint16(4, count, true);

  for (let i = 0; i < count; i++) {
    const size = sizes[i] | 0;
    const png = pngs[i];
    const entryOffset = 6 + (i * 16);
    dv.setUint8(entryOffset + 0, size === 256 ? 0 : size);
    dv.setUint8(entryOffset + 1, size === 256 ? 0 : size);
    dv.setUint8(entryOffset + 2, 0);
    dv.setUint8(entryOffset + 3, 0);
    dv.setUint16(entryOffset + 4, 1, true);
    dv.setUint16(entryOffset + 6, 32, true);
    dv.setUint32(entryOffset + 8, png.byteLength, true);
    dv.setUint32(entryOffset + 12, imageOffset, true);
    out.set(png, imageOffset);
    imageOffset += png.byteLength;
  }

  return out.buffer.slice(out.byteOffset, out.byteOffset + out.byteLength);
};

