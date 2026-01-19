import {NtExecutable, NtExecutableResource, Resource} from '@shockpkg/resedit';
import {createWindowsIconPngList} from './icon-images';

const toUint8Array = (data) => {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (data && data.buffer instanceof ArrayBuffer) {
    return new Uint8Array(data.buffer, data.byteOffset || 0, data.byteLength || data.buffer.byteLength);
  }
  throw new TypeError('Unsupported binary input');
};

export const patchWindowsExecutableIcon = async (exeData, baseIconPngData) => {
  const exeBytes = toUint8Array(exeData);
  const exe = NtExecutable.from(exeBytes, {ignoreCert: true});
  const res = NtExecutableResource.from(exe);

  const iconGroups = Resource.IconGroupEntry.fromEntries(res.entries);
  if (iconGroups.length === 0) {
    throw new Error('No icon group resources found');
  }
  const group = iconGroups[0];

  const iconPngs = await createWindowsIconPngList(baseIconPngData);
  Resource.IconGroupEntry.replaceIconsForResource(
    res.entries,
    group.id,
    group.lang,
    iconPngs
  );

  res.outputResource(exe);
  const output = exe.generate();
  return output instanceof Uint8Array ? output : new Uint8Array(output);
};
