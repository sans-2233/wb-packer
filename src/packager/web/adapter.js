import assetCache from './cache';
import request from '../../common/request';
import {readAsURL, readAsArrayBuffer} from '../../common/readers';
import defaultIcon from '../images/default-icon.png';

class WebAdapter {
  async getCachedAsset (asset) {
    try {
      const sha256 = asset && asset.sha256;
      const api = (typeof window !== 'undefined') ? window.PackagerLargeAssetsCachePreload : null;
      if (sha256 && api && typeof api.get === 'function') {
        const cached = await api.get(String(sha256).toLowerCase());
        if (cached) return cached;
      }
    } catch (e) {}
    return assetCache.get(asset);
  }

  async cacheAsset (asset, result) {
    try {
      const sha256 = asset && asset.sha256;
      const api = (typeof window !== 'undefined') ? window.PackagerLargeAssetsCachePreload : null;
      if (sha256 && api && typeof api.set === 'function') {
        await api.set(String(sha256).toLowerCase(), result);
      }
    } catch (e) {}
    await assetCache.set(asset, result);
  }

  getAppIcon (file) {
    if (!file) {
      return request({
        url: defaultIcon,
        type: 'arraybuffer'
      });
    }
    // Convert to PNG
    if (file.type === 'image/png') {
      return readAsArrayBuffer(file);
    }
    return new Promise((resolve, reject) => {
      const url = URL.createObjectURL(file);
      const image = new Image();
      image.onload = () => {
        image.onload = null;
        image.onerror = null;
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        if (!ctx) {
          reject(new Error('Cannot get rendering context for icon conversion'));
          return;
        }
        canvas.width = image.width;
        canvas.height = image.height;
        ctx.drawImage(image, 0, 0);
        canvas.toBlob((blob) => {
          URL.revokeObjectURL(url);
          resolve(readAsArrayBuffer(blob));
        });
      };
      image.onerror = () => {
        image.onload = null;
        image.onerror = null;
        reject(new Error('Cannot load icon'));
      };
      image.src = url;
    });
  }

  readAsURL (file, debugInfo) {
    return readAsURL(file)
      .catch((err) => {
        throw new Error(`${debugInfo}: ${err}`);
      });
  }

  fetchExtensionScript (url) {
    return request({
      type: 'text',
      url: url
    });
  }
}

export default WebAdapter;
