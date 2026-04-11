export function toStorageUrl(filePath: string | null | undefined) {
  if (!filePath) {
    return null;
  }

  const normalized = filePath.replace(/\\/g, '/');
  const storageIndex = normalized.toLowerCase().lastIndexOf('/storage/');
  if (storageIndex >= 0) {
    return normalized.slice(storageIndex);
  }

  if (normalized.toLowerCase().startsWith('storage/')) {
    return `/${normalized}`;
  }

  return null;
}

export function isPreviewableImage(filePath: string | null | undefined, mimeType: string | null | undefined) {
  if (mimeType?.startsWith('image/')) {
    return true;
  }

  return /\.(png|jpg|jpeg|gif|webp)$/i.test(filePath ?? '');
}