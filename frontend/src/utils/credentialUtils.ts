/**
 * 统一处理 credential ID 的格式转换工具
 */

/**
 * 将 ArrayBuffer 转换为 base64url 格式的字符串
 */
export const arrayBufferToBase64Url = (buffer: ArrayBuffer): string => {
  const uint8Array = new Uint8Array(buffer);
  const base64 = btoa(String.fromCharCode(...uint8Array));
  return base64ToBase64Url(base64);
};

/**
 * 将 base64 字符串转换为 base64url 格式
 */
export const base64ToBase64Url = (base64: string): string => {
  return base64
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
};

/**
 * 标准化 credential ID 格式
 * 确保输出为纯 base64url 格式（无填充字符）
 */
export const normalizeCredentialId = (credentialId: string | ArrayBuffer | undefined): string | undefined => {
  if (!credentialId) return undefined;
  
  // 如果是 ArrayBuffer，转换为 base64url
  if (credentialId instanceof ArrayBuffer) {
    return arrayBufferToBase64Url(credentialId);
  }
  
  // 如果是字符串，确保是 base64url 格式
  if (typeof credentialId === 'string') {
    return base64ToBase64Url(credentialId);
  }
  
  return undefined;
};

/**
 * 格式化认证响应对象
 * 确保 id 和 rawId 字段格式正确
 */
export const formatAuthenticationResponse = (response: any): any => {
  if (!response) return response;

  const formattedResponse = { ...response };

  // 处理 id 字段
  if (response.id) {
    formattedResponse.id = normalizeCredentialId(response.id);
  }

  // 如果只有 rawId，用它生成 id
  if (!formattedResponse.id && response.rawId) {
    formattedResponse.id = normalizeCredentialId(response.rawId);
  }

  // 确保 rawId 也是正确格式
  if (response.rawId) {
    formattedResponse.rawId = normalizeCredentialId(response.rawId);
  }

  return formattedResponse;
}; 