
"use strict";

const CofreCrypto = (() => {
  const ITERATIONS = 310000;
  const encoder = new TextEncoder();
  const decoder = new TextDecoder("utf-8", { fatal: true });

  function toBase64(bytes) {
    let binary = "";
    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }
    return btoa(binary);
  }

  function fromBase64(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, char => char.charCodeAt(0));
  }

  async function deriveKey(password, salt) {
    const material = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: ITERATIONS,
        hash: "SHA-256"
      },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptText(text, password) {
    if (typeof text !== "string" || text.length === 0) {
      throw new Error("Digite uma mensagem antes de criptografar.");
    }

    if (typeof password !== "string" || password.length < 8) {
      throw new Error("A senha precisa ter pelo menos 8 caracteres.");
    }

    if (!crypto.subtle) {
      throw new Error(
        "Criptografia indisponível. Abra o site por HTTPS."
      );
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt);

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      key,
      encoder.encode(text)
    );

    return JSON.stringify({
      version: 1,
      algorithm: "AES-GCM",
      kdf: "PBKDF2-SHA256",
      iterations: ITERATIONS,
      salt: toBase64(salt),
      iv: toBase64(iv),
      data: toBase64(new Uint8Array(encrypted))
    });
  }

  async function decryptText(serialized, password) {
    if (!serialized || !password) {
      throw new Error("Informe o conteúdo e a senha.");
    }

    if (!crypto.subtle) {
      throw new Error(
        "Criptografia indisponível. Abra o site por HTTPS."
      );
    }

    let payload;

    try {
      payload = JSON.parse(serialized);
    } catch {
      throw new Error("O conteúdo não é um arquivo criptografado válido.");
    }

    if (
      payload.version !== 1 ||
      payload.algorithm !== "AES-GCM" ||
      payload.kdf !== "PBKDF2-SHA256" ||
      payload.iterations !== ITERATIONS ||
      typeof payload.salt !== "string" ||
      typeof payload.iv !== "string" ||
      typeof payload.data !== "string"
    ) {
      throw new Error("Formato de criptografia não reconhecido.");
    }

    try {
      const salt = fromBase64(payload.salt);
      const iv = fromBase64(payload.iv);
      const encrypted = fromBase64(payload.data);

      if (
        salt.length !== 16 ||
        iv.length !== 12 ||
        encrypted.length < 16 ||
        encrypted.length > 10010000
      ) {
        throw new Error("Tamanho de conteúdo inválido.");
      }

      const key = await deriveKey(password, salt);

      const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, tagLength: 128 },
        key,
        encrypted
      );

      return decoder.decode(decrypted);
    } catch {
      throw new Error(
        "Não foi possível descriptografar. Confira a senha e o conteúdo."
      );
    }
  }

  async function hashText(text) {
    if (!crypto.subtle) {
      throw new Error(
        "SHA-256 indisponível. Abra o site por HTTPS."
      );
    }

    const digest = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(text)
    );

    return Array.from(new Uint8Array(digest))
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("");
  }

  return Object.freeze({
    encryptText,
    decryptText,
    hashText
  });
})();

window.CofreCrypto = CofreCrypto;
