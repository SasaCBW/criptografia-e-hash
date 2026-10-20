
"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const $ = id => document.getElementById(id);

  const toast = $("toast");
  let toastTimeout;

  function notify(message) {
    toast.textContent = message;
    toast.classList.add("show");
    clearTimeout(toastTimeout);
    toastTimeout = setTimeout(() => {
      toast.classList.remove("show");
    }, 3000);
  }

  function setBusy(button, busy, label) {
    if (busy) {
      button.dataset.originalText = button.innerHTML;
      button.disabled = true;
      button.textContent = label;
    } else {
      button.disabled = false;
      button.innerHTML = button.dataset.originalText || label;
    }
  }

  function showResult(id) {
    $(id).classList.remove("hidden");
  }

  function hideResult(id) {
    $(id).classList.add("hidden");
  }

  function showError(error) {
    notify(error instanceof Error ? error.message : "Ocorreu um erro.");
  }

  // Alternância entre ferramentas
  document.querySelectorAll(".lab-tab").forEach(button => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".lab-tab").forEach(tab => {
        const active = tab === button;
        tab.classList.toggle("active", active);
        tab.setAttribute("aria-selected", String(active));
      });

      document.querySelectorAll(".lab-panel").forEach(panel => {
        panel.classList.add("hidden");
      });

      $("panel-" + button.dataset.tab).classList.remove("hidden");
    });
  });

  // Contador de caracteres
  $("encrypt-text").addEventListener("input", event => {
    $("encrypt-count").textContent =
      `${event.target.value.length} / 10000`;
  });

  // Criptografia
  $("encrypt-button").addEventListener("click", async event => {
    const button = event.currentTarget;
    const text = $("encrypt-text").value;
    const password = $("encrypt-password").value;

    hideResult("encrypt-result");

    if (!text) {
      notify("Digite uma mensagem para criptografar.");
      return;
    }

    if (password.length < 8) {
      notify("Utilize uma senha com pelo menos 8 caracteres.");
      return;
    }

    setBusy(button, true, "Criptografando...");

    try {
      const encrypted = await window.CofreCrypto.encryptText(
        text,
        password
      );

      $("encrypt-output").value = encrypted;
      showResult("encrypt-result");
      notify("Mensagem criptografada com sucesso.");
    } catch (error) {
      showError(error);
    } finally {
      setBusy(button, false, "Criptografar");
    }
  });

  // Descriptografia
  $("decrypt-button").addEventListener("click", async event => {
    const button = event.currentTarget;
    const text = $("decrypt-text").value.trim();
    const password = $("decrypt-password").value;

    hideResult("decrypt-result");

    if (!text || !password) {
      notify("Informe a mensagem e a senha.");
      return;
    }

    setBusy(button, true, "Descriptografando...");

    try {
      const decrypted = await window.CofreCrypto.decryptText(
        text,
        password
      );

      $("decrypt-output").value = decrypted;
      showResult("decrypt-result");
      notify("Mensagem recuperada com sucesso.");
    } catch (error) {
      showError(error);
    } finally {
      setBusy(button, false, "Descriptografar");
    }
  });

  // Hash SHA-256
  $("hash-button").addEventListener("click", async event => {
    const button = event.currentTarget;
    const text = $("hash-text").value;

    hideResult("hash-result");
    $("compare-result").classList.add("hidden");

    setBusy(button, true, "Gerando hash...");

    try {
      const hash = await window.CofreCrypto.hashText(text);
      $("hash-output").value = hash;
      showResult("hash-result");
      notify("Hash SHA-256 gerado.");
    } catch (error) {
      showError(error);
    } finally {
      setBusy(button, false, "Gerar hash SHA-256");
    }
  });

  // Comparação de integridade
  $("compare-button").addEventListener("click", async event => {
    const button = event.currentTarget;
    const text = $("hash-text").value;
    const expected = $("compare-hash").value.trim().toLowerCase();
    const result = $("compare-result");

    result.className = "compare-result hidden";

    if (!expected) {
      notify("Cole o hash original para fazer a comparação.");
      return;
    }

    if (!/^[a-f0-9]{64}$/.test(expected)) {
      notify("O hash SHA-256 deve conter 64 caracteres hexadecimais.");
      return;
    }

    setBusy(button, true, "Comparando...");

    try {
      const actual = await window.CofreCrypto.hashText(text);
      const matches = actual === expected;

      result.textContent = matches
        ? "✓ Os hashes correspondem. O texto corresponde ao conteúdo esperado."
        : "✕ Os hashes são diferentes. O texto não corresponde ao hash informado.";

      result.className = `compare-result ${
        matches ? "success" : "failure"
      }`;

      notify(matches ? "Hashes correspondentes." : "Hashes diferentes.");
    } catch (error) {
      showError(error);
    } finally {
      setBusy(button, false, "Comparar hash");
    }
  });

  // Copiar resultados
  document.querySelectorAll("[data-copy]").forEach(button => {
    button.addEventListener("click", async () => {
      const target = $(button.dataset.copy);

      try {
        await navigator.clipboard.writeText(target.value);
        notify("Resultado copiado.");
      } catch {
        target.focus();
        target.select();
        notify("Selecione o conteúdo e copie manualmente.");
      }
    });
  });
});
