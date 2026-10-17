"use strict";
(() => {
  const messages = window.netinspectMessages;
  const names = {
    en: "English", "zh-CN": "简体中文", es: "Español", fr: "Français",
    de: "Deutsch", ja: "日本語", pt: "Português",
  };
  function matchLanguage(value) {
    if (typeof value !== "string") return null;
    const normalized = value.toLowerCase().replaceAll("_", "-");
    if (normalized === "zh" || normalized.startsWith("zh-")) return "zh-CN";
    const base = normalized.split("-")[0];
    return Object.hasOwn(messages, base) ? base : null;
  }
  function preferredLanguage() {
    try {
      const cookie = document.cookie.split(";").map((v) => v.trim())
        .find((v) => v.startsWith("netinspect.lang="));
      if (cookie) {
        const saved = matchLanguage(decodeURIComponent(cookie.slice("netinspect.lang=".length)));
        if (saved) return saved;
      }
    } catch {}
    for (const language of navigator.languages || [navigator.language]) {
      const matched = matchLanguage(language);
      if (matched) return matched;
    }
    return "en";
  }
  let language = preferredLanguage();
  function t(key, values = {}) {
    const text = messages[language]?.[key] ?? messages.en[key] ?? key;
    return text.replace(/\{(\w+)\}/g, (match, name) =>
      Object.hasOwn(values, name) ? String(values[name]) : match);
  }
  function apply() {
    document.documentElement.lang = language;
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      el.textContent = t(el.dataset.i18n);
    });
    for (const attribute of ["title", "aria-label", "placeholder"]) {
      document.querySelectorAll(`[data-i18n-${attribute}]`).forEach((el) => {
        el.setAttribute(attribute, t(el.getAttribute(`data-i18n-${attribute}`)));
      });
    }
    const select = document.getElementById("language");
    if (select) select.value = language;
  }
  function setLanguage(value) {
    const matched = matchLanguage(value);
    if (!matched) return;
    language = matched;
    try {
      document.cookie = `netinspect.lang=${encodeURIComponent(language)}; Path=/; Max-Age=31536000; SameSite=Lax`;
    } catch {}
    apply();
    window.dispatchEvent(new Event("netinspect:language"));
  }
  function init() {
    const select = document.getElementById("language");
    for (const [code, name] of Object.entries(names)) {
      const option = document.createElement("option");
      option.value = code;
      option.textContent = name;
      select.append(option);
    }
    select.onchange = () => setLanguage(select.value);
    apply();
  }
  window.netinspectI18n = { t, init, setLanguage, matchLanguage, get locale() { return language; } };
})();
