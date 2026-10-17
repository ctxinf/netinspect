// Run with: node --test scripts/test-i18n.cjs
const { test } = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");
const web = path.join(__dirname, "../internal/dashboard/web");
function load({ cookie = "", languages = ["en-US"], blockedCookie = false } = {}) {
  const elements = new Map();
  const element = (id) => {
    if (!elements.has(id)) elements.set(id, {
      dataset: {}, style: {}, children: [], classList: { toggle() {} },
      setAttribute(name, value) { this[name] = value; },
      append(value) { this.children.push(value); },
      querySelector(key) { return element(id + ":" + key); },
      showModal() { this.open = true; },
    });
    return elements.get(id);
  };
  const listeners = new Map();
  const document = {
    cookie, documentElement: { dataset: {} },
    querySelectorAll: () => [], getElementById: element,
    createElement: () => ({}), addEventListener() {},
  };
  if (blockedCookie) Object.defineProperty(document, "cookie", {
    get() { throw new Error("blocked"); }, set() { throw new Error("blocked"); },
  });
  const context = vm.createContext({
    document, navigator: { languages }, console, Intl, Date, Event,
    localStorage: { getItem() { return null; } },
    matchMedia: () => ({ matches: false, addEventListener() {} }),
    addEventListener(name, callback) { listeners.set(name, callback); },
    dispatchEvent(event) { listeners.get(event.type)?.(); },
  });
  context.window = context;
  for (const file of ["translations.js", "i18n.js", "app.js"])
    vm.runInContext(fs.readFileSync(path.join(web, file), "utf8"), context);
  return { context, element, document, i18n: context.netinspectI18n };
}
test("browser preferences, regional tags, cookie priority and fallback", () => {
  assert.equal(load({ languages: ["xx", "es-MX"] }).i18n.locale, "es");
  assert.equal(load({ languages: ["zh-Hans-CN"] }).i18n.locale, "zh-CN");
  assert.equal(load({ cookie: "other=1; netinspect.lang=ja", languages: ["fr"] }).i18n.locale, "ja");
  assert.equal(load({ cookie: "netinspect.lang=%broken", languages: ["pt-BR"] }).i18n.locale, "pt");
  assert.equal(load({ languages: ["xx"] }).i18n.locale, "en");
  assert.equal(load({ blockedCookie: true, languages: ["de"] }).i18n.locale, "de");
});
test("switching persists a cookie, updates document language and interpolates literally", () => {
  const { i18n, document } = load();
  i18n.init();
  i18n.setLanguage("fr-CA");
  assert.equal(i18n.locale, "fr");
  assert.equal(document.documentElement.lang, "fr");
  assert.match(document.cookie, /netinspect.lang=fr; Path=\/; Max-Age=31536000; SameSite=Lax/);
  assert.equal(i18n.t("{count} records", { count: 42 }), "42 enregistrements");
  assert.equal(i18n.t("View details for {target}", { target: "$&<x>" }), "Voir les détails de $&<x>");
  i18n.setLanguage("invalid");
  assert.equal(i18n.locale, "fr");
});
test("all locales cover static and dynamic keys and preserve placeholders", () => {
  const { context } = load();
  const messages = context.netinspectMessages;
  const keys = Object.keys(messages.en).sort();
  for (const [locale, dictionary] of Object.entries(messages)) {
    assert.deepEqual(Object.keys(dictionary).sort(), keys, locale);
    for (const key of keys) {
      assert.ok(dictionary[key], `${locale}: ${key}`);
      assert.deepEqual(dictionary[key].match(/\{\w+\}/g)?.sort() || [], key.match(/\{\w+\}/g)?.sort() || [], `${locale}: ${key}`);
    }
  }
  const html = fs.readFileSync(path.join(web, "index.html"), "utf8");
  for (const match of html.matchAll(/data-i18n(?:-[\w-]+)?="([^"]+)"/g))
    assert.ok(messages.en[match[1]], match[1]);
  const app = fs.readFileSync(path.join(web, "app.js"), "utf8");
  for (const match of app.matchAll(/\bt\("([^"]+)"/g))
    assert.ok(messages.en[match[1]], match[1]);
});
test("table, detail and session render in every locale without translating captured data", () => {
  const { context, i18n, element } = load();
  vm.runInContext(`state.data = {items:[{conn:{id:1,comm:"user-process",orig_ip:"127.0.0.1",orig_port:123,started_at:1,mode:"preload",route:"DIRECT"}}], total:1,active:1,closed:0};`, context);
  for (const locale of Object.keys(context.netinspectMessages)) {
    i18n.setLanguage(locale);
    vm.runInContext(`renderTable(); showDetail(0); renderSession({ session:{id:"x",command:"用户命令",started_at:1},stats:{},memory:{used:1,limit:2,limited:true,dropped:3} });`, context);
    assert.ok(element("table-head").innerHTML.includes(i18n.t("Process")), locale);
    assert.ok(element("detail-body").innerHTML.includes("user-process"), locale);
    assert.equal(element("command").textContent, "用户命令");
    assert.equal(element("status").textContent, i18n.t("Running"));
    assert.ok(element("limit-notice").textContent.includes("3"));
  }
});

test("remote-DNS upstream destinations render even without a resolved local IP", () => {
  const { context } = load();
  const target = vm.runInContext('value({conn:{orig_host:"target.invalid",orig_port:443}}, "dest")', context);
  assert.equal(target, "target.invalid:443");
});
