"use strict";
const $ = (id) => document.getElementById(id);
const esc = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        c
      ],
  );
function bytes(n) {
  n = Number(n) || 0;
  if (n < 1024) return n + " B";
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let i = -1;
  do {
    n /= 1024;
    i++;
  } while (n >= 1024 && i < 3);
  return n.toFixed(n >= 100 ? 0 : 1) + " " + units[i];
}
function duration(ms) {
  ms = Math.max(0, Number(ms) || 0);
  const [amount, unit] =
    ms < 1000
      ? [ms, "ms"]
      : ms < 60000
        ? [ms / 1000, "s"]
        : ms < 3600000
          ? [ms / 60000, "min"]
          : [ms / 3600000, "hour"];
  return amount.toFixed(2).replace(/\.?0+$/, "") + " " + unit;
}
const time = (ms) =>
  ms
    ? new Date(ms).toLocaleString("zh-CN", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      })
    : "—";
function relativeTime(ms, now = Date.now()) {
  if (!ms) return "—";
  const seconds = Math.max(0, Math.floor((now - ms) / 1000));
  if (seconds < 60) return seconds + " 秒前";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return minutes + " 分钟前";
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return hours + " 小时前";
  return Math.floor(hours / 24) + " 天前";
}
const systemTheme = matchMedia("(prefers-color-scheme: dark)");
const themeModes = ["system", "light", "dark"];
const themeNames = { system: "自动（跟随系统）", light: "亮色", dark: "暗色" };
const icon = (paths) =>
  '<svg aria-hidden="true" viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">' +
  paths +
  "</svg>";
const themeIcons = {
  system: icon(
    '<rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8m-4-4v4"/>',
  ),
  light: icon(
    '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/>',
  ),
  dark: icon('<path d="M20.8 13A9 9 0 0 1 11 3.2 9 9 0 1 0 20.8 13Z"/>'),
};
function applyTheme(theme) {
  if (!themeModes.includes(theme)) theme = "system";
  document.documentElement.dataset.theme =
    theme === "system" ? (systemTheme.matches ? "dark" : "light") : theme;
  const button = $("theme");
  button.dataset.mode = theme;
  button.innerHTML = themeIcons[theme];
  const next = themeModes[(themeModes.indexOf(theme) + 1) % themeModes.length];
  const label =
    "当前：" + themeNames[theme] + "；点击切换为" + themeNames[next];
  button.title = label;
  button.setAttribute("aria-label", label);
}
function initTheme() {
  let theme = "system";
  try {
    theme = localStorage.getItem("netinspect.theme") || theme;
  } catch {}
  applyTheme(theme);
  $("theme").onclick = () => {
    const next =
      themeModes[
        (themeModes.indexOf($("theme").dataset.mode) + 1) % themeModes.length
      ];
    applyTheme(next);
    try {
      localStorage.setItem("netinspect.theme", next);
    } catch {}
  };
  systemTheme.addEventListener("change", () => {
    if ($("theme").dataset.mode === "system") applyTheme("system");
  });
}
const elapsed = (ms) => {
  const sec = Math.max(0, Math.floor(ms / 1000));
  return [Math.floor(sec / 3600), Math.floor(sec / 60) % 60, sec % 60]
    .map((n) => String(n).padStart(2, "0"))
    .join(":");
};
const columns = [
  ["time", "连接时间", true],
  ["source", "Source", true],
  ["dest", "Dest", true],
  ["sni", "SNI", true],
  ["alpn", "ALPN", false],
  ["process", "进程", true],
  ["pid", "PID", false],
  ["protocol", "协议 / 查询类型", true],
  ["latency", "建连 / 查询耗时", true],
  ["down", "下载量", true],
  ["up", "上传量", true],
  ["result", "结果", true],
].map(([key, label, visible]) => ({ key, label, visible }));
const state = {
  status: "all",
  sort: "time",
  direction: "desc",
  page: 1,
  size: 50,
  q: "",
  paused: false,
  stopped: false,
  session: null,
  data: { items: [], total: 0, active: 0, closed: 0, page: 1, size: 50 },
  columns: columns.map((c) => ({ ...c })),
  request: 0,
  controller: null,
  detail: null,
  refreshing: false,
};
try {
  const saved = JSON.parse(localStorage.getItem("netinspect.columns.v3"));
  if (Array.isArray(saved)) {
    const ordered = [];
    for (const item of saved) {
      const c = columns.find((c) => c.key === item.key);
      if (c && !ordered.some((v) => v.key === c.key))
        ordered.push({ ...c, visible: !!item.visible });
    }
    for (const c of columns) {
      if (ordered.some((v) => v.key === c.key)) continue;
      ordered.push({ ...c });
    }
    if (ordered.some((c) => c.visible)) state.columns = ordered;
  }
} catch {}
const columnLabel = (key) => columns.find((c) => c.key === key)?.label || key;
function value(i, key) {
  const c = i.conn,
    d = i.dns;
  if (key === "kind") return c ? "TCP" : "DNS";
  if (key === "time" || key === "age") return c?.started_at ?? d?.at;
  if (key === "host") {
    if (!c) return d?.answer || d?.qname || "—";
    const host = c.orig_host || c.orig_ip || "—";
    return (host.includes(":") ? "[" + host + "]" : host) + ":" + c.orig_port;
  }
  if (key === "source") return c?.source || d?.source || "—";
  if (key === "dest")
    return c
      ? c.orig_ip
        ? (c.orig_ip.includes(":") ? "[" + c.orig_ip + "]" : c.orig_ip) +
          ":" +
          c.orig_port
        : "—"
      : d?.dest || "—";
  if (key === "process") return c?.comm || d?.comm || "—";
  if (key === "pid") return c?.pid || d?.pid || "—";
  if (key === "protocol") return c?.proto || d?.qtype || "TCP";
  if (key === "latency") return c?.connect_ms ?? d?.ms;
  if (key === "down") return c?.bytes_down;
  if (key === "up") return c?.bytes_up;
  if (key === "result") return c ? c.result || "open" : d.answer || "—";
  return c?.[{ ip: "orig_ip", port: "orig_port" }[key] || key] || "—";
}
function cell(i, key) {
  const v = value(i, key);
  if (key === "protocol")
    return (
      '<span class="type-badge ' +
      (i.dns ? "dns" : String(v).toLowerCase() === "tls" ? "tls" : "tcp") +
      '">' +
      esc(v) +
      "</span>"
    );
  if (key === "time")
    return (
      esc(
        v ? new Date(v).toLocaleTimeString("zh-CN", { hour12: false }) : "—",
      ) +
      ' <span class="inline-meta ' +
      (i.conn && !i.conn.ended_at ? "active-age" : "") +
      '" data-active="' +
      !!(i.conn && !i.conn.ended_at) +
      '" data-time="' +
      esc(v) +
      '">' +
      esc(
        relativeTime(
          v,
          i.conn && !i.conn.ended_at
            ? Date.now()
            : Math.floor(Date.now() / 1000) * 1000,
        ),
      ) +
      "</span>"
    );
  if (key === "up" || key === "down") return i.dns ? "—" : esc(bytes(v));
  if (key === "latency")
    return (
      esc(duration(v)) +
      (i.conn?.tls_ms
        ? ' <span class="inline-meta">TLS ' +
          esc(duration(i.conn.tls_ms)) +
          "</span>"
        : "")
    );
  if (key === "process")
    return (
      esc(v) +
      (i.conn?.pid || i.dns?.pid
        ? ' <span class="inline-meta process-pid">(' +
          esc(i.conn?.pid || i.dns?.pid) +
          ")</span>"
        : "")
    );
  if (key === "source" || key === "dest") {
    const split = String(v).lastIndexOf(":");
    if (split < 0) return esc(v);
    return (
      '<span class="host-name">' +
      esc(v.slice(0, split)) +
      '</span><span class="host-port">' +
      esc(v.slice(split)) +
      "</span>"
    );
  }
  if (key === "result" && i.conn)
    return (
      '<span class="result ' +
      (!["ok", "open", "observed", ""].includes(v) ? "fail" : "") +
      '">' +
      esc(v) +
      "</span>"
    );
  return esc(v ?? "—");
}
function renderTable() {
  const visible = state.columns.filter((c) => c.visible);
  $("table-head").innerHTML = visible
    .map(
      (c) =>
        '<th><button data-sort="' +
        c.key +
        '" class="' +
        (state.sort === c.key ? "sorted" : "") +
        '">' +
        esc(c.label) +
        (state.sort === c.key
          ? state.direction === "desc"
            ? " ↓"
            : " ↑"
          : "") +
        "</button></th>",
    )
    .join("");
  $("table-body").innerHTML = state.data.items
    .map(
      (i, index) =>
        '<tr data-index="' +
        index +
        '" tabindex="0" aria-label="查看 ' +
        esc(value(i, "dest")) +
        ' 详情">' +
        visible
          .map(
            (c) =>
              '<td class="' +
              (c.key === "time"
                ? i.conn && !i.conn.ended_at
                  ? "time-active"
                  : "time-closed"
                : "") +
              '" title="' +
              esc(
                ["time", "age"].includes(c.key)
                  ? time(value(i, c.key))
                  : c.key === "process"
                    ? i.conn?.cmdline || i.conn?.exe || value(i, c.key)
                    : value(i, c.key),
              ) +
              '">' +
              cell(i, c.key) +
              "</td>",
          )
          .join("") +
        "</tr>",
    )
    .join("");
  const empty = state.data.items.length === 0;
  $("empty").hidden = !empty;
  $("empty").querySelector("strong").textContent = state.q
    ? "没有匹配的记录"
    : state.status === "active"
      ? "暂无活动连接"
      : state.status === "all"
        ? "暂无记录"
        : "暂无已关闭记录";
  $("empty").querySelector("p").textContent = state.q
    ? "试试其他筛选条件"
    : state.status === "active"
      ? "连接结束后可在「已关闭」中查看，DNS 也会显示在那里。"
      : state.status === "all"
        ? "新的网络活动会显示在这里。"
        : "已完成的连接和 DNS 查询会显示在这里。";
  $("count-note").textContent = "共 " + state.data.total + " 条记录";
  $("all-count").textContent = state.data.active + state.data.closed;
  $("active-count").textContent = state.data.active;
  $("closed-count").textContent = state.data.closed;
  const pages = Math.max(1, Math.ceil(state.data.total / state.size));
  $("page-label").textContent = state.page + " / " + pages;
  $("page-range").textContent =
    (state.data.total ? (state.page - 1) * state.size + 1 : 0) +
    "–" +
    Math.min(state.page * state.size, state.data.total) +
    " / " +
    state.data.total;
  for (const id of ["first-page", "prev-page"])
    $(id).disabled = state.page <= 1;
  for (const id of ["next-page", "last-page"])
    $(id).disabled = state.page >= pages;
}
function renderSession(data) {
  state.session = data.session;
  const s = data.session,
    st = data.stats,
    m = data.memory;
  $("cli-version").textContent = data.version?.version || "dev";
  $("build-info").textContent = data.version?.build || "local";
  $("session-id").textContent = "#" + (s.id || "—");
  $("mode").textContent = s.mode || "—";
  $("command").textContent = s.command || "—";
  $("command").title = s.command || "";
  const ended = !!s.ended_at;
  $("status").textContent = ended ? "已结束" : "运行中";
  $("status").dataset.status = ended ? "ended" : "running";
  $("uptime-start").hidden = !ended;
  $("uptime-start").textContent = ended ? "开始于 " + time(s.started_at) : "";
  $("pause").hidden = ended || state.stopped;
  $("stop-server").hidden = !ended || state.stopped;
  $("stop-server").disabled = !ended || state.stopped;
  $("stop-server").title = ended
    ? "关闭 HTTP 服务并释放本次数据"
    : "被包裹的程序结束后可关闭 HTTP 服务";
  $("st-up").textContent = bytes(st.bytes_up);
  $("st-down").textContent = bytes(st.bytes_down);
  if (m) {
    $("memory-label").textContent = bytes(m.used) + " / " + bytes(m.limit);
    $("memory-bar").style.width = Math.min(100, (m.used / m.limit) * 100) + "%";
    $("limit-notice").hidden = !m.limited;
    $("limit-notice").textContent =
      "记录内存预算已达上限，已停止新增记录（跳过 " +
      m.dropped +
      " 条）。已有数据保留，已有连接继续更新；代理流量与目标程序继续运行。";
  }
  tick();
}
function tick() {
  if (!state.paused && !state.stopped)
    document.querySelectorAll("[data-time]").forEach((el) => {
      el.textContent = relativeTime(
        Number(el.dataset.time),
        el.dataset.active === "true"
          ? Date.now()
          : Math.floor(Date.now() / 1000) * 1000,
      );
    });
  if (state.session && !state.stopped)
    $("uptime").textContent = elapsed(
      (state.session.ended_at || Date.now()) - state.session.started_at,
    );
}
function connectionState(ok, message) {
  $("live-dot").classList.toggle("off", !ok);
  $("live-text").textContent = message;
}
function hasTableSelection() {
  const selection = window.getSelection();
  return (
    selection &&
    !selection.isCollapsed &&
    ($("table-body").contains(selection.anchorNode) ||
      $("table-body").contains(selection.focusNode))
  );
}
async function refresh(force = false) {
  if (hasTableSelection()) return;
  if (state.stopped || (state.paused && !force)) return;
  if (state.refreshing && !force) return;
  state.controller?.abort();
  const controller = new AbortController();
  state.controller = controller;
  const request = ++state.request;
  state.refreshing = true;
  const params = new URLSearchParams({
    status: state.status === "all" ? "" : state.status,
    sort: state.sort,
    direction: state.direction,
    page: state.page,
    size: state.size,
    q: state.q,
  });
  try {
    const responses = await Promise.all([
      fetch("/api/items?" + params, {
        signal: controller.signal,
        cache: "no-store",
      }),
      fetch("/api/session", { signal: controller.signal, cache: "no-store" }),
    ]);
    if (responses.some((r) => !r.ok)) throw new Error("加载失败");
    const [page, session] = await Promise.all(responses.map((r) => r.json()));
    if (
      request !== state.request ||
      state.paused ||
      state.stopped ||
      hasTableSelection()
    )
      return;
    state.data = page;
    state.page = page.page;
    renderSession(session);
    renderTable();
    connectionState(true, "服务已连接");
    $("refresh-error").textContent = "";
  } catch (e) {
    if (e.name !== "AbortError" && request === state.request) {
      connectionState(false, "连接中断");
      $("refresh-error").textContent = "刷新失败，正在重试；保留当前数据";
    }
  } finally {
    if (request === state.request) state.refreshing = false;
  }
}
function queryChanged() {
  state.page = 1;
  if (!state.paused) refresh(true);
}
function renderSort() {
  $("sort-label").textContent = columnLabel(state.sort);
  $("sort-menu").querySelector("summary").title =
    "排序列：" + columnLabel(state.sort);
  $("direction").innerHTML = icon(
    state.direction === "desc"
      ? '<path d="M7 4v16m-4-4 4 4 4-4M14 5h7m-7 5h5m-5 5h3"/>'
      : '<path d="M7 20V4m-4 4 4-4 4 4M14 5h3m-3 5h5m-5 5h7"/>',
  );
  $("direction").title =
    state.direction === "desc"
      ? "当前降序，点击切换升序"
      : "当前升序，点击切换降序";
  $("sort-options").innerHTML = columns
    .map(
      (c) =>
        '<button data-sort="' +
        c.key +
        '" class="' +
        (state.sort === c.key ? "chosen" : "") +
        '" aria-pressed="' +
        (state.sort === c.key) +
        '">' +
        esc(c.label) +
        "<span>" +
        (state.sort === c.key ? "✓" : "") +
        "</span></button>",
    )
    .join("");
}
function setSort(key) {
  if (state.sort === key)
    state.direction = state.direction === "desc" ? "asc" : "desc";
  else state.sort = key;
  renderSort();
  $("sort-menu").open = false;
  queryChanged();
}
function saveColumns() {
  try {
    localStorage.setItem(
      "netinspect.columns.v3",
      JSON.stringify(
        state.columns.map(({ key, visible }) => ({ key, visible })),
      ),
    );
  } catch {}
  renderTable();
}
function renderColumns() {
  $("column-options").innerHTML = state.columns
    .map(
      (c, i) =>
        '<div class="column-row"><span aria-hidden="true">⠿</span><label>' +
        esc(c.label) +
        '<input type="checkbox" data-key="' +
        c.key +
        '" ' +
        (c.visible ? "checked" : "") +
        ' aria-label="显示' +
        esc(c.label) +
        '"></label><button data-move="-1" data-key="' +
        c.key +
        '" ' +
        (!i ? "disabled" : "") +
        ' aria-label="上移' +
        esc(c.label) +
        '">↑</button><button data-move="1" data-key="' +
        c.key +
        '" ' +
        (i === state.columns.length - 1 ? "disabled" : "") +
        ' aria-label="下移' +
        esc(c.label) +
        '">↓</button></div>',
    )
    .join("");
}
function showDetail(index) {
  const item = state.data.items[index];
  if (!item) return;
  state.detail = item;
  const c = item.conn,
    d = item.dns;
  $("detail-title").textContent = d ? "DNS 查询详情" : "连接详情";
  const fields = c
    ? [
        ["ID", c.id],
        ["进程", c.comm],
        ["PID", c.pid],
        ["模式", c.mode],
        ["主机", c.orig_host],
        ["目标 IP", c.orig_ip],
        ["目标端口", c.orig_port],
        ["协议", c.proto],
        ["SNI", c.sni],
        ["ALPN", c.alpn],
        [
          "出站方式",
          c.mode === "observe"
            ? "仅观察（不接管流量）"
            : c.route === "DIRECT"
              ? "直连"
              : c.route,
        ],
        ["开始", time(c.started_at)],
        ["结束", c.ended_at ? time(c.ended_at) : "活动中"],
        ["建连耗时", duration(c.connect_ms)],
        ["TLS 耗时", duration(c.tls_ms)],
        ["上传", bytes(c.bytes_up)],
        ["下载", bytes(c.bytes_down)],
        ["结果", c.result],
        ["错误", c.error],
      ]
    : [
        ["ID", d.id],
        ["进程", d.comm],
        ["PID", d.pid],
        ["查询名", d.qname],
        ["查询类型", d.qtype],
        ["应答", d.answer],
        ["查询耗时", duration(d.ms)],
        ["时间", time(d.at)],
      ];
  $("detail-body").innerHTML = fields
    .map(
      ([k, v]) =>
        '<div class="detail-row"><dt>' +
        esc(k) +
        "</dt><dd>" +
        esc(v || "—") +
        "</dd></div>",
    )
    .join("");
  $("detail-dialog").showModal();
}
async function stopServer() {
  const button = $("stop-server");
  button.disabled = true;
  try {
    const control = await fetch("/api/control", {
      headers: { "X-Netinspect-Control": "1" },
    });
    if (!control.ok) throw new Error("无法获取控制权限");
    const { token } = await control.json();
    const response = await fetch("/api/shutdown", {
      method: "POST",
      headers: { Authorization: "Bearer " + token },
    });
    if (!response.ok) throw new Error("关闭失败，目标程序可能仍在运行");
    state.stopped = true;
    for (const id of [
      "pause",
      "filter",
      "direction",
      "page-size",
      "tab-all",
      "tab-active",
      "tab-closed",
      "first-page",
      "prev-page",
      "next-page",
      "last-page",
    ])
      $(id).disabled = true;
    $("sort-menu").hidden = true;
    state.controller?.abort();
    connectionState(false, "服务已结束");
    $("view-status").textContent = "服务已结束 · 数据快照";
    button.textContent = "服务已结束";
    button.hidden = true;
    $("refresh-error").textContent = "";
  } catch (e) {
    button.disabled = false;
    $("refresh-error").textContent = e.message;
  }
}
function init() {
  initTheme();
  let wide = false;
  try {
    wide = localStorage.getItem("netinspect.wide") === "true";
  } catch {}
  const setLayout = () => {
    document.documentElement.dataset.layout = wide ? "wide" : "contained";
    const button = $("layout-toggle");
    button.innerHTML = icon(
      wide
        ? '<path d="M4 9h5V4m11 5h-5V4M4 15h5v5m11-5h-5v5"/>'
        : '<path d="M9 4H4v5m11-5h5v5M9 20H4v-5m11 5h5v-5"/>',
    );
    button.setAttribute("aria-pressed", String(wide));
    button.title = wide ? "恢复默认宽度" : "切换宽屏";
    button.setAttribute("aria-label", button.title);
  };
  setLayout();
  $("layout-toggle").onclick = () => {
    wide = !wide;
    setLayout();
    try {
      localStorage.setItem("netinspect.wide", String(wide));
    } catch {}
  };
  renderSort();
  renderTable();
  document.querySelectorAll("button[data-status]").forEach((b) =>
    b.addEventListener("click", () => {
      if (state.paused) return;
      state.status = b.dataset.status;
      document
        .querySelectorAll("button[data-status]")
        .forEach((v) => v.classList.toggle("selected", v === b));
      queryChanged();
    }),
  );
  $("direction").onclick = () => {
    state.direction = state.direction === "desc" ? "asc" : "desc";
    renderSort();
    queryChanged();
  };
  $("sort-options").onclick = (e) => {
    const b = e.target.closest("[data-sort]");
    if (b) setSort(b.dataset.sort);
  };
  $("table-head").onclick = (e) => {
    const b = e.target.closest("[data-sort]");
    if (b && !state.paused) setSort(b.dataset.sort);
  };
  let filterTimer;
  $("filter").oninput = () => {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(() => {
      state.q = $("filter").value.trim();
      queryChanged();
    }, 250);
  };
  $("pause").onclick = () => {
    state.paused = !state.paused;
    $("pause").setAttribute("aria-pressed", String(state.paused));
    $("pause").textContent = state.paused ? "▷" : "Ⅱ";
    $("pause").setAttribute(
      "aria-label",
      state.paused ? "恢复页面刷新" : "暂停页面刷新",
    );
    $("view-status").textContent = state.paused
      ? "页面已暂停 · 代理和记录继续运行"
      : "实时更新";
    for (const id of [
      "filter",
      "direction",
      "page-size",
      "tab-all",
      "tab-active",
      "tab-closed",
      "first-page",
      "prev-page",
      "next-page",
      "last-page",
    ])
      $(id).disabled = state.paused || state.stopped;
    $("sort-menu").open = false;
    $("sort-menu").hidden = state.paused;
    if (state.paused) {
      state.controller?.abort();
      state.request++;
      state.refreshing = false;
    } else refresh(true);
  };
  $("settings").onclick = () => {
    renderColumns();
    $("column-dialog").showModal();
  };
  for (const id of ["columns-close", "columns-done"])
    $(id).onclick = () => $("column-dialog").close();
  $("reset-columns").onclick = () => {
    state.columns = columns.map((c) => ({ ...c }));
    saveColumns();
    renderColumns();
  };
  $("column-options").onchange = (e) => {
    const c = state.columns.find((c) => c.key === e.target.dataset.key);
    if (!c) return;
    if (
      !e.target.checked &&
      state.columns.filter((c) => c.visible).length === 1
    ) {
      e.target.checked = true;
      return;
    }
    c.visible = e.target.checked;
    saveColumns();
  };
  $("column-options").onclick = (e) => {
    const b = e.target.closest("[data-move]");
    if (!b) return;
    const index = state.columns.findIndex((c) => c.key === b.dataset.key),
      target = index + Number(b.dataset.move);
    [state.columns[index], state.columns[target]] = [
      state.columns[target],
      state.columns[index],
    ];
    saveColumns();
    renderColumns();
    $("column-options")
      .querySelector(
        '[data-key="' +
          b.dataset.key +
          '"][data-move="' +
          b.dataset.move +
          '"]',
      )
      .focus();
  };
  $("page-size").onchange = () => {
    state.size = Number($("page-size").value);
    queryChanged();
  };
  for (const [id, page] of [
    ["first-page", () => 1],
    ["prev-page", () => state.page - 1],
    ["next-page", () => state.page + 1],
    ["last-page", () => Math.max(1, Math.ceil(state.data.total / state.size))],
  ])
    $(id).onclick = () => {
      state.page = page();
      refresh(true);
    };
  let rowPointer = null;
  let draggedSelection = false;
  $("table-body").addEventListener("pointerdown", (e) => {
    rowPointer = { x: e.clientX, y: e.clientY };
    draggedSelection = false;
  });
  $("table-body").addEventListener("pointermove", (e) => {
    if (
      e.buttons &&
      rowPointer &&
      Math.hypot(e.clientX - rowPointer.x, e.clientY - rowPointer.y) > 4
    )
      draggedSelection = true;
  });
  $("table-body").onclick = (e) => {
    if (draggedSelection || !window.getSelection()?.isCollapsed) return;
    const row = e.target.closest("[data-index]");
    if (row) showDetail(Number(row.dataset.index));
  };
  $("table-body").onkeydown = (e) => {
    if (e.key === "Enter") {
      const row = e.target.closest("[data-index]");
      if (row) showDetail(Number(row.dataset.index));
    }
  };
  let backdropDown = false;
  const detail = $("detail-dialog");
  const outsideDetail = (e) => {
    const r = detail.getBoundingClientRect();
    return (
      e.clientX < r.left ||
      e.clientX > r.right ||
      e.clientY < r.top ||
      e.clientY > r.bottom
    );
  };
  detail.addEventListener("pointerdown", (e) => {
    backdropDown = e.target === detail && outsideDetail(e);
  });
  detail.addEventListener("click", (e) => {
    if (backdropDown && e.target === detail && outsideDetail(e)) detail.close();
    backdropDown = false;
  });
  $("detail-close").onclick = () => $("detail-dialog").close();
  $("stop-server").onclick = stopServer;
  document.addEventListener("click", (e) => {
    if (!$("sort-menu").contains(e.target)) $("sort-menu").open = false;
  });
  document.addEventListener("keydown", (e) => {
    if (
      e.key === "/" &&
      !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName) &&
      !document.querySelector("dialog[open]")
    ) {
      e.preventDefault();
      $("filter").focus();
    }
    if (e.key === "Escape") $("sort-menu").open = false;
  });
  refresh();
  setInterval(() => refresh(), 500);
  setInterval(tick, 500);
}
document.addEventListener("DOMContentLoaded", init);
