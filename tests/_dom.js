// A small DOM for tests that build components with app/components/h.js and
// read the result back: tag, attributes, classes, dataset, children,
// textContent, listeners fired by hand. No layout; selectors are simple
// compounds with descendant combinators (matches). install() sets
// globalThis.document and Node; the return value restores them.
//
//   const restore = install();
//   const el = someComponent();
//   walk(el, (n) => n.tagName === "INPUT")   → every input under el, document order
//   text(el)                                 → the concatenated text
//   fire(el, "click")                        → run the listeners for that event
//   restore();

// A mutation observer is opt-in (install({ mutationObserver: true })): most
// tests never register one, so notifyMutation below is a no-op walk with
// nothing to find. Registered, it matches the real API closely enough for
// components that watch a subtree for a status line or a hidden flag to
// flip: childList, attributes (with attributeFilter) and characterData,
// callbacks batched onto one microtask per observer, records themselves
// left empty since nothing here reads them.
const pendingObservers = new Set();
function notifyMutation(node, type, attributeName) {
  let n = node;
  let subtreeOnly = false;
  while (n) {
    for (const { observer, opts } of n._observers || []) {
      if (subtreeOnly && !opts.subtree) continue;
      if (type === "attributes" && !opts.attributes) continue;
      if (type === "attributes" && opts.attributeFilter && !opts.attributeFilter.includes(attributeName)) continue;
      if (type === "childList" && !opts.childList) continue;
      if (type === "characterData" && !opts.characterData) continue;
      if (!pendingObservers.has(observer)) {
        pendingObservers.add(observer);
        queueMicrotask(() => {
          pendingObservers.delete(observer);
          observer.cb([], observer);
        });
      }
    }
    n = n.parentNode;
    subtreeOnly = true;
  }
}

export class MutationObserverShim {
  constructor(cb) {
    this.cb = cb;
    this.targets = [];
  }
  observe(target, opts = {}) {
    this.targets.push(target);
    (target._observers = target._observers || []).push({ observer: this, opts });
  }
  disconnect() {
    for (const t of this.targets) t._observers = (t._observers || []).filter((o) => o.observer !== this);
    this.targets = [];
  }
  takeRecords() {
    return [];
  }
}

export class Node {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.attributes = {};
    // dataset writes land in data-* attributes, the way a browser reflects them.
    const attrs = this.attributes;
    const kebab = (k) => `data-${String(k).replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`)}`;
    this.dataset = new Proxy(
      {},
      {
        get: (_, k) => attrs[kebab(k)],
        set: (_, k, v) => {
          attrs[kebab(k)] = String(v);
          return true;
        },
        has: (_, k) => kebab(k) in attrs,
        deleteProperty: (_, k) => delete attrs[kebab(k)],
      },
    );
    this.style = { setProperty(k, v) { this[k] = v; }, removeProperty(k) { delete this[k]; } };
    this.listeners = {};
    this.children = [];
    this.parentNode = null;
    this._hidden = false;
    this.open = false;
    this.disabled = false;
    this.checked = false;
    this.value = "";
    this._text = "";
  }
  // A reflected boolean attribute, the way a browser treats hidden: the
  // property and the attribute stay in step either way in.
  get hidden() {
    return this._hidden;
  }
  set hidden(v) {
    this._hidden = Boolean(v);
    if (this._hidden) this.attributes.hidden = "";
    else delete this.attributes.hidden;
    notifyMutation(this, "attributes", "hidden");
  }
  get className() {
    return this.attributes.class || "";
  }
  set className(v) {
    this.attributes.class = v;
  }
  get id() {
    return this.attributes.id || "";
  }
  set id(v) {
    this.attributes.id = v;
  }
  get classList() {
    const self = this;
    return {
      contains: (c) => self.className.split(/\s+/).includes(c),
      add: (c) => {
        if (!self.className.split(/\s+/).includes(c)) self.className = `${self.className} ${c}`.trim();
      },
      remove: (c) => {
        self.className = self.className.split(/\s+/).filter((x) => x && x !== c).join(" ");
      },
      toggle: (c, force) => {
        const has = self.className.split(/\s+/).includes(c);
        const want = force === undefined ? !has : force;
        if (want && !has) self.className = `${self.className} ${c}`.trim();
        if (!want && has) self.className = self.className.split(/\s+/).filter((x) => x && x !== c).join(" ");
      },
    };
  }
  setAttribute(k, v) {
    this.attributes[k] = String(v);
    if (k === "hidden") this._hidden = true;
    notifyMutation(this, "attributes", k);
  }
  getAttribute(k) {
    return k in this.attributes ? this.attributes[k] : null;
  }
  removeAttribute(k) {
    delete this.attributes[k];
    if (k === "hidden") this._hidden = false;
    notifyMutation(this, "attributes", k);
  }
  hasAttribute(k) {
    return k in this.attributes;
  }
  addEventListener(type, fn) {
    (this.listeners[type] = this.listeners[type] || []).push(fn);
  }
  removeEventListener(type, fn) {
    this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn);
  }
  // A component's own CustomEvent: the listeners here, then up the tree when it bubbles.
  dispatchEvent(e) {
    for (const fn of this.listeners[e.type] || []) fn(e);
    if (e.bubbles && this.parentNode && typeof this.parentNode.dispatchEvent === "function") this.parentNode.dispatchEvent(e);
    return !e.defaultPrevented;
  }
  appendChild(child) {
    if (child.parentNode) child.parentNode.removeChild(child);
    child.parentNode = this;
    this.children.push(child);
    notifyMutation(this, "childList");
    return child;
  }
  append(...items) {
    for (const item of items) this.appendChild(typeof item === "string" ? document.createTextNode(item) : item);
  }
  prepend(...items) {
    for (const item of items.reverse()) {
      const node = typeof item === "string" ? document.createTextNode(item) : item;
      if (node.parentNode) node.parentNode.removeChild(node);
      node.parentNode = this;
      this.children.unshift(node);
    }
    notifyMutation(this, "childList");
  }
  insertBefore(node, ref) {
    if (node.parentNode) node.parentNode.removeChild(node);
    node.parentNode = this;
    const i = ref ? this.children.indexOf(ref) : -1;
    if (i < 0) this.children.push(node);
    else this.children.splice(i, 0, node);
    notifyMutation(this, "childList");
    return node;
  }
  removeChild(child) {
    this.children = this.children.filter((c) => c !== child);
    child.parentNode = null;
    notifyMutation(this, "childList");
    return child;
  }
  replaceChildren(...items) {
    for (const c of this.children) c.parentNode = null;
    this.children = [];
    this.append(...items);
    notifyMutation(this, "childList");
  }
  remove() {
    if (this.parentNode) this.parentNode.removeChild(this);
  }
  replaceWith(...items) {
    if (!this.parentNode) return;
    this.before(...items);
    this.remove();
  }
  contains(node) {
    if (node === this) return true;
    return this.children.some((c) => c.contains && c.contains(node));
  }
  insertAdjacentElement(where, el) {
    if (!this.parentNode) return el;
    const i = this.parentNode.children.indexOf(this);
    el.parentNode = this.parentNode;
    this.parentNode.children.splice(where === "afterend" ? i + 1 : i, 0, el);
    return el;
  }
  before(...items) {
    if (!this.parentNode) return;
    const i = this.parentNode.children.indexOf(this);
    for (const item of items) {
      if (item.parentNode) item.parentNode.removeChild(item);
      item.parentNode = this.parentNode;
    }
    this.parentNode.children.splice(i, 0, ...items);
  }
  get isConnected() {
    let n = this;
    while (n.parentNode) n = n.parentNode;
    return Boolean(globalThis.document && (n === document.body || n === document.head));
  }
  get firstChild() {
    return this.children[0] || null;
  }
  get firstElementChild() {
    return this.children.find((c) => c.tagName !== "#TEXT") || null;
  }
  get parentElement() {
    return this.parentNode && this.parentNode.tagName !== "#TEXT" ? this.parentNode : null;
  }
  get title() {
    return this.attributes.title || "";
  }
  set title(v) {
    this.attributes.title = String(v);
  }
  get childElementCount() {
    return this.children.filter((c) => c.tagName !== "#TEXT").length;
  }
  get textContent() {
    return this.tagName === "#TEXT" ? this._text : this.children.map((c) => c.textContent).join("");
  }
  set textContent(v) {
    if (this.tagName === "#TEXT") {
      this._text = String(v);
      notifyMutation(this, "characterData");
    } else this.replaceChildren(String(v));
  }
  get innerText() {
    return this.textContent;
  }
  focus() {}
  blur() {}
  click() {
    fire(this, "click");
  }
  scrollIntoView() {}
  getBoundingClientRect() {
    return { top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 };
  }
  closest(sel) {
    let n = this;
    while (n) {
      if (matches(n, sel)) return n;
      n = n.parentNode;
    }
    return null;
  }
  querySelector(sel) {
    return walk(this, (n) => n !== this && matches(n, sel))[0] || null;
  }
  querySelectorAll(sel) {
    return walk(this, (n) => n !== this && matches(n, sel));
  }
}

// A selector: a compound of tag, .class, #id, [attr], [attr=value],
// [attr*=value], :not(simple) and :scope, descendant combinators between
// compounds, and a comma list of those. Enough for the components and
// the context readers under test.
function matchesCompound(node, compound) {
  let rest = compound;
  let m;
  while (rest) {
    if ((m = /^:scope/.exec(rest))) {
      rest = rest.slice(m[0].length);
      continue;
    }
    if ((m = /^:not\(([^)]*)\)/.exec(rest))) {
      if (matchesCompound(node, m[1].trim())) return false;
    } else if ((m = /^#([\w-]+)/.exec(rest))) {
      if (node.id !== m[1]) return false;
    } else if ((m = /^\.([\w-]+)/.exec(rest))) {
      if (!node.classList.contains(m[1])) return false;
    } else if ((m = /^\[([\w-]+)(?:(\*?)=(?:"([^"]*)"|'([^']*)'|([^\]]*)))?\]/.exec(rest))) {
      const want = m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : m[5];
      if (!(m[1] in node.attributes)) return false;
      if (want !== undefined && (m[2] ? !String(node.attributes[m[1]]).includes(want) : node.attributes[m[1]] !== want)) return false;
    } else if ((m = /^([a-z][\w-]*)/i.exec(rest))) {
      if (node.tagName !== m[1].toUpperCase()) return false;
    } else {
      return false;
    }
    rest = rest.slice(m[0].length);
  }
  return true;
}

export function matches(node, sel) {
  if (node.tagName === "#TEXT") return false;
  return String(sel)
    .split(",")
    .map((s) => s.trim())
    .some((one) => {
      const parts = one.split(/\s+(?![^\[]*\])/).filter(Boolean);
      if (!parts.length || !matchesCompound(node, parts[parts.length - 1])) return false;
      let n = node.parentNode;
      for (let i = parts.length - 2; i >= 0; i--) {
        while (n && !matchesCompound(n, parts[i])) n = n.parentNode;
        if (!n) return false;
        n = n.parentNode;
      }
      return true;
    });
}

export function walk(root, pred, out = []) {
  if (pred(root)) out.push(root);
  for (const c of root.children || []) walk(c, pred, out);
  return out;
}

export function text(node) {
  return node.textContent.replace(/\s+/g, " ").trim();
}

export function fire(node, type, event = {}) {
  const e = { type, target: node, defaultPrevented: false, isTrusted: true, preventDefault() { this.defaultPrevented = true; }, stopPropagation() {}, ...event };
  for (const fn of node.listeners[type] || []) fn(e);
  return e;
}

export function install({ mutationObserver = false } = {}) {
  const saved = { document: globalThis.document, Node: globalThis.Node, CSS: globalThis.CSS, MutationObserver: globalThis.MutationObserver };
  const body = new Node("body");
  const head = new Node("head");
  globalThis.Node = Node;
  globalThis.CSS = { escape: (s) => String(s) };
  if (mutationObserver) globalThis.MutationObserver = MutationObserverShim;
  else delete globalThis.MutationObserver;
  globalThis.document = {
    body,
    head,
    documentElement: new Node("html"),
    createElement: (tag) => new Node(tag),
    createTextNode: (t) => {
      const n = new Node("#text");
      n._text = String(t);
      return n;
    },
    getElementById: (id) => walk(body, (n) => n.id === id)[0] || walk(head, (n) => n.id === id)[0] || null,
    querySelector: (sel) => body.querySelector(sel),
    querySelectorAll: (sel) => body.querySelectorAll(sel),
    addEventListener() {},
    removeEventListener() {},
    activeElement: null,
  };
  return () => {
    globalThis.document = saved.document;
    globalThis.Node = saved.Node;
    globalThis.CSS = saved.CSS;
    if (saved.MutationObserver === undefined) delete globalThis.MutationObserver;
    else globalThis.MutationObserver = saved.MutationObserver;
  };
}

export default { Node, install, walk, text, fire, matches };
